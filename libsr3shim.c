
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <math.h>
#include <stdarg.h>
#include <errno.h>

#ifdef INTERCEPT_SYSCALL
// needed for aio_context_t
#include <linux/aio_abi.h>
// needed for cap_user_data_t and cap_user_header_t (libcap-devel)
// #include <sys/capability.h>
// manually defining the structs here rather than requiring sys/capability.h
// because we need to build on systems that don't have libcap installed.
typedef struct __user_cap_header_struct {
        __u32 version;
        int pid;
} *cap_user_header_t;
typedef struct __user_cap_data_struct {
        __u32 effective;
        __u32 permitted;
        __u32 inheritable;
} *cap_user_data_t;
// needed for key_serial_t
#include <keyutils.h>
// needed for mqd_t
#include <mqueue.h>
// these types are not defined in headers outside of /usr/src
typedef __kernel_uid32_t qid_t;
typedef __kernel_rwf_t rwf_t;
typedef uint32_t u32;
typedef uint64_t u64;
typedef short unsigned int umode_t;
#ifdef __powerpc__
// not defined on PPC
typedef sigset_t old_sigset_t;
#endif
#endif

#include <dirent.h>
#define clerror(s)  if (s==0) { errno=0; }

#include "sr_post.h"

/*
 libsrshim - intercepts calls to libc and kernel to post files for broker.

SR_SHIM_CONFIG -- environment variable to set configuration file name 
     (format as per sr_subscribe(1) and/or sr_post(1). )        

 FIXME:  1024, and PATH_MAX, should likely be replaced by code that mallocs properly.

 set following variables to non-empty strings to activate.

 SR_SHIMDEBUG - when set, debug output triggerred.

 FIXME:
     sigh.... redirection... the final frontier...

    rmdir(2)
      - directory must be empty, so rmdir has no effect (only deal with files.)
        hmm... do we need to start dealing with directories?
        result: even with delete active, empty directories likely.

    sendfile64(2)
    truncate64(2)
      - ordinary calls are dealt with... dunno that we need a separate 64 variety.

 */

void exit_cleanup_posts();
int exit_cleanup_posts_setup = 0;

int mypid = 0;
int pid_seconds_wallclock = 0;
int srshim_debug_level = -1;

struct sr_log_context_s *logctxptr = NULL;

void sr_shimdebug_msg(int level, const char *format, ...)
{
	struct timespec ts;
	va_list ap;
	char *srdbgstr;

	if (srshim_debug_level == -1) {
		srdbgstr = getenv("SR_SHIMDEBUG");
		if (!srdbgstr) {
			srshim_debug_level = -2;
			return;
		}
		clock_gettime(CLOCK_REALTIME, &ts);
		srshim_debug_level = atoi(srdbgstr);
		mypid = getpid();
		fprintf(stderr, " startup ");
		pid_seconds_wallclock = ts.tv_sec;

	} else if (srshim_debug_level == -2)
		return;

	clock_gettime(CLOCK_REALTIME, &ts);

	if (level > srshim_debug_level)
		return;

	fprintf(stderr, "SR_SHIMDEBUG %d %d %g ", level, mypid,
		(ts.tv_sec + ts.tv_nsec / 1e9) - pid_seconds_wallclock);

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);

}

static struct sr_config_s sr_cfg;

void setup_exit()
{
	if (!exit_cleanup_posts_setup) {
		atexit(exit_cleanup_posts);
		exit_cleanup_posts_setup = 1;
		sr_shimdebug_msg(1, "setup_exit done.\n");
	}
}

/*
 * duping a file results in multiple closes of the same file, or redundant posting. 
 * We should arrange things so that we only post on the last close of a duped fd.
 * duped_fds, used to track currently duped file descriptors.
 * steps:
 *    - initialize all entries to -2.
 *    - when dupX is called, add the two file descriptos to the table.
 *    - if the dup call is going to result in the newfd (being already open) being closed,
 *      make sure to call shim's close, rather than libc close, to post if need be.
 *    - when closing an fd, check the table,
 *       - if found, remove both fd's from the table by setting entries to -1
 *                   do not post file.
 *         else (not found because never duped, or already removed from table.)
 *            post.
 */

#define MAX_DUPED_FDS (20)
signed int duped_fds[MAX_DUPED_FDS];

void init_duped_fds()
{
	for (int i = 0; i < MAX_DUPED_FDS; i++)
		duped_fds[i] = -2;
}

void record_duped_fds(int oldfd, int newfd)
{
	int duped_fd_index;

	// look for an empty pair of spots in duped_fds to add two new fds.
	for (duped_fd_index = 0; (duped_fd_index < MAX_DUPED_FDS); duped_fd_index += 2) {
		if ((duped_fds[duped_fd_index] < 0) && (duped_fds[duped_fd_index + 1] < 0))
			break;
	}
	if (duped_fd_index >= MAX_DUPED_FDS) {
		sr_log_msg(logctxptr,LOG_ERROR,
			   "srshim ran out of room to store duplicated file descriptors, recompile with MAX_DUPED_FDS (==%d) increased\n",
			   MAX_DUPED_FDS);
	} else {
		duped_fds[duped_fd_index] = oldfd;
		sr_shimdebug_msg(16, "set duped_fds[%d]=%d\n", duped_fd_index,
				 duped_fds[duped_fd_index]);
		duped_fd_index++;
		duped_fds[duped_fd_index] = newfd;
		sr_shimdebug_msg(16, "set duped_fds[%d]=%d\n", duped_fd_index,
				 duped_fds[duped_fd_index]);
	}
}

bool is_duped(int fd)
{
	/* see if current fd was duped to or from */
	for (int i = 0; (i < MAX_DUPED_FDS); i++) {

		if (duped_fds[i] == -2)
			break;	// past last value ever used.

		if (duped_fds[i] == fd) {
			if (i % 2 == 0) {
				duped_fds[i] = -1;
				duped_fds[i + 1] = -1;
			} else {
				duped_fds[i] = -1;
				duped_fds[i - 1] = -1;
			}
			sr_shimdebug_msg(16, " is_duped!\n");
			return true;
		}
	};
	return false;
}

char **parent_files_open = NULL;
int last_pfo = 0;
int max_pfo = 1;

/* build list of files opened by parent pid
 */
void setup_pfo()
{
	char fdpath[500];
	int fdpathlen;
	DIR *fddir = NULL;
	struct dirent *fdde;

	parent_files_open = (char **)malloc(sizeof(char *));

	snprintf(fdpath, 499, "/proc/%d/fd", getppid());
	fddir = opendir(fdpath);

	if (fddir) {
		while ((fdde = readdir(fddir))) {
			if (fdde->d_name[0] == '.')
				continue;

			fdpathlen = readlinkat(dirfd(fddir), fdde->d_name, fdpath, 500);

			if (fdpathlen < 0)
				continue;

			fdpath[fdpathlen] = '\0';

			if (fdpath[0] != '/')	//only looking for ordinary files, not sockets and pipes.
				continue;

			if (!strncmp(fdpath, "/dev/", 5))
				continue;

			if (!strncmp(fdpath, "/proc/", 6))
				continue;

			parent_files_open[last_pfo++] = strdup(fdpath);

			if (last_pfo >= max_pfo) {
				char **save_pfo = parent_files_open;
				max_pfo *= 2;
				parent_files_open = (char **)malloc(max_pfo * sizeof(char *));
				for (int i = 0; i < last_pfo; i++)
					parent_files_open[i] = save_pfo[i];
				free(save_pfo);
			}

		}
		closedir(fddir);
	}
	sr_shimdebug_msg(1, "setup pfo done.\n");
}

static struct sr_context *sr_c = NULL;
static int sr_connected = 0;

static int close_init_done = 0;
typedef int (*close_fn)(int);
static close_fn close_fn_ptr = close;

struct filename_memory {
	int clean;
	struct timespec ts;
	char *name;
};

struct filename_memory (*remembered_filenames)[] = NULL;
int remembered_count = 0;
int remembered_max = 0;

int should_not_post(const char *fn)
/*
   given the file name fn, return(1) if we should post it, 0 otherwise.

   return true:
       - file isn't opened by parent pid.
       - file hasn't been seen by this routine in minterval seconds.

   otherwise returns false.

   side effect: builds an array of files the routine has seen, and when.
   (called remembered_filenames);
 */
{
	struct timespec ts;
	struct tm s;
	float interval;

	clock_gettime(CLOCK_REALTIME, &ts);
	localtime_r(&(ts.tv_sec), &s);

	/* check against files opened by parent */
	for (int i = 0; (i < last_pfo); i++)
		if (!strcmp(fn, parent_files_open[i]))
			return (1);

	/* if already seen, then return (either too soon, or OK!) */
	for (int i = 0; i < remembered_count; i++) {
		sr_shimdebug_msg(5, "looking at remembered files %d\n", i);
		if (!strcmp((*remembered_filenames)[i].name, fn)) {
			interval = (ts.tv_sec + ts.tv_nsec / 1e9) -
			    ((*remembered_filenames)[i].ts.tv_sec +
			     (*remembered_filenames)[i].ts.tv_nsec / 1e9);
			if (interval < sr_cfg.shim_post_minterval) {
				sr_shimdebug_msg(1,
						 "suppress repeated post of %s (count=%d) (only: %g seconds ago, minterval is: %g)\n",
						 fn, remembered_count, interval,
						 sr_cfg.shim_post_minterval);
				(*remembered_filenames)[i].clean = 0;
				return (1);
			} else {
				sr_shimdebug_msg(1,
						 "shim_post_minterval (%g) exceeded (%g), repeat post of %s (count=%d) \n",
						 sr_cfg.shim_post_minterval, interval, fn,
						 remembered_count);
				(*remembered_filenames)[i].ts = ts;
				(*remembered_filenames)[i].clean =
				    !(sr_c->cfg->shim_defer_posting_to_exit);
				return (0);
			}
		}
	}
	/* lengthen list, if necessary */
	if (remembered_count >= remembered_max) {
		if (!remembered_filenames) {
			remembered_filenames = malloc(1 * sizeof(struct filename_memory));
			remembered_max = 1;
		} else {
			struct filename_memory (*saved_post_filenames)[] = remembered_filenames;
			remembered_max *= 2;
			remembered_filenames =
			    malloc(remembered_max * sizeof(struct filename_memory));

			for (int i = 0; i < remembered_count; i++)
				(*remembered_filenames)[i] = (*saved_post_filenames)[i];
		}
	}

	/* add last item to the list */
	(*remembered_filenames)[remembered_count].clean = !(sr_c->cfg->shim_defer_posting_to_exit);
	(*remembered_filenames)[remembered_count].ts = ts;
	(*remembered_filenames)[remembered_count++].name = strdup(fn);

	sr_shimdebug_msg(1, "remembering post of %s (count=%d) \n", fn, remembered_count);
	return (0);

}

static int shim_disabled = 0;

void srshim_initialize(const char *progname)
{

	static int config_read = 0;
	static int init_in_progress = 0;
	char *setstr;
	int finalize_good;

	if (init_in_progress)
		return;
	init_in_progress = 1;

	sr_shimdebug_msg(3, "srshim_initialize %s starting..\n", progname);
	if (sr_c) {
		sr_shimdebug_msg(3, "srshim_initialize %s already good.\n", progname);
		return;
	}
	setstr = getenv("SR_POST_CONFIG");

	if (setstr == NULL) {
		sr_shimdebug_msg(3, "srshim_initialize %s null config\n", progname);
		return;
	}
	//sr_shimdebug_msg( 3, "srshim_initialize 2 %s setstr=%p\n", progname, setstr);

	// skip many FD to try to avoid stepping over stdout stderr, for logs & broker connection.
	if (config_read == 0) {
		setstr = strdup(setstr);
		sr_shimdebug_msg(9, "srshim_initialize %s about to sr_config_init\n",
				 progname);
		sr_config_init(&sr_cfg, progname);
		if (srshim_debug_level > 0) {
			sr_cfg.loglevel = LOG_DEBUG;
			sr_cfg.debug = 1;
			sr_set_loglevel(NULL,LOG_DEBUG);
		}
		sr_shimdebug_msg(9, "srshim_initialize %s about to sr_config_read\n",
				 progname);
		config_read = sr_config_read(&sr_cfg, setstr, 1, 1);
		logctxptr = sr_cfg.logctx;
		sr_set_loglevel( sr_cfg.logctx, sr_cfg.loglevel );
		sr_shimdebug_msg(9, "srshim_initialize %s back from sr_config_read\n",
				 progname);
		free(setstr);
		if (!config_read) {
			sr_log_msg(sr_cfg.logctx,LOG_ERROR,
				   "srshim_initialize problem with configuration file. library disabled\n");
			shim_disabled = 1;	// turn off the library so stuff works without it.
			errno = 0;
			return;
		}
	}

	if (!close_init_done) {
		setup_exit();
		close_fn_ptr = (close_fn) dlsym(RTLD_NEXT, "close");
		close_init_done = 1;
	}

	/* FIXME: since action is *foreground*, no separate log file will be set up.
	   worry that if we ever use a log file, then there might be a
	   conflict where the log file uses one of the standard file descriptors.
	 */
	sr_shimdebug_msg(9, "srshim_initialize %s about to sr_config_finalize\n", progname);
	finalize_good = sr_config_finalize(&sr_cfg, 0);
	sr_shimdebug_msg(9, "srshim_initialize %s back from sr_config_finalize\n", progname);

	if (!finalize_good) {
		shim_disabled = 1;	// turn off the library so stuff works without it.
		errno = 0;
		sr_shimdebug_msg(3,
				 "srshim_initialize %s disabled, unable to finalize configuration.\n",
				 progname);
		return;
	}

	init_duped_fds();

	if (sr_cfg.shim_skip_parent_open_files)
		setup_pfo();

	sr_c = sr_context_init_config(&sr_cfg, 1);
	if (!sr_c) {
		sr_log_msg(sr_cfg.logctx,LOG_ERROR,
			   "srshim_initialize problem establishing context. library disabled\n");
		shim_disabled = 1;	// turn off the library so stuff works without it.
		errno = 0;
		return;
	}
	init_in_progress = 0;
	errno = 0;
	sr_shimdebug_msg(3, "srshim_initialize setup completed.\n");
}

int srshim_connect()
{
	if (!sr_connected) {

		sr_c = sr_context_connect(sr_c);
		if (sr_c) {
			sr_connected = 1;
			sr_post_init(sr_c);
		} else {
			sr_log_msg(sr_c->cfg->logctx,LOG_ERROR,
				   "srshim_connect problem establishing context. library disabled\n");
			shim_disabled = 1;	// turn off the library so stuff works without it.
		}
		errno = 0;
	}
	return (sr_connected);
}

void srshim_realpost(const char *path)
/*
  post using initialize sr_ context.

 */
{
	struct sr_mask_s *mask;
	struct stat sb;
	int statres;
	char fn[PATH_MAX + 1];
	char fnreal[PATH_MAX + 1];

	sr_shimdebug_msg(1, "srshim_realpost 1 PATH %s src=%p\n", path, sr_c);

	if (!path || !sr_c)
		return;

	sr_shimdebug_msg(1, "srshim_realpost 2 PATH %s\n", path);

	statres = lstat(path, &sb);

	if (!statres && !S_ISDIR(sb.st_mode) && !S_ISREG(sb.st_mode) && !S_ISLNK(sb.st_mode)) {
		sr_shimdebug_msg(1,
				 "srshim_realpost 2.2 returning statres=%d, mode=%o , S_IFREG=%o, S_IFLNK=%o \n",
				 statres, sb.st_mode, S_IFREG, S_IFLNK);
		return;
	}
	strcpy(fn, path);

	if (sr_cfg.realpathPost || sr_cfg.realpathFilter)
		realpath_adjust(sr_cfg.logctx, path, fnreal, sr_cfg.realpathAdjust);

	if (sr_cfg.realpathPost) {
		strcpy(fn, fnreal);
	}

	if (sr_cfg.realpathFilter) {
		mask = sr_isMatchingPattern(&sr_cfg, fnreal);
	} else {
		mask = sr_isMatchingPattern(&sr_cfg, fn);
	}

	if ((mask && !(mask->accepting)) || (!mask && !(sr_cfg.acceptUnmatched))) {	//reject.
		sr_shimdebug_msg(1,
				 "srshim_realpost mask: %p, mask->accepting=%d acceptUnmatched=%d\n",
				 mask, mask?mask->accepting:0, sr_cfg.acceptUnmatched);
		if (sr_cfg.logReject)
			sr_log_msg(sr_cfg.logctx,LOG_INFO, "sr_%s rejecting pattern: %s\n", sr_cfg.progname, fn);
		return;
	}
	sr_shimdebug_msg(1, "srshim_realpost accepted... %s now\n", fn);

	if (should_not_post(fn)) {
		sr_shimdebug_msg(1, "srshim_realpost rejecting should_not_post... %s\n", fn);
		return;
	}
	if (sr_c->cfg->shim_defer_posting_to_exit) {
		sr_shimdebug_msg(1, "srshim_realpost post deferred to exit ... %s\n", fn);
		return;
	}

	if (!srshim_connect()) {
		sr_shimdebug_msg(1, "srshim_realpost post unable to connect... %s\n", fn);
		return;
	}
	if (statres) {
		sr_shimdebug_msg(1,
				 "srshim_realpost should be really posting %s remove now sr_c=%p\n",
				 path, sr_c);
		sr_post(sr_c, path, NULL);
		return;
	}

	sr_shimdebug_msg(1, "srshim_realpost 9 PATH %s\n", path);
	sr_post(sr_c, path, &sb);

}

int shimpost(const char *path, int status)
{
	char *cwd = NULL;
	char *real_path = NULL;
	char saved_errno;

	if (shim_disabled)
		return (status);

	saved_errno=errno;
	// disable shim library during post operations (to avoid forever recursion.)
	shim_disabled = 1;
	sr_shimdebug_msg(3, "shim disabled during post of %s\n", path);
	if (!status) {
		srshim_initialize("shim");

		if (path[0] == '/') {
			sr_shimdebug_msg(3, "absolute 1 shimpost %s, status=%d\n", path, status);
			srshim_realpost(path);
		} else {
			cwd = get_current_dir_name();
			real_path = (char *)malloc(strlen(cwd) + strlen(path) + 3);
			//getwd(real_path);
			strcpy(real_path, cwd);
			strcat(real_path, "/");
			strcat(real_path, path);
			sr_shimdebug_msg(3, "relative 2 shimpost %s status=%d\n", real_path,
					 status);
			srshim_realpost(real_path);
			free(real_path);
			free(cwd);
		}
	}
	shim_disabled = 0;
	sr_shimdebug_msg(3, "shim re-enabled after post of %s\n", path);

	errno=saved_errno;
	return (status);
}


static int dup2_init_done = 0;
typedef int (*dup2_fn)(int, int);
static dup2_fn dup2_fn_ptr = dup2;

int dup2(int oldfd, int newfd)
{
	int fdstat;
	char fdpath[32];
	char real_path[PATH_MAX + 1];
	char *real_return;
	int status;

	sr_shimdebug_msg(1, " dup2 oldfd %d newfd %d\n", oldfd, newfd);

	if (!dup2_init_done) {
		setup_exit();
		dup2_fn_ptr = (dup2_fn) dlsym(RTLD_NEXT, "dup2");
		dup2_init_done = 1;
		srshim_initialize("shim");
	}

	errno = 0;

	if (shim_disabled || (oldfd == newfd)) {
		sr_shimdebug_msg(4, " dup2 NO POST oldfd = newfd \n");
		return dup2_fn_ptr(oldfd, newfd);
	}

	fdstat = fcntl(oldfd, F_GETFL);

	if (fdstat == -1) {
		sr_shimdebug_msg(4, " dup2 NO POST not valid fd !\n");
		errno = 0;
		return dup2_fn_ptr(oldfd, newfd);
	}

	if ((fdstat & O_ACCMODE) == O_RDONLY) {
		sr_shimdebug_msg(4, " dup2 NO POST read mode !\n");
		errno = 0;
		return dup2_fn_ptr(oldfd, newfd);
	}

	snprintf(fdpath, 32, "/proc/self/fd/%d", oldfd);
	real_return = realpath(fdpath, real_path);

	if (!real_return) {
		sr_shimdebug_msg(4, " dup2 NO POST no path from fd !\n");
		errno = 0;
		return dup2_fn_ptr(oldfd, newfd);
	}

	if (!strncmp(real_path, "/dev/", 5) || !strncmp(real_path, "/proc/", 6)) {
		sr_shimdebug_msg(4, " dup2 NO POST path device or proc !\n");
		errno = 0;
		return dup2_fn_ptr(oldfd, newfd);
	}

	if (!getenv("SR_POST_READS"))
		srshim_initialize("shim");

	// If newfd is open, then it will be closed by dup2, perhaps trigger post?
	// recipe: https://stackoverflow.com/questions/12340695/how-to-check-if-a-given-file-descriptor-stored-in-a-variable-is-still-valid
	if ((fcntl(newfd, F_GETFD) != -1) || errno != EBADF) {
		sr_shimdebug_msg(4,
				 " dup2 newfd is open, so close it explicitly to potentially post.\n");
		close(newfd);
	}

	status = dup2_fn_ptr(oldfd, newfd);
	if (status == -1)
		return status;

	record_duped_fds(oldfd, newfd);

	sr_shimdebug_msg(1, " dup2 posting %s status=%d\n", real_path, status);

	clerror(status);

	return status;
}

static int dup3_init_done = 0;
typedef int (*dup3_fn)(int, int, int);
static dup3_fn dup3_fn_ptr = dup3;

int dup3(int oldfd, int newfd, int flags)
{
	int fdstat;
	char fdpath[32];
	char real_path[PATH_MAX + 1];
	char *real_return;
	int status;

	sr_shimdebug_msg(1, " dup3 oldfd %d newfd %d flags %d\n", oldfd, newfd, flags);

	if (!dup3_init_done) {
		setup_exit();
		dup3_fn_ptr = (dup3_fn) dlsym(RTLD_NEXT, "dup3");
		dup3_init_done = 1;
		if (getenv("SR_POST_READS"))
			srshim_initialize("shim");
	}

	if (shim_disabled || (oldfd == newfd)) {
		sr_shimdebug_msg(4, " dup3 NO POST oldfd = newfd \n");
		errno = 0;
		return dup3_fn_ptr(oldfd, newfd, flags);
	}

	fdstat = fcntl(newfd, F_GETFL);

	if (fdstat == -1) {
		sr_shimdebug_msg(4, " dup3 NO POST not valid fd !\n");
		errno = 0;
		return dup3_fn_ptr(oldfd, newfd, flags);
	}

	if ((fdstat & O_ACCMODE) == O_RDONLY) {
		sr_shimdebug_msg(4, " dup3 NO POST read mode !\n");
		errno = 0;
		return dup3_fn_ptr(oldfd, newfd, flags);
	}

	snprintf(fdpath, 32, "/proc/self/fd/%d", newfd);
	real_return = realpath(fdpath, real_path);

	if (!real_return) {
		sr_shimdebug_msg(4, " dup3 NO POST no path from fd !\n");
		errno = 0;
		return dup3_fn_ptr(oldfd, newfd, flags);
	}

	if (!strncmp(real_path, "/dev/", 5) || !strncmp(real_path, "/proc/", 6)) {
		sr_shimdebug_msg(4, " dup3 NO POST path device or proc !\n");
		errno = 0;
		return dup3_fn_ptr(oldfd, newfd, flags);
	}

	if (!getenv("SR_POST_READS"))
		srshim_initialize("shim");

	// If newfd is open, then it will be closed by dup2, perhaps trigger post?
	if ((fcntl(newfd, F_GETFD) != -1) || errno != EBADF) {
		sr_shimdebug_msg(4,
				 " dup3 newfd is open, so close it explicitly to potentially post.\n");
		close(newfd);
	}

	errno = 0;
	status = dup3_fn_ptr(oldfd, newfd, flags);
	if (status == -1)
		return status;

	record_duped_fds(oldfd, newfd);

	sr_shimdebug_msg(1, " dup3 posting %s %d\n", real_path, status);

	// because shimpost posts when:    if (!status)
	// we use a tmpstatus and call shimpost with status=0

	shimpost(real_path, 0);

	clerror(status);
	return status;
}

static int exit_cleanup_posts_ran = 0;


void exit_cleanup_posts()
{
	int fdstat;
	struct stat sb;
	int statres;
	char fdpath[500];
	char real_path[PATH_MAX + 1];
	char *real_return;
	int fd;
	int found;
	DIR *fddir = NULL;
	struct dirent *fdde;

	sr_shimdebug_msg(1, "exit_cleanup_posts, context=%p\n", sr_c);

	if (exit_cleanup_posts_ran || shim_disabled || !getenv("SR_POST_CONFIG"))
		return;

	exit_cleanup_posts_ran = 1;

	sr_shimdebug_msg(4, "exit_cleanup_posts, scan /proc/self/fd\n");
	// In the current process, find files which are not opened by the parent
	// that need posting.
	fddir = opendir("/proc/self/fd");

	if (fddir) {
		while ((fdde = readdir(fddir))) {
			sr_shimdebug_msg(8, "exit_cleanup_posts, readdir fdde->d_name=%s\n",
					 fdde->d_name);
			if (fdde->d_name[0] == '.')
				continue;

			fd = atoi(fdde->d_name);
			fdstat = fcntl(fd, F_GETFL);

			if (fdstat == -1) {
				sr_shimdebug_msg(16,
						 "exit_cleanup_posts, fcntl failed, skipping\n");
				continue;
			}

			if ((fdstat & O_ACCMODE) == O_RDONLY) {
				sr_shimdebug_msg(16, "exit_cleanup_posts, read-only, skipping\n");
				continue;
			}
			if (!strcmp(fdde->d_name,"2")) {
				sr_shimdebug_msg(16, "exit_cleanup_posts, stderr, skipping\n");
				continue;
			}
			snprintf(fdpath, 499, "/proc/self/fd/%s", fdde->d_name);
			real_return = realpath(fdpath, real_path);

			if ((!real_return) || (real_path[0] != '/') ||
			    (!strncmp(real_path, "/dev/", 5))
			    || (!strncmp(real_path, "/proc/", 6))) {
				sr_shimdebug_msg(16,
						 "exit_cleanup_posts, /proc or /dev, skipping\n");
				continue;
			}
			sr_shimdebug_msg(16, "exit_cleanup_posts, real_return=%s\n", real_path);
			found = 0;
			for (int i = 0; (i < last_pfo); i++) {
				sr_shimdebug_msg(8,
						 "exit_cleanup_posts, last_pfo i=%d open_file=%s\n",
						 i, parent_files_open[i]);
				if (!strcmp(real_path, parent_files_open[i])) {
					found = 1;
					break;
				}
			}

			if (found) {
				sr_shimdebug_msg(16,
						 "exit_cleanup_posts, parent has file open, skipping\n");
				continue;
			}
			fsync(fd);	// ensure data is flushed to disk before post occurs.

			sr_shimdebug_msg(8, "exit_cleanup_posts posting %s\n", real_path);

			shimpost(real_path, 0);
		}
		closedir(fddir);
	}

	sr_shimdebug_msg(1, "exit_cleanup_posting... deferred posting start.\n");

	/* execute deferred/remembered posts, FIXME: embarrasing n**2 algo, should do better later */
	for (int i = 0; i < remembered_count; i++) {
		// if a file was already posted and hasn't been written since.
		sr_shimdebug_msg(8, "exit_cleanup_post, i=%d\n", i);
		if (!(sr_cfg.shim_defer_posting_to_exit)
		    && (*remembered_filenames)[i].clean)
			continue;

		srshim_initialize("shim");

		if (!srshim_connect())
			continue;

		sr_shimdebug_msg(8, "exit_cleanup_post, looking at: %s\n",
				 (*remembered_filenames)[i].name);
		statres = lstat((*remembered_filenames)[i].name, &sb);

		if (statres) {
			sr_post(sr_c, (*remembered_filenames)[i].name, NULL);
		} else {
			if (S_ISLNK(sb.st_mode)) {
				sr_shimdebug_msg(8, "exit_cleanup_post reading link: %s\n",
						 (*remembered_filenames)[i].name);
				statres =
				    readlink((*remembered_filenames)[i].name, real_path, PATH_MAX);
				if (statres) {
					real_path[statres] = '\0';
					sr_post(sr_c, real_path, &sb);
				}
			}
			sr_post(sr_c, (*remembered_filenames)[i].name, &sb);
		}
	}
	sr_shimdebug_msg(1, "exit_cleanup_posting closing context sr_c=%p\n", sr_c);
	if (sr_c)
		sr_context_close(sr_c);

	free(sr_c);
	sr_c = NULL;

	// cleaning up parent file open list.
	for (int i = 0; (i < last_pfo); i++)
		free(parent_files_open[i]);
	free(parent_files_open);

	//FIXME: free the parent file open array...

	//sr_config_free(&sr_cfg);

	// after this point things get closed, so cannot reliably post.
	// turn off libsrshim functionality.

	shim_disabled = 1;

}

//void exit(int status) __attribute__((noreturn));

typedef void (*exit_fn)(int) __attribute__( (noreturn));

void exit(int status)
{
	static exit_fn exit_fn_ptr = NULL;

	if (exit_cleanup_posts_ran)
		_exit(status);

	exit_fn_ptr = (exit_fn) dlsym(RTLD_NEXT, "exit");

	exit_cleanup_posts();

	// how to ensure other atexit functions run? call it again... loop potential.
	exit_fn_ptr(status);
}

/*  
   in some process traces, saw that exit wasn't being called, only exit_group.
   added this, but it didn't solve the problem, so removing for now...

 */
void exit_group(int status)
{
	static exit_fn exit_group_fn_ptr = NULL;

	sr_shimdebug_msg(1, "exit_group 0, context=%p\n", sr_c);

	exit_group_fn_ptr = (exit_fn) dlsym(RTLD_NEXT, "exit_group");

	if (!getenv("SR_POST_CONFIG") || shim_disabled)
		exit_group_fn_ptr(status);

	exit_cleanup_posts();

	// do it for real.
	exit_group_fn_ptr(status);
}

static int copy_file_range_init_done = 0;
typedef ssize_t(*copy_file_range_fn) (int, __off64_t *, int, __off64_t *, size_t, unsigned int);
static copy_file_range_fn copy_file_range_fn_ptr = NULL;

ssize_t copy_file_range(int fd_in, __off64_t * off_in, int fd_out,
			__off64_t * off_out, size_t len, unsigned int flags)
{
	ssize_t status;
	char fdpath[32];
	char real_path[PATH_MAX + 1];
	char *real_return;

	sr_shimdebug_msg(1, "copy_file_range(%d,%p,%d,%p,%ld,%d)\n", fd_in, off_in, fd_out, off_out, len, flags);
	if (!copy_file_range_init_done) {
		setup_exit();
		copy_file_range_fn_ptr = (copy_file_range_fn) dlsym(RTLD_NEXT, "copy_file_range");
		copy_file_range_init_done = 1;
	}
	sr_shimdebug_msg(1, "copy_file_range, 961 ready to call real one\n" );
	status = copy_file_range_fn_ptr(fd_in, off_in, fd_out, off_out, len, flags);
	sr_shimdebug_msg(1, "copy_file_range, 963 back from real one (copied %ld bytes)\n", status );
	if (shim_disabled)
		return (status);

	if (!status) {
	        sr_shimdebug_msg(1, "copy_file_range, 963 ERROR no bytes copied, nothing to post\n", status );
		return (status);
	}

	sr_shimdebug_msg(1, "copy_file_range, 967 about to try to post...\n" );
	snprintf(fdpath, 32, "/proc/self/fd/%d", fd_out);
	real_return = realpath(fdpath, real_path);

	sr_shimdebug_msg(1, "copy_file_range to %s, real_return=%d\n", real_path, real_return);

	if (!real_return)
		return (status);
	if (!strncmp(real_path, "/dev/", 5))
		return (status);
	if (!strncmp(real_path, "/proc/", 6))
		return (status);

	shimpost(real_path, 0);

	clerror(status);
	return (status);
}

int close(int fd)
{

	int fdstat;
	char fdpath[PATH_MAX];
	char real_path[PATH_MAX + 1];
	char *real_return;
	int status;

	sr_shimdebug_msg(4, " close fd=%d!\n", fd);
	if (!close_init_done) {
		setup_exit();
		close_fn_ptr = (close_fn) dlsym(RTLD_NEXT, "close");
		close_init_done = 1;
		if (getenv("SR_POST_READS"))
			srshim_initialize("shim");
	}
	if (shim_disabled) {
		sr_shimdebug_msg(8, " close fd=%d shim_disabled, passing to built-in.\n", fd);
		return close_fn_ptr(fd);
	}
	fdstat = fcntl(fd, F_GETFL);

	if (fdstat == -1) {
		sr_shimdebug_msg(8, " close NO POST not valid fd !\n");
		errno = 0;
		return close_fn_ptr(fd);
	}

	// check against duped files 
	if (is_duped(fd)) {
		return close_fn_ptr(fd);
	}

	if ((fdstat & O_ACCMODE) == O_RDONLY) {
		errno = 0;
		sr_shimdebug_msg(8, " close fd=%d read-only, so no post, passing to built-in.\n",
				 fd);
		return close_fn_ptr(fd);
	}
	snprintf(fdpath, 32, "/proc/self/fd/%d", fd);
	real_return = realpath(fdpath, real_path);

	if (!getenv("SR_POST_READS"))
		srshim_initialize("shim");

	errno = 0;
	status = close_fn_ptr(fd);
	if (status == -1) {
		sr_shimdebug_msg(8, " close fd=%d failed, returning without post.\n", fd);
		return status;
	}
	if (!real_return) {
		sr_shimdebug_msg(8, " close fd=%d - %s real_returning... no post.\n", fd, real_path);
	        errno=0;
		return status;
	}
	sr_shimdebug_msg(8, "close fd=%d realpath=%s\n", fd, real_path);

	if (!strncmp(real_path, "/dev/", 5)) {
		sr_shimdebug_msg(8, " close fd=%d reject /dev: %s\n", fd, real_path );
	        errno=0;
		return (status);
	}

	if (!strncmp(real_path, "/proc/", 6)) {
		sr_shimdebug_msg(8, " close fd=%d reject /proc: %s\n", fd, real_path );
	        errno=0;
		return (status);
	}
	sr_shimdebug_msg(8, "close fd=%d realpath=%s passing to shimpost\n", fd, real_path);
	errno=0;

	return shimpost(real_path, status);
}

/*
static int fclose_init_done = 0;
typedef int (*fclose_fn)(FILE *);
static fclose_fn fclose_fn_ptr = fclose;

int fclose(FILE * f)
{

	int fd;
	int fdstat;
	char fdpath[32];
	char real_path[PATH_MAX + 1];
	char *real_return;
	int status;

	if (!fclose_init_done) {
		setup_exit();
		fclose_fn_ptr = (fclose_fn) dlsym(RTLD_NEXT, "fclose");
		fclose_init_done = 1;
		if (getenv("SR_POST_READS"))
			srshim_initialize("shim");
	}
	if (shim_disabled)
		return fclose_fn_ptr(f);

	fd = fileno(f);
	if (fd == -1) {
		clerror(fd);
		return fclose_fn_ptr(f);
	}

	// check against duped files 
	if (is_duped(fd)) {
		return fclose_fn_ptr(f);
	}

	fdstat = fcntl(fd, F_GETFL);

	sr_shimdebug_msg(5, " fclose %p fd=%i fdstat=%o, starting\n", f, fd, fdstat);

	if (fdstat == -1) {
		sr_shimdebug_msg(5, " fclose NO POST not valid fd=%d !\n", fd);
		errno = 0;
		return fclose_fn_ptr(f);
	}

	if ((fdstat & O_ACCMODE) == O_RDONLY) {
		sr_shimdebug_msg(5, " fclose NO POST read-only. fd=%d\n", fd);
		errno = 0;
		return fclose_fn_ptr(f);
	}

	if (fd == 2 || fd==13 || fd==27) {
		sr_shimdebug_msg(5, " fclose %d skipping fd I do not like\n", fd );
		return 0;
	}

	snprintf(fdpath, 32, "/proc/self/fd/%d", fd);
	real_return = realpath(fdpath, real_path);
	sr_shimdebug_msg(5, " fclose %p real_return=%s\n", f, real_return);
	status = fclose_fn_ptr(f);
	clerror(status);

	if (status != 0)
		return status;
	if (!real_return)
		return (status);

	if (!strncmp(real_path, "/dev/", 5)) {
		clerror(status);
		return (status);
	}

	if (!strncmp(real_path, "/proc/", 6)) {
		clerror(status);
		return (status);
	}

	sr_shimdebug_msg(2, "fclose %p %s status=%d\n", f, real_path, status);

	return shimpost(real_path, status);
}
*/
