
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
#endif

#include <dirent.h>
#define clerror(s)  if (s==0) { errno=0; }

#include "sr_post.h"

/*
See https://github.com/MetPX/sarrac/issues/145. 
glibc < 2.28 doesn't provide renameat2.
*/
#if !__GLIBC_PREREQ(2,28)
#define INTERCEPT_SYSCALL
#endif

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

void syscall_init();

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
				 mask, mask->accepting, sr_cfg.acceptUnmatched);
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

	if (shim_disabled)
		return (status);

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

	clerror(status);
	return (status);
}

static int truncate_init_done = 0;
typedef int (*truncate_fn)(const char *, off_t length);
static truncate_fn truncate_fn_ptr = truncate;

int truncate(const char *path, off_t length)
{
	int status;

	if (!truncate_init_done) {
		setup_exit();
		truncate_fn_ptr = (truncate_fn) dlsym(RTLD_NEXT, "truncate");
		truncate_init_done = 1;
	}
	status = truncate_fn_ptr(path, length);

	if (shim_disabled)
		return (status);

	//clerror(status);
	if (status == -1)
		return status;

	if (!strncmp(path, "/dev/", 5))
		return (status);
	if (!strncmp(path, "/proc/", 6))
		return (status);

	return (shimpost(path, status));

}

static int mkdir_init_done = 0;
typedef int (*mkdir_fn)(const char *, mode_t);
static mkdir_fn mkdir_fn_ptr = mkdir;

int mkdir(const char *pathname, mode_t mode)
{
	int status;

	sr_shimdebug_msg(1, "mkdir %s %4o\n", pathname, mode);
	if (!mkdir_init_done) {
		setup_exit();
		mkdir_fn_ptr = (mkdir_fn) dlsym(RTLD_NEXT, "mkdir");
		mkdir_init_done = 1;
	}
	status = mkdir_fn_ptr(pathname, mode);
	if (shim_disabled)
		return (status);

	clerror(status);
	if (status == -1)
		return status;

	if (!strncmp(pathname, "/dev/", 5))
		return (status);
	if (!strncmp(pathname, "/proc/", 6))
		return (status);

	return (shimpost(pathname, status));
}

static int mkdirat_init_done = 0;
typedef int (*mkdirat_fn)(int, const char *, mode_t);
static mkdirat_fn mkdirat_fn_ptr = mkdirat;

int mkdirat(int dirfd, const char *pathname, mode_t mode)
{
	int status;

	sr_shimdebug_msg(1, "mkdirat %d %s %4o\n", dirfd, pathname, mode);
	if (!mkdirat_init_done) {
		setup_exit();
		mkdirat_fn_ptr = (mkdirat_fn) dlsym(RTLD_NEXT, "mkdirat");
		mkdirat_init_done = 1;
	}
	status = mkdirat_fn_ptr(dirfd, pathname, mode);
	if (shim_disabled)
		return (status);

	clerror(status);
	if (status == -1)
		return status;

	if (!strncmp(pathname, "/dev/", 5))
		return (status);
	if (!strncmp(pathname, "/proc/", 6))
		return (status);

	return (shimpost(pathname, status));
}

static int rmdir_init_done = 0;
typedef int (*rmdir_fn)(const char *);
static rmdir_fn rmdir_fn_ptr = rmdir;

int rmdir(const char *pathname)
{
	int status;

	sr_shimdebug_msg(1, "rmdir %s\n", pathname);
	if (!rmdir_init_done) {
		setup_exit();
		rmdir_fn_ptr = (rmdir_fn) dlsym(RTLD_NEXT, "rmdir");
		rmdir_init_done = 1;
	}
	status = rmdir_fn_ptr(pathname);
	if (shim_disabled)
		return (status);

	clerror(status);
	if (status == -1)
		return status;

	if (!strncmp(pathname, "/dev/", 5))
		return (status);
	if (!strncmp(pathname, "/proc/", 6))
		return (status);

	rmdir_in_progress = 1;
	return (shimpost(pathname, status));
}

static int remove_init_done = 0;
typedef int (*remove_fn)(const char *);
static remove_fn remove_fn_ptr = remove;

int remove(const char *pathname)
{
	int status;
	struct stat sb;
	int statres;
	bool isdir = false;

	sr_shimdebug_msg(1, "remove %s\n", pathname);
	if (!remove_init_done) {
		setup_exit();
		remove_fn_ptr = (remove_fn) dlsym(RTLD_NEXT, "remove");
		remove_init_done = 1;
	}

	// before removing, need to know if pathname is a file or dir
	// if stat fails, also assuming that pathname is not a dir
	statres = lstat(pathname, &sb);
	if (!statres) {
		isdir = S_ISDIR(sb.st_mode);
	}

	status = remove_fn_ptr(pathname);
	if (shim_disabled)
		return (status);

	sr_shimdebug_msg(1, " remove 2 %s status=%d\n", pathname, status);	

	clerror(status);
	if (status == -1)
		return status;

	if (!strncmp(pathname, "/dev/", 5))
		return (status);
	if (!strncmp(pathname, "/proc/", 6))
		return (status);

	if (isdir) {
		rmdir_in_progress = 1;
	}
	return (shimpost(pathname, status));
}

static int symlink_init_done = 0;
typedef int (*symlink_fn)(const char *, const char *);
static symlink_fn symlink_fn_ptr = symlink;

int symlink(const char *target, const char *linkpath)
{
	int status;

	sr_shimdebug_msg(1, "symlink %s %s\n", target, linkpath);
	if (!symlink_init_done) {
		setup_exit();
		symlink_fn_ptr = (symlink_fn) dlsym(RTLD_NEXT, "symlink");
		symlink_init_done = 1;
	}
	status = symlink_fn_ptr(target, linkpath);
	if (shim_disabled)
		return (status);

	clerror(status);
	if (status == -1)
		return status;

	if (!strncmp(linkpath, "/dev/", 5))
		return (status);
	if (!strncmp(linkpath, "/proc/", 6))
		return (status);

	return (shimpost(linkpath, status));
}

static int symlinkat_init_done = 0;
typedef int (*symlinkat_fn)(const char *, int, const char *);
static symlinkat_fn symlinkat_fn_ptr = symlinkat;

int symlinkat(const char *target, int dirfd, const char *linkpath)
{
	int status;
	char fdpath[PATH_MAX + 1];
	char real_path[PATH_MAX + 1];
	char *real_return;

	if (!symlinkat_init_done) {
		setup_exit();
		symlinkat_fn_ptr = (symlinkat_fn) dlsym(RTLD_NEXT, "symlinkat");
		symlinkat_init_done = 1;
	}
	status = symlinkat_fn_ptr(target, dirfd, linkpath);

	if (shim_disabled) {
		sr_shimdebug_msg(1, "symlinkat %s %s\n", target, linkpath);
		return (status);
	}
	clerror(status);
	if (status == -1)
		return status;

	if (!strncmp(linkpath, "/dev/", 5))
		return (status);
	if (!strncmp(linkpath, "/proc/", 6))
		return (status);

	if (dirfd == AT_FDCWD) {
		clerror(status);
		return (shimpost(linkpath, status));
	}

	snprintf(fdpath, 32, "/proc/self/fd/%d", dirfd);
	real_return = realpath(fdpath, real_path);

	sr_shimdebug_msg(1, "4 symlinkat real_path=%s target=%s linkpath=%s\n", real_path, target,
			 linkpath);

	clerror(status);
	if (!real_return) {
		return (status);
	}
	strcat(real_path, "/");
	strcat(real_path, linkpath);

	clerror(status);
	return (shimpost(real_path, status));

}

static int unlinkat_init_done = 0;
typedef int (*unlinkat_fn)(int dirfd, const char *, int flags);
static unlinkat_fn unlinkat_fn_ptr = unlinkat;

int unlinkat(int dirfd, const char *path, int flags)
{
	int status;
	int stat_failed;
	struct stat sb;
	char fdpath[PATH_MAX + 1];
	char real_path[PATH_MAX + 1];
	char *real_return;

	sr_shimdebug_msg(1, "unlinkat %s dirfd=%i\n", path, dirfd);
	if (!unlinkat_init_done) {
		setup_exit();
		unlinkat_fn_ptr = (unlinkat_fn) dlsym(RTLD_NEXT, "unlinkat");
		unlinkat_init_done = 1;
	}

	stat_failed = fstatat(dirfd, path, &sb, 0);
	sr_shimdebug_msg(1, "unlinkat %s dirfd=%i stat returned: %d\n", path, dirfd, stat_failed);

	status = unlinkat_fn_ptr(dirfd, path, flags);
	if (shim_disabled)
		return status;
	clerror(status);
	if (status == -1)
		return status;

	if (dirfd == AT_FDCWD)
		return (shimpost(path, status));

	snprintf(fdpath, 32, "/proc/self/fd/%d", dirfd);
	real_return = realpath(fdpath, real_path);
	sr_shimdebug_msg(1, " unlinkat relative directory %s real_return=%p\n", fdpath,
			 real_return);
	strcat(real_path, "/");
	strcat(real_path, path);

	clerror(status);
	if (!real_return)
		return (status);

	sr_shimdebug_msg(1, " unlinkat realpath %s\n", real_path);

	return (shimpost(real_path, status));
}

static int unlink_init_done = 0;
typedef int (*unlink_fn)(const char *);
static unlink_fn unlink_fn_ptr = unlink;

int unlink(const char *path)
{
	int status;

	sr_shimdebug_msg(1, " unlink %s\n", path);
	if (!unlink_init_done) {
		setup_exit();
		unlink_fn_ptr = (unlink_fn) dlsym(RTLD_NEXT, "unlink");
		unlink_init_done = 1;
	}
	status = unlink_fn_ptr(path);
	if (shim_disabled)
		return (status);

	sr_shimdebug_msg(1, " unlink 2 %s status=%d\n", path, status);

	if (status == -1)
		return status;

	if (!strncmp(path, "/dev/", 5)) {
		clerror(status);
		return (status);
	}

	return (shimpost(path, status));
}

static int link_init_done = 0;
typedef int (*link_fn)(const char *, const char *);
static link_fn link_fn_ptr = link;

static int linkat_init_done = 0;
typedef int (*linkat_fn)(int, const char *, int, const char *, int flags);
static linkat_fn linkat_fn_ptr = linkat;

static int renameat_init_done = 0;
typedef int (*renameat_fn)(int, const char *, int, const char *);
static renameat_fn renameat_fn_ptr = NULL;


static int renameat2_init_done = 0;
typedef int (*renameat2_fn)(int, const char *, int, const char *, unsigned int);
static renameat2_fn renameat2_fn_ptr = NULL;

static int syscall_init_done = 0;
typedef long int (*syscall_fn)(long int, ...);
static syscall_fn syscall_fn_ptr = NULL;


int renameorlink(int olddirfd, const char *oldpath, int newdirfd,
		 const char *newpath, int flags, int link)
/*
  The real implementation of all renames.
 */
{
	int status;
	char fdpath[32];
	char real_path[PATH_MAX + 1];
	char *real_return;
	char oreal_path[PATH_MAX + 1];
	char *oreal_return;

	sr_shimdebug_msg(1, " renameorlink %s %s\n", oldpath, newpath);

	if (!renameat2_init_done) {
		setup_exit();
		renameat2_fn_ptr = (renameat2_fn) dlsym(RTLD_NEXT, "renameat2");
		renameat2_init_done = 1;
	}

	if (!renameat_init_done) {
		renameat_fn_ptr = (renameat_fn) dlsym(RTLD_NEXT, "renameat");
		renameat_init_done = 1;
	}

	if (!link_init_done) {
		link_fn_ptr = (link_fn) dlsym(RTLD_NEXT, "link");
		link_init_done = 1;
	}

	if (!linkat_init_done) {
		linkat_fn_ptr = (linkat_fn) dlsym(RTLD_NEXT, "linkat");
		linkat_init_done = 1;
	}

	if (!syscall_init_done) {
		syscall_init();
	}

	if (link) {
		if (linkat_fn_ptr)
			status = linkat_fn_ptr(olddirfd, oldpath, newdirfd, newpath, flags);
		else if (link_fn_ptr && !flags)
			status = link_fn_ptr(oldpath, newpath);
		else {
			sr_log_msg(logctxptr,LOG_ERROR,
				   " renameorlink could not identify real entry point for link\n");
		}
	} else {
		if (renameat2_fn_ptr) {
			sr_shimdebug_msg(1, " renameorlink using renameat2\n");
			status = renameat2_fn_ptr(olddirfd, oldpath, newdirfd, newpath, flags);
		} else if (renameat_fn_ptr && !flags) {
			sr_shimdebug_msg(1, " renameorlink using renameat\n");
			status = renameat_fn_ptr(olddirfd, oldpath, newdirfd, newpath);
		} else if (syscall_fn_ptr) {
			sr_shimdebug_msg(1, " renameorlink using renameat2 via syscall(SYS_renameat2, ...)\n");
			status = syscall_fn_ptr(SYS_renameat2, olddirfd, oldpath, newdirfd, newpath, flags);
		} else {
			sr_log_msg(logctxptr,LOG_ERROR,
				   " renameorlink could not identify real entry point for renameat\n");
			return (-1);
		}
	}
	if (shim_disabled)
		return (status);

	if (status == -1) {
		sr_shimdebug_msg(1, " renameorlink %s %s failed, no post\n", oldpath, newpath);
		return (status);
	}

	srshim_initialize("shim");

	clerror(status);
	if (!sr_c)
		return (status);

	if (olddirfd == AT_FDCWD) {
		strcpy(oreal_path, oldpath);
	} else {
		snprintf(fdpath, 32, "/proc/self/fd/%d", olddirfd);
		oreal_return = realpath(fdpath, oreal_path);
		if (oreal_return) {
			sr_log_msg(logctxptr,LOG_WARNING,
				   "srshim renameorlink could not obtain real_path for olddir=%s failed, no post\n",
				   fdpath);
			clerror(status);
			return (status);
		}
		strcat(oreal_path, "/");
		strcat(oreal_path, oldpath);
	}

	if (newdirfd == AT_FDCWD) {
		strcpy(real_path, newpath);
	} else {
		snprintf(fdpath, 32, "/proc/self/fd/%d", newdirfd);
		real_return = realpath(fdpath, real_path);
		if (real_return) {
			sr_log_msg(logctxptr,LOG_WARNING,
				   "srshim renameorlink could not obtain real_path for newdir=%s failed, no post\n",
				   fdpath);
			clerror(status);
			return (status);
		}
		strcat(real_path, "/");
		strcat(real_path, newpath);
	}
	sr_shimdebug_msg(1,
			 " renameorlink sr_c=%p, oreal_path=%s, real_path=%s\n",
			 sr_c, oreal_path, real_path);

	if (!srshim_connect())
		return (status);

	sr_post_rename(sr_c, oreal_path, real_path);

	clerror(status);
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

int link(const char *target, const char *linkpath)
{
	sr_shimdebug_msg(1, " link %s %s\n", target, linkpath);
	return (renameorlink(AT_FDCWD, target, AT_FDCWD, linkpath, 0, 1));
}

int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags)
{
	sr_shimdebug_msg(1,
			 "linkat olddirfd=%d, oldname=%s newdirfd=%d newname=%s flags=%d\n",
			 olddirfd, oldpath, newdirfd, newpath, flags);
	return (renameorlink(olddirfd, oldpath, newdirfd, newpath, flags, 1));
}

int rename(const char *oldpath, const char *newpath)
{
	sr_shimdebug_msg(1, "rename %s %s\n", oldpath, newpath);

	return (renameorlink(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0, 0));
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
	sr_shimdebug_msg(1, "renameat %s %s\n", oldpath, newpath);

	return (renameorlink(olddirfd, oldpath, newdirfd, newpath, 0, 0));
}

int renameat2(int olddirfd, const char *oldpath, int newdirfd,
	      const char *newpath, unsigned int flags)
{
	sr_shimdebug_msg(1, "renameat2 %s %s\n", oldpath, newpath);

	return (renameorlink(olddirfd, oldpath, newdirfd, newpath, flags, 0));
}

void syscall_init()
{
	if (!syscall_init_done) {
		setup_exit();
		syscall_fn_ptr = (syscall_fn) dlsym(RTLD_NEXT, "syscall");
		syscall_init_done = 1;
	}
}

static int sendfile_init_done = 0;
typedef ssize_t(*sendfile_fn) (int, int, off_t *, size_t);
static sendfile_fn sendfile_fn_ptr = NULL;

ssize_t sendfile(int out_fd, int in_fd, off_t * offset, size_t count)
{
	ssize_t status;
	char fdpath[32];
	char real_path[PATH_MAX + 1];
	char *real_return;

	if (!sendfile_init_done) {
		setup_exit();
		sendfile_fn_ptr = (sendfile_fn) dlsym(RTLD_NEXT, "sendfile");
		sendfile_init_done = 1;
	}
	status = sendfile_fn_ptr(out_fd, in_fd, offset, count);
	if (status == -1)
		return status;
	if (shim_disabled)
		return (status);

	snprintf(fdpath, 32, "/proc/self/fd/%d", out_fd);
	real_return = realpath(fdpath, real_path);

	sr_shimdebug_msg(1, " sendfile to %s\n", real_path);

	clerror(status);
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

static int copy_file_range_init_done = 0;
typedef ssize_t(*copy_file_range_fn) (int, loff_t *, int, loff_t *, size_t, unsigned int);
static copy_file_range_fn copy_file_range_fn_ptr = NULL;

ssize_t copy_file_range(int fd_in, loff_t * off_in, int fd_out,
			loff_t * off_out, size_t len, unsigned int flags)
{
	ssize_t status;
	char fdpath[32];
	char real_path[PATH_MAX + 1];
	char *real_return;

	if (!copy_file_range_init_done) {
		setup_exit();
		copy_file_range_fn_ptr = (copy_file_range_fn) dlsym(RTLD_NEXT, "copy_file_range");
		copy_file_range_init_done = 1;
	}
	status = copy_file_range_fn_ptr(fd_in, off_in, fd_out, off_out, len, flags);
	if (shim_disabled)
		return (status);

	snprintf(fdpath, 32, "/proc/self/fd/%d", fd_out);
	real_return = realpath(fdpath, real_path);

	sr_shimdebug_msg(1, "copy_file_range to %s\n", real_path);

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
	char fdpath[32];
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

	/* check against duped files */
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
		sr_shimdebug_msg(8, " close fd=%d - %s, failed, returning without post.\n", fd,
				 real_path);
		return status;
	}
	clerror(status);
	if (!real_return) {
		sr_shimdebug_msg(8, " close fd=%d - %s real_returning... no post.\n", fd,
				 real_path);
		return status;
	}
	sr_shimdebug_msg(8, "close %s fd=%d\n", real_path, fd);

	if (!strncmp(real_path, "/dev/", 5)) {
		clerror(status);
		return (status);
	}

	if (!strncmp(real_path, "/proc/", 6)) {
		clerror(status);
		return (status);
	}

	return shimpost(real_path, status);
}

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

	/* check against duped files */
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

	snprintf(fdpath, 32, "/proc/self/fd/%d", fd);
	real_return = realpath(fdpath, real_path);
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

static int fopen_init_done = 0;
typedef FILE *(*fopen_fn)(const char *pathname, const char *mode);
static fopen_fn fopen_fn_ptr = fopen;

FILE *fopen(const char *pathname, const char *mode)
/*
  fopen will never trigger any posts, currently, it only serves to prime for (setup_exit())

 */
{
	if (!fopen_init_done) {
		fopen_fn_ptr = (fopen_fn) dlsym(RTLD_NEXT, "fopen");
		fopen_init_done = 1;
		if (getenv("SR_POST_READS"))
			srshim_initialize("shim");
		setup_exit();
	}
	sr_shimdebug_msg(2, "fopen %s %s\n", pathname, mode);

	return (fopen_fn_ptr(pathname, mode));
}


#ifdef INTERCEPT_SYSCALL
long int syscall(long int __sysno, ...)
{
	va_list syscall_args;
	long int syscall_status = -1;

	sr_shimdebug_msg(1, "syscall %ld\n", __sysno);
	
	if (!syscall_init_done) {
		syscall_init();
	}
	// renameat2 - call renameorlink to do the rename and post a message
	if (__sysno == SYS_renameat2) {
		sr_shimdebug_msg(1, "syscall %ld --> renameat2, will call renameorlink\n", __sysno);
		
		va_start(syscall_args, __sysno);
		int olddirfd = va_arg(syscall_args, int);
		char *oldpath = va_arg(syscall_args, char*);
		int newdirfd = va_arg(syscall_args, int);
		char *newpath = va_arg(syscall_args, char*);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);

		sr_shimdebug_msg(1, "%d, %s, %d, %s, %d", olddirfd, oldpath, newdirfd, newpath, flags);
		syscall_status = renameorlink(olddirfd, oldpath, newdirfd, newpath, flags, 0);
	
	// all other syscalls we don't do anything, but we have to pass them through to the real syscall
	// start of auto-generated code

	#ifdef SYS_accept
	} else if (__sysno == SYS_accept && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> accept, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int unknown_name0 = va_arg(syscall_args, int);
		struct sockaddr * unknown_name1 = va_arg(syscall_args, struct sockaddr *);
		int * unknown_name2 = va_arg(syscall_args, int *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2);
	#endif
	#ifdef SYS_accept4
	} else if (__sysno == SYS_accept4 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> accept4, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int unknown_name0 = va_arg(syscall_args, int);
		struct sockaddr * unknown_name1 = va_arg(syscall_args, struct sockaddr *);
		int * unknown_name2 = va_arg(syscall_args, int *);
		int unknown_name3 = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2, unknown_name3);
	#endif
	#ifdef SYS_access
	} else if (__sysno == SYS_access && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> access, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		int mode = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename, mode);
	#endif
	#ifdef SYS_acct
	} else if (__sysno == SYS_acct && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> acct, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * name = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, name);
	#endif
	#ifdef SYS_add_key
	} else if (__sysno == SYS_add_key && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> add_key, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * _type = va_arg(syscall_args, char *);
		char * _description = va_arg(syscall_args, char *);
		void * _payload = va_arg(syscall_args, void *);
		size_t plen = va_arg(syscall_args, size_t);
		key_serial_t destringid = va_arg(syscall_args, key_serial_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, _type, _description, _payload, plen, destringid);
	#endif
	#ifdef SYS_adjtimex
	} else if (__sysno == SYS_adjtimex && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> adjtimex, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		struct timex * txc_p = va_arg(syscall_args, struct timex *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, txc_p);
	#endif
	#ifdef SYS_alarm
	} else if (__sysno == SYS_alarm && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> alarm, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int seconds = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, seconds);
	#endif
	#ifdef SYS_bdflush
	} else if (__sysno == SYS_bdflush && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> bdflush, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int func = va_arg(syscall_args, int);
		long data = va_arg(syscall_args, long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, func, data);
	#endif
	#ifdef SYS_bind
	} else if (__sysno == SYS_bind && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> bind, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int unknown_name0 = va_arg(syscall_args, int);
		struct sockaddr * unknown_name1 = va_arg(syscall_args, struct sockaddr *);
		int unknown_name2 = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2);
	#endif
	#ifdef SYS_bpf
	} else if (__sysno == SYS_bpf && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> bpf, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int cmd = va_arg(syscall_args, int);
		union bpf_attr * attr = va_arg(syscall_args, union bpf_attr *);
		unsigned int size = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, cmd, attr, size);
	#endif
	#ifdef SYS_brk
	} else if (__sysno == SYS_brk && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> brk, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long brk = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, brk);
	#endif
	#ifdef SYS_capget
	} else if (__sysno == SYS_capget && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> capget, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		cap_user_header_t header = va_arg(syscall_args, cap_user_header_t);
		cap_user_data_t dataptr = va_arg(syscall_args, cap_user_data_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, header, dataptr);
	#endif
	#ifdef SYS_capset
	} else if (__sysno == SYS_capset && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> capset, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		cap_user_header_t header = va_arg(syscall_args, cap_user_header_t);
		cap_user_data_t data = va_arg(syscall_args, cap_user_data_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, header, data);
	#endif
	#ifdef SYS_chdir
	} else if (__sysno == SYS_chdir && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> chdir, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename);
	#endif
	#ifdef SYS_chmod
	} else if (__sysno == SYS_chmod && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> chmod, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		umode_t mode = (umode_t)va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename, mode);
	#endif
	#ifdef SYS_chown
	} else if (__sysno == SYS_chown && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> chown, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		uid_t user = va_arg(syscall_args, uid_t);
		gid_t group = va_arg(syscall_args, gid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename, user, group);
	#endif
	#ifdef SYS_chown16
	} else if (__sysno == SYS_chown16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> chown16, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		old_uid_t user = va_arg(syscall_args, old_uid_t);
		old_gid_t group = va_arg(syscall_args, old_gid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename, user, group);
	#endif
	#ifdef SYS_chroot
	} else if (__sysno == SYS_chroot && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> chroot, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename);
	#endif
	#ifdef SYS_clock_adjtime
	} else if (__sysno == SYS_clock_adjtime && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> clock_adjtime, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		clockid_t which_clock = va_arg(syscall_args, clockid_t);
		struct timex * tx = va_arg(syscall_args, struct timex *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, which_clock, tx);
	#endif
	#ifdef SYS_clock_getres
	} else if (__sysno == SYS_clock_getres && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> clock_getres, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		clockid_t which_clock = va_arg(syscall_args, clockid_t);
		struct __kernel_timespec * tp = va_arg(syscall_args, struct __kernel_timespec *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, which_clock, tp);
	#endif
	#ifdef SYS_clock_gettime
	} else if (__sysno == SYS_clock_gettime && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> clock_gettime, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		clockid_t which_clock = va_arg(syscall_args, clockid_t);
		struct __kernel_timespec * tp = va_arg(syscall_args, struct __kernel_timespec *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, which_clock, tp);
	#endif
	#ifdef SYS_clock_nanosleep
	} else if (__sysno == SYS_clock_nanosleep && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> clock_nanosleep, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		clockid_t which_clock = va_arg(syscall_args, clockid_t);
		int flags = va_arg(syscall_args, int);
		struct __kernel_timespec * rqtp = va_arg(syscall_args, struct __kernel_timespec *);
		struct __kernel_timespec * rmtp = va_arg(syscall_args, struct __kernel_timespec *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, which_clock, flags, rqtp, rmtp);
	#endif
	#ifdef SYS_clock_settime
	} else if (__sysno == SYS_clock_settime && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> clock_settime, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		clockid_t which_clock = va_arg(syscall_args, clockid_t);
		struct __kernel_timespec * tp = va_arg(syscall_args, struct __kernel_timespec *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, which_clock, tp);
	#endif
	#ifdef SYS_clone
	} else if (__sysno == SYS_clone && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> clone, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long unknown_name0 = va_arg(syscall_args, unsigned long);
		unsigned long unknown_name1 = va_arg(syscall_args, unsigned long);
		int * unknown_name2 = va_arg(syscall_args, int *);
		unsigned long unknown_name3 = va_arg(syscall_args, unsigned long);
		int * unknown_name4 = va_arg(syscall_args, int *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2, unknown_name3, unknown_name4);
	#endif
	#ifdef SYS_close
	} else if (__sysno == SYS_close && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> close, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd);
	#endif
	#ifdef SYS_close_range
	} else if (__sysno == SYS_close_range && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> close_range, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		unsigned int max_fd = va_arg(syscall_args, unsigned int);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, max_fd, flags);
	#endif
	#ifdef SYS_connect
	} else if (__sysno == SYS_connect && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> connect, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int unknown_name0 = va_arg(syscall_args, int);
		struct sockaddr * unknown_name1 = va_arg(syscall_args, struct sockaddr *);
		int unknown_name2 = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2);
	#endif
	#ifdef SYS_copy_file_range
	} else if (__sysno == SYS_copy_file_range && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> copy_file_range, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd_in = va_arg(syscall_args, int);
		loff_t * off_in = va_arg(syscall_args, loff_t *);
		int fd_out = va_arg(syscall_args, int);
		loff_t * off_out = va_arg(syscall_args, loff_t *);
		size_t len = va_arg(syscall_args, size_t);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd_in, off_in, fd_out, off_out, len, flags);
	#endif
	#ifdef SYS_creat
	} else if (__sysno == SYS_creat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> creat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * pathname = va_arg(syscall_args, char *);
		umode_t mode = (umode_t)va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pathname, mode);
	#endif
	#ifdef SYS_delete_module
	} else if (__sysno == SYS_delete_module && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> delete_module, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * name_user = va_arg(syscall_args, char *);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, name_user, flags);
	#endif
	#ifdef SYS_dup
	} else if (__sysno == SYS_dup && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> dup, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fildes = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fildes);
	#endif
	#ifdef SYS_dup2
	} else if (__sysno == SYS_dup2 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> dup2, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int oldfd = va_arg(syscall_args, unsigned int);
		unsigned int newfd = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, oldfd, newfd);
	#endif
	#ifdef SYS_dup3
	} else if (__sysno == SYS_dup3 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> dup3, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int oldfd = va_arg(syscall_args, unsigned int);
		unsigned int newfd = va_arg(syscall_args, unsigned int);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, oldfd, newfd, flags);
	#endif
	#ifdef SYS_epoll_create
	} else if (__sysno == SYS_epoll_create && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> epoll_create, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int size = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, size);
	#endif
	#ifdef SYS_epoll_create1
	} else if (__sysno == SYS_epoll_create1 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> epoll_create1, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, flags);
	#endif
	#ifdef SYS_epoll_ctl
	} else if (__sysno == SYS_epoll_ctl && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> epoll_ctl, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int epfd = va_arg(syscall_args, int);
		int op = va_arg(syscall_args, int);
		int fd = va_arg(syscall_args, int);
		struct epoll_event * event = va_arg(syscall_args, struct epoll_event *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, epfd, op, fd, event);
	#endif
	#ifdef SYS_epoll_pwait
	} else if (__sysno == SYS_epoll_pwait && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> epoll_pwait, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int epfd = va_arg(syscall_args, int);
		struct epoll_event * events = va_arg(syscall_args, struct epoll_event *);
		int maxevents = va_arg(syscall_args, int);
		int timeout = va_arg(syscall_args, int);
		sigset_t * sigmask = va_arg(syscall_args, sigset_t *);
		size_t sigsetsize = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, epfd, events, maxevents, timeout, sigmask, sigsetsize);
	#endif
	#ifdef SYS_epoll_wait
	} else if (__sysno == SYS_epoll_wait && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> epoll_wait, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int epfd = va_arg(syscall_args, int);
		struct epoll_event * events = va_arg(syscall_args, struct epoll_event *);
		int maxevents = va_arg(syscall_args, int);
		int timeout = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, epfd, events, maxevents, timeout);
	#endif
	#ifdef SYS_eventfd
	} else if (__sysno == SYS_eventfd && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> eventfd, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int count = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, count);
	#endif
	#ifdef SYS_eventfd2
	} else if (__sysno == SYS_eventfd2 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> eventfd2, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int count = va_arg(syscall_args, unsigned int);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, count, flags);
	#endif
	#ifdef SYS_execve
	} else if (__sysno == SYS_execve && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> execve, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		char ** argv = va_arg(syscall_args, char **);
		char ** envp = va_arg(syscall_args, char **);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename, argv, envp);
	#endif
	#ifdef SYS_execveat
	} else if (__sysno == SYS_execveat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> execveat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char * filename = va_arg(syscall_args, char *);
		char ** argv = va_arg(syscall_args, char **);
		char ** envp = va_arg(syscall_args, char **);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd, filename, argv, envp, flags);
	#endif
	#ifdef SYS_exit
	} else if (__sysno == SYS_exit && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> exit, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int error_code = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, error_code);
	#endif
	#ifdef SYS_exit_group
	} else if (__sysno == SYS_exit_group && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> exit_group, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int error_code = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, error_code);
	#endif
	#ifdef SYS_faccessat
	} else if (__sysno == SYS_faccessat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> faccessat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char * filename = va_arg(syscall_args, char *);
		int mode = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd, filename, mode);
	#endif
	#ifdef SYS_faccessat2
	} else if (__sysno == SYS_faccessat2 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> faccessat2, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char * filename = va_arg(syscall_args, char *);
		int mode = va_arg(syscall_args, int);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd, filename, mode, flags);
	#endif
	#ifdef SYS_fadvise64
	} else if (__sysno == SYS_fadvise64 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fadvise64, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		loff_t offset = va_arg(syscall_args, loff_t);
		size_t len = va_arg(syscall_args, size_t);
		int advice = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, offset, len, advice);
	#endif
	#ifdef SYS_fadvise64_64
	} else if (__sysno == SYS_fadvise64_64 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fadvise64_64, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		loff_t offset = va_arg(syscall_args, loff_t);
		loff_t len = va_arg(syscall_args, loff_t);
		int advice = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, offset, len, advice);
	#endif
	#ifdef SYS_fallocate
	} else if (__sysno == SYS_fallocate && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fallocate, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		int mode = va_arg(syscall_args, int);
		loff_t offset = va_arg(syscall_args, loff_t);
		loff_t len = va_arg(syscall_args, loff_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, mode, offset, len);
	#endif
	#ifdef SYS_fanotify_init
	} else if (__sysno == SYS_fanotify_init && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fanotify_init, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		unsigned int event_f_flags = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, flags, event_f_flags);
	#endif
	#ifdef SYS_fanotify_mark
	} else if (__sysno == SYS_fanotify_mark && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fanotify_mark, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fanotify_fd = va_arg(syscall_args, int);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		u64 mask = va_arg(syscall_args, u64);
		int fd = va_arg(syscall_args, int);
		char * pathname = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fanotify_fd, flags, mask, fd, pathname);
	#endif
	#ifdef SYS_fchdir
	} else if (__sysno == SYS_fchdir && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fchdir, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd);
	#endif
	#ifdef SYS_fchmod
	} else if (__sysno == SYS_fchmod && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fchmod, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		umode_t mode = (umode_t)va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, mode);
	#endif
	#ifdef SYS_fchmodat
	} else if (__sysno == SYS_fchmodat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fchmodat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char *  filename = va_arg(syscall_args, char *);
		umode_t mode = (umode_t)va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd,  filename, mode);
	#endif
	#ifdef SYS_fchown
	} else if (__sysno == SYS_fchown && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fchown, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		uid_t user = va_arg(syscall_args, uid_t);
		gid_t group = va_arg(syscall_args, gid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, user, group);
	#endif
	#ifdef SYS_fchown16
	} else if (__sysno == SYS_fchown16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fchown16, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		old_uid_t user = va_arg(syscall_args, old_uid_t);
		old_gid_t group = va_arg(syscall_args, old_gid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, user, group);
	#endif
	#ifdef SYS_fchownat
	} else if (__sysno == SYS_fchownat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fchownat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char * filename = va_arg(syscall_args, char *);
		uid_t user = va_arg(syscall_args, uid_t);
		gid_t group = va_arg(syscall_args, gid_t);
		int flag = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd, filename, user, group, flag);
	#endif
	#ifdef SYS_fcntl
	} else if (__sysno == SYS_fcntl && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fcntl, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		unsigned int cmd = va_arg(syscall_args, unsigned int);
		unsigned long arg = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, cmd, arg);
	#endif
	#ifdef SYS_fcntl64
	} else if (__sysno == SYS_fcntl64 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fcntl64, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		unsigned int cmd = va_arg(syscall_args, unsigned int);
		unsigned long arg = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, cmd, arg);
	#endif
	#ifdef SYS_fdatasync
	} else if (__sysno == SYS_fdatasync && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fdatasync, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd);
	#endif
	#ifdef SYS_fgetxattr
	} else if (__sysno == SYS_fgetxattr && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fgetxattr, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		char * name = va_arg(syscall_args, char *);
		void * value = va_arg(syscall_args, void *);
		size_t size = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, name, value, size);
	#endif
	#ifdef SYS_finit_module
	} else if (__sysno == SYS_finit_module && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> finit_module, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		char * uargs = va_arg(syscall_args, char *);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, uargs, flags);
	#endif
	#ifdef SYS_flistxattr
	} else if (__sysno == SYS_flistxattr && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> flistxattr, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		char * list = va_arg(syscall_args, char *);
		size_t size = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, list, size);
	#endif
	#ifdef SYS_flock
	} else if (__sysno == SYS_flock && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> flock, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		unsigned int cmd = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, cmd);
	#endif
	#ifdef SYS_fork
	} else if (__sysno == SYS_fork && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fork, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_fremovexattr
	} else if (__sysno == SYS_fremovexattr && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fremovexattr, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		char * name = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, name);
	#endif
	#ifdef SYS_fsconfig
	} else if (__sysno == SYS_fsconfig && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fsconfig, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fs_fd = va_arg(syscall_args, int);
		unsigned int cmd = va_arg(syscall_args, unsigned int);
		char * key = va_arg(syscall_args, char *);
		void * value = va_arg(syscall_args, void *);
		int aux = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fs_fd, cmd, key, value, aux);
	#endif
	#ifdef SYS_fsetxattr
	} else if (__sysno == SYS_fsetxattr && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fsetxattr, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		char * name = va_arg(syscall_args, char *);
		void * value = va_arg(syscall_args, void *);
		size_t size = va_arg(syscall_args, size_t);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, name, value, size, flags);
	#endif
	#ifdef SYS_fsmount
	} else if (__sysno == SYS_fsmount && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fsmount, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fs_fd = va_arg(syscall_args, int);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		unsigned int ms_flags = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fs_fd, flags, ms_flags);
	#endif
	#ifdef SYS_fsopen
	} else if (__sysno == SYS_fsopen && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fsopen, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * fs_name = va_arg(syscall_args, char *);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fs_name, flags);
	#endif
	#ifdef SYS_fspick
	} else if (__sysno == SYS_fspick && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fspick, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char * path = va_arg(syscall_args, char *);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd, path, flags);
	#endif
	#ifdef SYS_fstat
	} else if (__sysno == SYS_fstat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fstat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		struct __old_kernel_stat * statbuf = va_arg(syscall_args, struct __old_kernel_stat *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, statbuf);
	#endif
	#ifdef SYS_fstat64
	} else if (__sysno == SYS_fstat64 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fstat64, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long fd = va_arg(syscall_args, unsigned long);
		struct stat64 * statbuf = va_arg(syscall_args, struct stat64 *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, statbuf);
	#endif
	#ifdef SYS_fstatat64
	} else if (__sysno == SYS_fstatat64 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fstatat64, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char * filename = va_arg(syscall_args, char *);
		struct stat64 * statbuf = va_arg(syscall_args, struct stat64 *);
		int flag = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd, filename, statbuf, flag);
	#endif
	#ifdef SYS_fstatfs
	} else if (__sysno == SYS_fstatfs && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fstatfs, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		struct statfs * buf = va_arg(syscall_args, struct statfs *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, buf);
	#endif
	#ifdef SYS_fstatfs64
	} else if (__sysno == SYS_fstatfs64 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fstatfs64, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		size_t sz = va_arg(syscall_args, size_t);
		struct statfs64 * buf = va_arg(syscall_args, struct statfs64 *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, sz, buf);
	#endif
	#ifdef SYS_fsync
	} else if (__sysno == SYS_fsync && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> fsync, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd);
	#endif
	#ifdef SYS_ftruncate
	} else if (__sysno == SYS_ftruncate && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> ftruncate, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		off_t length = va_arg(syscall_args, off_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, length);
	#endif
	#ifdef SYS_ftruncate64
	} else if (__sysno == SYS_ftruncate64 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> ftruncate64, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		loff_t length = va_arg(syscall_args, loff_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, length);
	#endif
	#ifdef SYS_futex
	} else if (__sysno == SYS_futex && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> futex, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		u32 * uaddr = va_arg(syscall_args, u32 *);
		int op = va_arg(syscall_args, int);
		u32 val = va_arg(syscall_args, u32);
		struct timespec * utime = va_arg(syscall_args, struct timespec *);
		u32 * uaddr2 = va_arg(syscall_args, u32 *);
		u32 val3 = va_arg(syscall_args, u32);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, uaddr, op, val, utime, uaddr2, val3);
	#endif
	#ifdef SYS_futimesat
	} else if (__sysno == SYS_futimesat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> futimesat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char * filename = va_arg(syscall_args, char *);
		struct timeval * utimes = va_arg(syscall_args, struct timeval *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd, filename, utimes);
	#endif
	#ifdef SYS_get_mempolicy
	} else if (__sysno == SYS_get_mempolicy && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> get_mempolicy, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int * policy = va_arg(syscall_args, int *);
		unsigned long * nmask = va_arg(syscall_args, unsigned long *);
		unsigned long maxnode = va_arg(syscall_args, unsigned long);
		unsigned long addr = va_arg(syscall_args, unsigned long);
		unsigned long flags = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, policy, nmask, maxnode, addr, flags);
	#endif
	#ifdef SYS_get_robust_list
	} else if (__sysno == SYS_get_robust_list && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> get_robust_list, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int pid = va_arg(syscall_args, int);
		struct robust_list_head * * head_ptr = va_arg(syscall_args, struct robust_list_head * *);
		size_t * len_ptr = va_arg(syscall_args, size_t *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, head_ptr, len_ptr);
	#endif
	#ifdef SYS_getcpu
	} else if (__sysno == SYS_getcpu && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getcpu, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned * cpu = va_arg(syscall_args, unsigned *);
		unsigned * node = va_arg(syscall_args, unsigned *);
		struct getcpu_cache * cache = va_arg(syscall_args, struct getcpu_cache *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, cpu, node, cache);
	#endif
	#ifdef SYS_getcwd
	} else if (__sysno == SYS_getcwd && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getcwd, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * buf = va_arg(syscall_args, char *);
		unsigned long size = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, buf, size);
	#endif
	#ifdef SYS_getdents
	} else if (__sysno == SYS_getdents && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getdents, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		struct linux_dirent * dirent = va_arg(syscall_args, struct linux_dirent *);
		unsigned int count = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, dirent, count);
	#endif
	#ifdef SYS_getdents64
	} else if (__sysno == SYS_getdents64 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getdents64, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		struct linux_dirent64 * dirent = va_arg(syscall_args, struct linux_dirent64 *);
		unsigned int count = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, dirent, count);
	#endif
	#ifdef SYS_getegid
	} else if (__sysno == SYS_getegid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getegid, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_getegid16
	} else if (__sysno == SYS_getegid16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getegid16, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_geteuid
	} else if (__sysno == SYS_geteuid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> geteuid, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_geteuid16
	} else if (__sysno == SYS_geteuid16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> geteuid16, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_getgid
	} else if (__sysno == SYS_getgid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getgid, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_getgid16
	} else if (__sysno == SYS_getgid16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getgid16, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_getgroups
	} else if (__sysno == SYS_getgroups && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getgroups, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int gidsetsize = va_arg(syscall_args, int);
		gid_t * grouplist = va_arg(syscall_args, gid_t *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, gidsetsize, grouplist);
	#endif
	#ifdef SYS_getgroups16
	} else if (__sysno == SYS_getgroups16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getgroups16, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int gidsetsize = va_arg(syscall_args, int);
		old_gid_t * grouplist = va_arg(syscall_args, old_gid_t *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, gidsetsize, grouplist);
	#endif
	#ifdef SYS_gethostname
	} else if (__sysno == SYS_gethostname && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> gethostname, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * name = va_arg(syscall_args, char *);
		int len = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, name, len);
	#endif
	#ifdef SYS_getitimer
	} else if (__sysno == SYS_getitimer && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getitimer, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int which = va_arg(syscall_args, int);
		struct itimerval * value = va_arg(syscall_args, struct itimerval *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, which, value);
	#endif
	#ifdef SYS_getpeername
	} else if (__sysno == SYS_getpeername && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getpeername, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int unknown_name0 = va_arg(syscall_args, int);
		struct sockaddr * unknown_name1 = va_arg(syscall_args, struct sockaddr *);
		int * unknown_name2 = va_arg(syscall_args, int *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2);
	#endif
	#ifdef SYS_getpgid
	} else if (__sysno == SYS_getpgid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getpgid, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid);
	#endif
	#ifdef SYS_getpgrp
	} else if (__sysno == SYS_getpgrp && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getpgrp, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_getpid
	} else if (__sysno == SYS_getpid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getpid, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_getppid
	} else if (__sysno == SYS_getppid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getppid, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_getpriority
	} else if (__sysno == SYS_getpriority && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getpriority, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int which = va_arg(syscall_args, int);
		int who = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, which, who);
	#endif
	#ifdef SYS_getrandom
	} else if (__sysno == SYS_getrandom && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getrandom, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * buf = va_arg(syscall_args, char *);
		size_t count = va_arg(syscall_args, size_t);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, buf, count, flags);
	#endif
	#ifdef SYS_getresgid
	} else if (__sysno == SYS_getresgid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getresgid, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		gid_t * rgid = va_arg(syscall_args, gid_t *);
		gid_t * egid = va_arg(syscall_args, gid_t *);
		gid_t * sgid = va_arg(syscall_args, gid_t *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, rgid, egid, sgid);
	#endif
	#ifdef SYS_getresgid16
	} else if (__sysno == SYS_getresgid16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getresgid16, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		old_gid_t * rgid = va_arg(syscall_args, old_gid_t *);
		old_gid_t * egid = va_arg(syscall_args, old_gid_t *);
		old_gid_t * sgid = va_arg(syscall_args, old_gid_t *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, rgid, egid, sgid);
	#endif
	#ifdef SYS_getresuid
	} else if (__sysno == SYS_getresuid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getresuid, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		uid_t * ruid = va_arg(syscall_args, uid_t *);
		uid_t * euid = va_arg(syscall_args, uid_t *);
		uid_t * suid = va_arg(syscall_args, uid_t *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, ruid, euid, suid);
	#endif
	#ifdef SYS_getresuid16
	} else if (__sysno == SYS_getresuid16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getresuid16, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		old_uid_t * ruid = va_arg(syscall_args, old_uid_t *);
		old_uid_t * euid = va_arg(syscall_args, old_uid_t *);
		old_uid_t * suid = va_arg(syscall_args, old_uid_t *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, ruid, euid, suid);
	#endif
	#ifdef SYS_getrlimit
	} else if (__sysno == SYS_getrlimit && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getrlimit, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int resource = va_arg(syscall_args, unsigned int);
		struct rlimit * rlim = va_arg(syscall_args, struct rlimit *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, resource, rlim);
	#endif
	#ifdef SYS_getrusage
	} else if (__sysno == SYS_getrusage && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getrusage, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int who = va_arg(syscall_args, int);
		struct rusage * ru = va_arg(syscall_args, struct rusage *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, who, ru);
	#endif
	#ifdef SYS_getsid
	} else if (__sysno == SYS_getsid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getsid, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid);
	#endif
	#ifdef SYS_getsockname
	} else if (__sysno == SYS_getsockname && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getsockname, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int unknown_name0 = va_arg(syscall_args, int);
		struct sockaddr * unknown_name1 = va_arg(syscall_args, struct sockaddr *);
		int * unknown_name2 = va_arg(syscall_args, int *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2);
	#endif
	#ifdef SYS_getsockopt
	} else if (__sysno == SYS_getsockopt && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getsockopt, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		int level = va_arg(syscall_args, int);
		int optname = va_arg(syscall_args, int);
		char * optval = va_arg(syscall_args, char *);
		int * optlen = va_arg(syscall_args, int *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, level, optname, optval, optlen);
	#endif
	#ifdef SYS_gettid
	} else if (__sysno == SYS_gettid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> gettid, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_gettimeofday
	} else if (__sysno == SYS_gettimeofday && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> gettimeofday, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		struct timeval * tv = va_arg(syscall_args, struct timeval *);
		struct timezone * tz = va_arg(syscall_args, struct timezone *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, tv, tz);
	#endif
	#ifdef SYS_getuid
	} else if (__sysno == SYS_getuid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getuid, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_getuid16
	} else if (__sysno == SYS_getuid16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getuid16, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_getxattr
	} else if (__sysno == SYS_getxattr && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> getxattr, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * path = va_arg(syscall_args, char *);
		char * name = va_arg(syscall_args, char *);
		void * value = va_arg(syscall_args, void *);
		size_t size = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, path, name, value, size);
	#endif
	#ifdef SYS_init_module
	} else if (__sysno == SYS_init_module && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> init_module, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		void * umod = va_arg(syscall_args, void *);
		unsigned long len = va_arg(syscall_args, unsigned long);
		char * uargs = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, umod, len, uargs);
	#endif
	#ifdef SYS_inotify_add_watch
	} else if (__sysno == SYS_inotify_add_watch && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> inotify_add_watch, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		char * path = va_arg(syscall_args, char *);
		u32 mask = va_arg(syscall_args, u32);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, path, mask);
	#endif
	#ifdef SYS_inotify_init
	} else if (__sysno == SYS_inotify_init && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> inotify_init, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_inotify_init1
	} else if (__sysno == SYS_inotify_init1 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> inotify_init1, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, flags);
	#endif
	#ifdef SYS_inotify_rm_watch
	} else if (__sysno == SYS_inotify_rm_watch && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> inotify_rm_watch, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		__s32 wd = va_arg(syscall_args, __s32);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, wd);
	#endif
	#ifdef SYS_io_cancel
	} else if (__sysno == SYS_io_cancel && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> io_cancel, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		aio_context_t ctx_id = va_arg(syscall_args, aio_context_t);
		struct iocb * iocb = va_arg(syscall_args, struct iocb *);
		struct io_event * result = va_arg(syscall_args, struct io_event *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, ctx_id, iocb, result);
	#endif
	#ifdef SYS_io_destroy
	} else if (__sysno == SYS_io_destroy && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> io_destroy, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		aio_context_t ctx = va_arg(syscall_args, aio_context_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, ctx);
	#endif
	#ifdef SYS_io_getevents
	} else if (__sysno == SYS_io_getevents && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> io_getevents, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		aio_context_t ctx_id = va_arg(syscall_args, aio_context_t);
		long min_nr = va_arg(syscall_args, long);
		long nr = va_arg(syscall_args, long);
		struct io_event * events = va_arg(syscall_args, struct io_event *);
		struct timespec * timeout = va_arg(syscall_args, struct timespec *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, ctx_id, min_nr, nr, events, timeout);
	#endif
	#ifdef SYS_io_pgetevents
	} else if (__sysno == SYS_io_pgetevents && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> io_pgetevents, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		aio_context_t ctx_id = va_arg(syscall_args, aio_context_t);
		long min_nr = va_arg(syscall_args, long);
		long nr = va_arg(syscall_args, long);
		struct io_event * events = va_arg(syscall_args, struct io_event *);
		struct timespec * timeout = va_arg(syscall_args, struct timespec *);
		struct __aio_sigset * sig = va_arg(syscall_args, struct __aio_sigset *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, ctx_id, min_nr, nr, events, timeout, sig);
	#endif
	#ifdef SYS_io_setup
	} else if (__sysno == SYS_io_setup && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> io_setup, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned nr_reqs = va_arg(syscall_args, unsigned);
		aio_context_t * ctx = va_arg(syscall_args, aio_context_t *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, nr_reqs, ctx);
	#endif
	#ifdef SYS_io_submit
	} else if (__sysno == SYS_io_submit && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> io_submit, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		aio_context_t unknown_name0 = va_arg(syscall_args, aio_context_t);
		long unknown_name1 = va_arg(syscall_args, long);
		struct iocb * * unknown_name2 = va_arg(syscall_args, struct iocb * *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2);
	#endif
	#ifdef SYS_io_uring_enter
	} else if (__sysno == SYS_io_uring_enter && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> io_uring_enter, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		u32 to_submit = va_arg(syscall_args, u32);
		u32 min_complete = va_arg(syscall_args, u32);
		u32 flags = va_arg(syscall_args, u32);
		sigset_t * sig = va_arg(syscall_args, sigset_t *);
		size_t sigsz = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, to_submit, min_complete, flags, sig, sigsz);
	#endif
	#ifdef SYS_io_uring_register
	} else if (__sysno == SYS_io_uring_register && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> io_uring_register, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		unsigned int op = va_arg(syscall_args, unsigned int);
		void * arg = va_arg(syscall_args, void *);
		unsigned int nr_args = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, op, arg, nr_args);
	#endif
	#ifdef SYS_io_uring_setup
	} else if (__sysno == SYS_io_uring_setup && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> io_uring_setup, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		u32 entries = va_arg(syscall_args, u32);
		struct io_uring_params * p = va_arg(syscall_args, struct io_uring_params *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, entries, p);
	#endif
	#ifdef SYS_ioctl
	} else if (__sysno == SYS_ioctl && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> ioctl, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		unsigned int cmd = va_arg(syscall_args, unsigned int);
		unsigned long arg = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, cmd, arg);
	#endif
	#ifdef SYS_ioperm
	} else if (__sysno == SYS_ioperm && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> ioperm, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long from = va_arg(syscall_args, unsigned long);
		unsigned long num = va_arg(syscall_args, unsigned long);
		int on = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, from, num, on);
	#endif
	#ifdef SYS_ioprio_get
	} else if (__sysno == SYS_ioprio_get && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> ioprio_get, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int which = va_arg(syscall_args, int);
		int who = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, which, who);
	#endif
	#ifdef SYS_ioprio_set
	} else if (__sysno == SYS_ioprio_set && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> ioprio_set, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int which = va_arg(syscall_args, int);
		int who = va_arg(syscall_args, int);
		int ioprio = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, which, who, ioprio);
	#endif
	#ifdef SYS_ipc
	} else if (__sysno == SYS_ipc && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> ipc, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int call = va_arg(syscall_args, unsigned int);
		int first = va_arg(syscall_args, int);
		unsigned long second = va_arg(syscall_args, unsigned long);
		unsigned long third = va_arg(syscall_args, unsigned long);
		void * ptr = va_arg(syscall_args, void *);
		long fifth = va_arg(syscall_args, long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, call, first, second, third, ptr, fifth);
	#endif
	#ifdef SYS_kcmp
	} else if (__sysno == SYS_kcmp && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> kcmp, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid1 = va_arg(syscall_args, pid_t);
		pid_t pid2 = va_arg(syscall_args, pid_t);
		int type = va_arg(syscall_args, int);
		unsigned long idx1 = va_arg(syscall_args, unsigned long);
		unsigned long idx2 = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid1, pid2, type, idx1, idx2);
	#endif
	#ifdef SYS_kexec_file_load
	} else if (__sysno == SYS_kexec_file_load && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> kexec_file_load, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int kernel_fd = va_arg(syscall_args, int);
		int initrd_fd = va_arg(syscall_args, int);
		unsigned long cmdline_len = va_arg(syscall_args, unsigned long);
		char * cmdline_ptr = va_arg(syscall_args, char *);
		unsigned long flags = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, kernel_fd, initrd_fd, cmdline_len, cmdline_ptr, flags);
	#endif
	#ifdef SYS_kexec_load
	} else if (__sysno == SYS_kexec_load && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> kexec_load, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long entry = va_arg(syscall_args, unsigned long);
		unsigned long nr_segments = va_arg(syscall_args, unsigned long);
		struct kexec_segment * segments = va_arg(syscall_args, struct kexec_segment *);
		unsigned long flags = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, entry, nr_segments, segments, flags);
	#endif
	#ifdef SYS_keyctl
	} else if (__sysno == SYS_keyctl && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> keyctl, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int cmd = va_arg(syscall_args, int);
		unsigned long arg2 = va_arg(syscall_args, unsigned long);
		unsigned long arg3 = va_arg(syscall_args, unsigned long);
		unsigned long arg4 = va_arg(syscall_args, unsigned long);
		unsigned long arg5 = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, cmd, arg2, arg3, arg4, arg5);
	#endif
	#ifdef SYS_kill
	} else if (__sysno == SYS_kill && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> kill, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		int sig = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, sig);
	#endif
	#ifdef SYS_lchown
	} else if (__sysno == SYS_lchown && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> lchown, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		uid_t user = va_arg(syscall_args, uid_t);
		gid_t group = va_arg(syscall_args, gid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename, user, group);
	#endif
	#ifdef SYS_lchown16
	} else if (__sysno == SYS_lchown16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> lchown16, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		old_uid_t user = va_arg(syscall_args, old_uid_t);
		old_gid_t group = va_arg(syscall_args, old_gid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename, user, group);
	#endif
	#ifdef SYS_lgetxattr
	} else if (__sysno == SYS_lgetxattr && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> lgetxattr, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * path = va_arg(syscall_args, char *);
		char * name = va_arg(syscall_args, char *);
		void * value = va_arg(syscall_args, void *);
		size_t size = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, path, name, value, size);
	#endif
	#ifdef SYS_link
	} else if (__sysno == SYS_link && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> link, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * oldname = va_arg(syscall_args, char *);
		char * newname = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, oldname, newname);
	#endif
	#ifdef SYS_linkat
	} else if (__sysno == SYS_linkat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> linkat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int olddfd = va_arg(syscall_args, int);
		char * oldname = va_arg(syscall_args, char *);
		int newdfd = va_arg(syscall_args, int);
		char * newname = va_arg(syscall_args, char *);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, olddfd, oldname, newdfd, newname, flags);
	#endif
	#ifdef SYS_listen
	} else if (__sysno == SYS_listen && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> listen, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int unknown_name0 = va_arg(syscall_args, int);
		int unknown_name1 = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1);
	#endif
	#ifdef SYS_listxattr
	} else if (__sysno == SYS_listxattr && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> listxattr, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * path = va_arg(syscall_args, char *);
		char * list = va_arg(syscall_args, char *);
		size_t size = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, path, list, size);
	#endif
	#ifdef SYS_llistxattr
	} else if (__sysno == SYS_llistxattr && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> llistxattr, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * path = va_arg(syscall_args, char *);
		char * list = va_arg(syscall_args, char *);
		size_t size = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, path, list, size);
	#endif
	#ifdef SYS_llseek
	} else if (__sysno == SYS_llseek && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> llseek, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		unsigned long offset_high = va_arg(syscall_args, unsigned long);
		unsigned long offset_low = va_arg(syscall_args, unsigned long);
		loff_t * result = va_arg(syscall_args, loff_t *);
		unsigned int whence = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, offset_high, offset_low, result, whence);
	#endif
	#ifdef SYS_lookup_dcookie
	} else if (__sysno == SYS_lookup_dcookie && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> lookup_dcookie, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		u64 cookie64 = va_arg(syscall_args, u64);
		char * buf = va_arg(syscall_args, char *);
		size_t len = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, cookie64, buf, len);
	#endif
	#ifdef SYS_lremovexattr
	} else if (__sysno == SYS_lremovexattr && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> lremovexattr, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * path = va_arg(syscall_args, char *);
		char * name = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, path, name);
	#endif
	#ifdef SYS_lseek
	} else if (__sysno == SYS_lseek && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> lseek, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		off_t offset = va_arg(syscall_args, off_t);
		unsigned int whence = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, offset, whence);
	#endif
	#ifdef SYS_lsetxattr
	} else if (__sysno == SYS_lsetxattr && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> lsetxattr, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * path = va_arg(syscall_args, char *);
		char * name = va_arg(syscall_args, char *);
		void * value = va_arg(syscall_args, void *);
		size_t size = va_arg(syscall_args, size_t);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, path, name, value, size, flags);
	#endif
	#ifdef SYS_lstat
	} else if (__sysno == SYS_lstat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> lstat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		struct __old_kernel_stat * statbuf = va_arg(syscall_args, struct __old_kernel_stat *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename, statbuf);
	#endif
	#ifdef SYS_lstat64
	} else if (__sysno == SYS_lstat64 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> lstat64, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		struct stat64 * statbuf = va_arg(syscall_args, struct stat64 *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename, statbuf);
	#endif
	#ifdef SYS_madvise
	} else if (__sysno == SYS_madvise && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> madvise, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long start = va_arg(syscall_args, unsigned long);
		size_t len = va_arg(syscall_args, size_t);
		int behavior = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, start, len, behavior);
	#endif
	#ifdef SYS_mbind
	} else if (__sysno == SYS_mbind && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mbind, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long start = va_arg(syscall_args, unsigned long);
		unsigned long len = va_arg(syscall_args, unsigned long);
		unsigned long mode = va_arg(syscall_args, unsigned long);
		unsigned long * nmask = va_arg(syscall_args, unsigned long *);
		unsigned long maxnode = va_arg(syscall_args, unsigned long);
		unsigned flags = va_arg(syscall_args, unsigned);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, start, len, mode, nmask, maxnode, flags);
	#endif
	#ifdef SYS_membarrier
	} else if (__sysno == SYS_membarrier && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> membarrier, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int cmd = va_arg(syscall_args, int);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, cmd, flags);
	#endif
	#ifdef SYS_memfd_create
	} else if (__sysno == SYS_memfd_create && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> memfd_create, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * uname_ptr = va_arg(syscall_args, char *);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, uname_ptr, flags);
	#endif
	#ifdef SYS_migrate_pages
	} else if (__sysno == SYS_migrate_pages && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> migrate_pages, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		unsigned long maxnode = va_arg(syscall_args, unsigned long);
		unsigned long * from = va_arg(syscall_args, unsigned long *);
		unsigned long * to = va_arg(syscall_args, unsigned long *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, maxnode, from, to);
	#endif
	#ifdef SYS_mincore
	} else if (__sysno == SYS_mincore && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mincore, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long start = va_arg(syscall_args, unsigned long);
		size_t len = va_arg(syscall_args, size_t);
		unsigned char *  vec = va_arg(syscall_args, unsigned char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, start, len,  vec);
	#endif
	#ifdef SYS_mkdir
	} else if (__sysno == SYS_mkdir && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mkdir, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * pathname = va_arg(syscall_args, char *);
		umode_t mode = (umode_t)va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pathname, mode);
	#endif
	#ifdef SYS_mkdirat
	} else if (__sysno == SYS_mkdirat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mkdirat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char *  pathname = va_arg(syscall_args, char *);
		umode_t mode = (umode_t)va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd,  pathname, mode);
	#endif
	#ifdef SYS_mknod
	} else if (__sysno == SYS_mknod && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mknod, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		umode_t mode = (umode_t)va_arg(syscall_args, unsigned int);
		unsigned dev = va_arg(syscall_args, unsigned);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename, mode, dev);
	#endif
	#ifdef SYS_mknodat
	} else if (__sysno == SYS_mknodat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mknodat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char *  filename = va_arg(syscall_args, char *);
		umode_t mode = (umode_t)va_arg(syscall_args, unsigned int);
		unsigned dev = va_arg(syscall_args, unsigned);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd,  filename, mode, dev);
	#endif
	#ifdef SYS_mlock
	} else if (__sysno == SYS_mlock && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mlock, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long start = va_arg(syscall_args, unsigned long);
		size_t len = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, start, len);
	#endif
	#ifdef SYS_mlock2
	} else if (__sysno == SYS_mlock2 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mlock2, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long start = va_arg(syscall_args, unsigned long);
		size_t len = va_arg(syscall_args, size_t);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, start, len, flags);
	#endif
	#ifdef SYS_mlockall
	} else if (__sysno == SYS_mlockall && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mlockall, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, flags);
	#endif
	#ifdef SYS_mmap_pgoff
	} else if (__sysno == SYS_mmap_pgoff && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mmap_pgoff, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long addr = va_arg(syscall_args, unsigned long);
		unsigned long len = va_arg(syscall_args, unsigned long);
		unsigned long prot = va_arg(syscall_args, unsigned long);
		unsigned long flags = va_arg(syscall_args, unsigned long);
		unsigned long fd = va_arg(syscall_args, unsigned long);
		unsigned long pgoff = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, addr, len, prot, flags, fd, pgoff);
	#endif
	#ifdef SYS_mount
	} else if (__sysno == SYS_mount && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mount, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * dev_name = va_arg(syscall_args, char *);
		char * dir_name = va_arg(syscall_args, char *);
		char * type = va_arg(syscall_args, char *);
		unsigned long flags = va_arg(syscall_args, unsigned long);
		void * data = va_arg(syscall_args, void *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dev_name, dir_name, type, flags, data);
	#endif
	#ifdef SYS_move_mount
	} else if (__sysno == SYS_move_mount && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> move_mount, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int from_dfd = va_arg(syscall_args, int);
		char * from_path = va_arg(syscall_args, char *);
		int to_dfd = va_arg(syscall_args, int);
		char * to_path = va_arg(syscall_args, char *);
		unsigned int ms_flags = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, from_dfd, from_path, to_dfd, to_path, ms_flags);
	#endif
	#ifdef SYS_move_pages
	} else if (__sysno == SYS_move_pages && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> move_pages, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		unsigned long nr_pages = va_arg(syscall_args, unsigned long);
		void * * pages = va_arg(syscall_args, void * *);
		int * nodes = va_arg(syscall_args, int *);
		int * status = va_arg(syscall_args, int *);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, nr_pages, pages, nodes, status, flags);
	#endif
	#ifdef SYS_mprotect
	} else if (__sysno == SYS_mprotect && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mprotect, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long start = va_arg(syscall_args, unsigned long);
		size_t len = va_arg(syscall_args, size_t);
		unsigned long prot = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, start, len, prot);
	#endif
	#ifdef SYS_mq_getsetattr
	} else if (__sysno == SYS_mq_getsetattr && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mq_getsetattr, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		mqd_t mqdes = va_arg(syscall_args, mqd_t);
		struct mq_attr * mqstat = va_arg(syscall_args, struct mq_attr *);
		struct mq_attr * omqstat = va_arg(syscall_args, struct mq_attr *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, mqdes, mqstat, omqstat);
	#endif
	#ifdef SYS_mq_notify
	} else if (__sysno == SYS_mq_notify && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mq_notify, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		mqd_t mqdes = va_arg(syscall_args, mqd_t);
		struct sigevent * notification = va_arg(syscall_args, struct sigevent *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, mqdes, notification);
	#endif
	#ifdef SYS_mq_open
	} else if (__sysno == SYS_mq_open && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mq_open, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * name = va_arg(syscall_args, char *);
		int oflag = va_arg(syscall_args, int);
		umode_t mode = (umode_t)va_arg(syscall_args, unsigned int);
		struct mq_attr * attr = va_arg(syscall_args, struct mq_attr *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, name, oflag, mode, attr);
	#endif
	#ifdef SYS_mq_timedreceive
	} else if (__sysno == SYS_mq_timedreceive && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mq_timedreceive, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		mqd_t mqdes = va_arg(syscall_args, mqd_t);
		char * msg_ptr = va_arg(syscall_args, char *);
		size_t msg_len = va_arg(syscall_args, size_t);
		unsigned int * msg_prio = va_arg(syscall_args, unsigned int *);
		struct __kernel_timespec * abs_timeout = va_arg(syscall_args, struct __kernel_timespec *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
	#endif
	#ifdef SYS_mq_timedsend
	} else if (__sysno == SYS_mq_timedsend && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mq_timedsend, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		mqd_t mqdes = va_arg(syscall_args, mqd_t);
		char * msg_ptr = va_arg(syscall_args, char *);
		size_t msg_len = va_arg(syscall_args, size_t);
		unsigned int msg_prio = va_arg(syscall_args, unsigned int);
		struct __kernel_timespec * abs_timeout = va_arg(syscall_args, struct __kernel_timespec *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
	#endif
	#ifdef SYS_mq_unlink
	} else if (__sysno == SYS_mq_unlink && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mq_unlink, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * name = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, name);
	#endif
	#ifdef SYS_mremap
	} else if (__sysno == SYS_mremap && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> mremap, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long addr = va_arg(syscall_args, unsigned long);
		unsigned long old_len = va_arg(syscall_args, unsigned long);
		unsigned long new_len = va_arg(syscall_args, unsigned long);
		unsigned long flags = va_arg(syscall_args, unsigned long);
		unsigned long new_addr = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, addr, old_len, new_len, flags, new_addr);
	#endif
	#ifdef SYS_msgctl
	} else if (__sysno == SYS_msgctl && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> msgctl, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int msqid = va_arg(syscall_args, int);
		int cmd = va_arg(syscall_args, int);
		struct msqid_ds * buf = va_arg(syscall_args, struct msqid_ds *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, msqid, cmd, buf);
	#endif
	#ifdef SYS_msgget
	} else if (__sysno == SYS_msgget && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> msgget, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		key_t key = va_arg(syscall_args, key_t);
		int msgflg = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, key, msgflg);
	#endif
	#ifdef SYS_msgrcv
	} else if (__sysno == SYS_msgrcv && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> msgrcv, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int msqid = va_arg(syscall_args, int);
		struct msgbuf * msgp = va_arg(syscall_args, struct msgbuf *);
		size_t msgsz = va_arg(syscall_args, size_t);
		long msgtyp = va_arg(syscall_args, long);
		int msgflg = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, msqid, msgp, msgsz, msgtyp, msgflg);
	#endif
	#ifdef SYS_msgsnd
	} else if (__sysno == SYS_msgsnd && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> msgsnd, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int msqid = va_arg(syscall_args, int);
		struct msgbuf * msgp = va_arg(syscall_args, struct msgbuf *);
		size_t msgsz = va_arg(syscall_args, size_t);
		int msgflg = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, msqid, msgp, msgsz, msgflg);
	#endif
	#ifdef SYS_msync
	} else if (__sysno == SYS_msync && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> msync, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long start = va_arg(syscall_args, unsigned long);
		size_t len = va_arg(syscall_args, size_t);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, start, len, flags);
	#endif
	#ifdef SYS_munlock
	} else if (__sysno == SYS_munlock && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> munlock, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long start = va_arg(syscall_args, unsigned long);
		size_t len = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, start, len);
	#endif
	#ifdef SYS_munlockall
	} else if (__sysno == SYS_munlockall && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> munlockall, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_munmap
	} else if (__sysno == SYS_munmap && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> munmap, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long addr = va_arg(syscall_args, unsigned long);
		size_t len = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, addr, len);
	#endif
	#ifdef SYS_name_to_handle_at
	} else if (__sysno == SYS_name_to_handle_at && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> name_to_handle_at, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char * name = va_arg(syscall_args, char *);
		struct file_handle * handle = va_arg(syscall_args, struct file_handle *);
		int * mnt_id = va_arg(syscall_args, int *);
		int flag = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd, name, handle, mnt_id, flag);
	#endif
	#ifdef SYS_nanosleep
	} else if (__sysno == SYS_nanosleep && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> nanosleep, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		struct __kernel_timespec * rqtp = va_arg(syscall_args, struct __kernel_timespec *);
		struct __kernel_timespec * rmtp = va_arg(syscall_args, struct __kernel_timespec *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, rqtp, rmtp);
	#endif
	#ifdef SYS_newfstat
	} else if (__sysno == SYS_newfstat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> newfstat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		struct stat * statbuf = va_arg(syscall_args, struct stat *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, statbuf);
	#endif
	#ifdef SYS_newfstatat
	} else if (__sysno == SYS_newfstatat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> newfstatat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char * filename = va_arg(syscall_args, char *);
		struct stat * statbuf = va_arg(syscall_args, struct stat *);
		int flag = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd, filename, statbuf, flag);
	#endif
	#ifdef SYS_newlstat
	} else if (__sysno == SYS_newlstat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> newlstat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		struct stat * statbuf = va_arg(syscall_args, struct stat *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename, statbuf);
	#endif
	#ifdef SYS_newstat
	} else if (__sysno == SYS_newstat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> newstat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		struct stat * statbuf = va_arg(syscall_args, struct stat *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename, statbuf);
	#endif
	#ifdef SYS_newuname
	} else if (__sysno == SYS_newuname && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> newuname, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		struct new_utsname * name = va_arg(syscall_args, struct new_utsname *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, name);
	#endif
	#ifdef SYS_ni_syscall
	} else if (__sysno == SYS_ni_syscall && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> ni_syscall, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_nice
	} else if (__sysno == SYS_nice && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> nice, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int increment = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, increment);
	#endif
	#ifdef SYS_old_getrlimit
	} else if (__sysno == SYS_old_getrlimit && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> old_getrlimit, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int resource = va_arg(syscall_args, unsigned int);
		struct rlimit * rlim = va_arg(syscall_args, struct rlimit *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, resource, rlim);
	#endif
	#ifdef SYS_old_mmap
	} else if (__sysno == SYS_old_mmap && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> old_mmap, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		struct mmap_arg_struct * arg = va_arg(syscall_args, struct mmap_arg_struct *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, arg);
	#endif
	#ifdef SYS_old_readdir
	} else if (__sysno == SYS_old_readdir && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> old_readdir, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int unknown_name0 = va_arg(syscall_args, unsigned int);
		struct old_linux_dirent * unknown_name1 = va_arg(syscall_args, struct old_linux_dirent *);
		unsigned int unknown_name2 = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2);
	#endif
	#ifdef SYS_old_select
	} else if (__sysno == SYS_old_select && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> old_select, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		struct sel_arg_struct * arg = va_arg(syscall_args, struct sel_arg_struct *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, arg);
	#endif
	#ifdef SYS_oldumount
	} else if (__sysno == SYS_oldumount && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> oldumount, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * name = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, name);
	#endif
	#ifdef SYS_olduname
	} else if (__sysno == SYS_olduname && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> olduname, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		struct oldold_utsname * unknown_name0 = va_arg(syscall_args, struct oldold_utsname *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0);
	#endif
	#ifdef SYS_open
	} else if (__sysno == SYS_open && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> open, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		int flags = va_arg(syscall_args, int);
		umode_t mode = (umode_t)va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename, flags, mode);
	#endif
	#ifdef SYS_open_by_handle_at
	} else if (__sysno == SYS_open_by_handle_at && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> open_by_handle_at, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int mountdirfd = va_arg(syscall_args, int);
		struct file_handle * handle = va_arg(syscall_args, struct file_handle *);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, mountdirfd, handle, flags);
	#endif
	#ifdef SYS_open_tree
	} else if (__sysno == SYS_open_tree && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> open_tree, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char * path = va_arg(syscall_args, char *);
		unsigned flags = va_arg(syscall_args, unsigned);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd, path, flags);
	#endif
	#ifdef SYS_openat
	} else if (__sysno == SYS_openat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> openat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char * filename = va_arg(syscall_args, char *);
		int flags = va_arg(syscall_args, int);
		umode_t mode = (umode_t)va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd, filename, flags, mode);
	#endif
	#ifdef SYS_openat2
	} else if (__sysno == SYS_openat2 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> openat2, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char * filename = va_arg(syscall_args, char *);
		struct open_how * how = va_arg(syscall_args, struct open_how *);
		size_t size = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd, filename, how, size);
	#endif
	#ifdef SYS_pause
	} else if (__sysno == SYS_pause && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> pause, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_pciconfig_iobase
	} else if (__sysno == SYS_pciconfig_iobase && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> pciconfig_iobase, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		long which = va_arg(syscall_args, long);
		unsigned long bus = va_arg(syscall_args, unsigned long);
		unsigned long devfn = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, which, bus, devfn);
	#endif
	#ifdef SYS_pciconfig_read
	} else if (__sysno == SYS_pciconfig_read && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> pciconfig_read, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long bus = va_arg(syscall_args, unsigned long);
		unsigned long dfn = va_arg(syscall_args, unsigned long);
		unsigned long off = va_arg(syscall_args, unsigned long);
		unsigned long len = va_arg(syscall_args, unsigned long);
		void * buf = va_arg(syscall_args, void *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, bus, dfn, off, len, buf);
	#endif
	#ifdef SYS_pciconfig_write
	} else if (__sysno == SYS_pciconfig_write && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> pciconfig_write, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long bus = va_arg(syscall_args, unsigned long);
		unsigned long dfn = va_arg(syscall_args, unsigned long);
		unsigned long off = va_arg(syscall_args, unsigned long);
		unsigned long len = va_arg(syscall_args, unsigned long);
		void * buf = va_arg(syscall_args, void *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, bus, dfn, off, len, buf);
	#endif
	#ifdef SYS_perf_event_open
	} else if (__sysno == SYS_perf_event_open && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> perf_event_open, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		struct perf_event_attr * attr_uptr = va_arg(syscall_args, struct perf_event_attr *);
		pid_t pid = va_arg(syscall_args, pid_t);
		int cpu = va_arg(syscall_args, int);
		int group_fd = va_arg(syscall_args, int);
		unsigned long flags = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, attr_uptr, pid, cpu, group_fd, flags);
	#endif
	#ifdef SYS_personality
	} else if (__sysno == SYS_personality && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> personality, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int personality = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, personality);
	#endif
	#ifdef SYS_pidfd_send_signal
	} else if (__sysno == SYS_pidfd_send_signal && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> pidfd_send_signal, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int pidfd = va_arg(syscall_args, int);
		int sig = va_arg(syscall_args, int);
		siginfo_t * info = va_arg(syscall_args, siginfo_t *);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pidfd, sig, info, flags);
	#endif
	#ifdef SYS_pipe
	} else if (__sysno == SYS_pipe && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> pipe, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int * fildes = va_arg(syscall_args, int *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fildes);
	#endif
	#ifdef SYS_pipe2
	} else if (__sysno == SYS_pipe2 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> pipe2, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int * fildes = va_arg(syscall_args, int *);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fildes, flags);
	#endif
	#ifdef SYS_pivot_root
	} else if (__sysno == SYS_pivot_root && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> pivot_root, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * new_root = va_arg(syscall_args, char *);
		char * put_old = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, new_root, put_old);
	#endif
	#ifdef SYS_pkey_alloc
	} else if (__sysno == SYS_pkey_alloc && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> pkey_alloc, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long flags = va_arg(syscall_args, unsigned long);
		unsigned long init_val = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, flags, init_val);
	#endif
	#ifdef SYS_pkey_free
	} else if (__sysno == SYS_pkey_free && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> pkey_free, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int pkey = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pkey);
	#endif
	#ifdef SYS_pkey_mprotect
	} else if (__sysno == SYS_pkey_mprotect && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> pkey_mprotect, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long start = va_arg(syscall_args, unsigned long);
		size_t len = va_arg(syscall_args, size_t);
		unsigned long prot = va_arg(syscall_args, unsigned long);
		int pkey = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, start, len, prot, pkey);
	#endif
	#ifdef SYS_poll
	} else if (__sysno == SYS_poll && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> poll, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		struct pollfd * ufds = va_arg(syscall_args, struct pollfd *);
		unsigned int nfds = va_arg(syscall_args, unsigned int);
		int timeout = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, ufds, nfds, timeout);
	#endif
	#ifdef SYS_ppoll
	} else if (__sysno == SYS_ppoll && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> ppoll, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		struct pollfd * unknown_name0 = va_arg(syscall_args, struct pollfd *);
		unsigned int unknown_name1 = va_arg(syscall_args, unsigned int);
		struct timespec * unknown_name2 = va_arg(syscall_args, struct timespec *);
		sigset_t * unknown_name3 = va_arg(syscall_args, sigset_t *);
		size_t unknown_name4 = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2, unknown_name3, unknown_name4);
	#endif
	#ifdef SYS_prctl
	} else if (__sysno == SYS_prctl && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> prctl, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int option = va_arg(syscall_args, int);
		unsigned long arg2 = va_arg(syscall_args, unsigned long);
		unsigned long arg3 = va_arg(syscall_args, unsigned long);
		unsigned long arg4 = va_arg(syscall_args, unsigned long);
		unsigned long arg5 = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, option, arg2, arg3, arg4, arg5);
	#endif
	#ifdef SYS_pread64
	} else if (__sysno == SYS_pread64 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> pread64, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		char * buf = va_arg(syscall_args, char *);
		size_t count = va_arg(syscall_args, size_t);
		loff_t pos = va_arg(syscall_args, loff_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, buf, count, pos);
	#endif
	#ifdef SYS_preadv
	} else if (__sysno == SYS_preadv && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> preadv, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long fd = va_arg(syscall_args, unsigned long);
		struct iovec * vec = va_arg(syscall_args, struct iovec *);
		unsigned long vlen = va_arg(syscall_args, unsigned long);
		unsigned long pos_l = va_arg(syscall_args, unsigned long);
		unsigned long pos_h = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, vec, vlen, pos_l, pos_h);
	#endif
	#ifdef SYS_preadv2
	} else if (__sysno == SYS_preadv2 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> preadv2, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long fd = va_arg(syscall_args, unsigned long);
		struct iovec * vec = va_arg(syscall_args, struct iovec *);
		unsigned long vlen = va_arg(syscall_args, unsigned long);
		unsigned long pos_l = va_arg(syscall_args, unsigned long);
		unsigned long pos_h = va_arg(syscall_args, unsigned long);
		rwf_t flags = va_arg(syscall_args, rwf_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, vec, vlen, pos_l, pos_h, flags);
	#endif
	#ifdef SYS_prlimit64
	} else if (__sysno == SYS_prlimit64 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> prlimit64, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		unsigned int resource = va_arg(syscall_args, unsigned int);
		struct rlimit64 * new_rlim = va_arg(syscall_args, struct rlimit64 *);
		struct rlimit64 * old_rlim = va_arg(syscall_args, struct rlimit64 *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, resource, new_rlim, old_rlim);
	#endif
	#ifdef SYS_process_vm_readv
	} else if (__sysno == SYS_process_vm_readv && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> process_vm_readv, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		struct iovec * lvec = va_arg(syscall_args, struct iovec *);
		unsigned long liovcnt = va_arg(syscall_args, unsigned long);
		struct iovec * rvec = va_arg(syscall_args, struct iovec *);
		unsigned long riovcnt = va_arg(syscall_args, unsigned long);
		unsigned long flags = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, lvec, liovcnt, rvec, riovcnt, flags);
	#endif
	#ifdef SYS_process_vm_writev
	} else if (__sysno == SYS_process_vm_writev && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> process_vm_writev, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		struct iovec * lvec = va_arg(syscall_args, struct iovec *);
		unsigned long liovcnt = va_arg(syscall_args, unsigned long);
		struct iovec * rvec = va_arg(syscall_args, struct iovec *);
		unsigned long riovcnt = va_arg(syscall_args, unsigned long);
		unsigned long flags = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, lvec, liovcnt, rvec, riovcnt, flags);
	#endif
	#ifdef SYS_pselect6
	} else if (__sysno == SYS_pselect6 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> pselect6, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int unknown_name0 = va_arg(syscall_args, int);
		fd_set * unknown_name1 = va_arg(syscall_args, fd_set *);
		fd_set * unknown_name2 = va_arg(syscall_args, fd_set *);
		fd_set * unknown_name3 = va_arg(syscall_args, fd_set *);
		struct timespec * unknown_name4 = va_arg(syscall_args, struct timespec *);
		void * unknown_name5 = va_arg(syscall_args, void *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2, unknown_name3, unknown_name4, unknown_name5);
	#endif
	#ifdef SYS_ptrace
	} else if (__sysno == SYS_ptrace && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> ptrace, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		long request = va_arg(syscall_args, long);
		long pid = va_arg(syscall_args, long);
		unsigned long addr = va_arg(syscall_args, unsigned long);
		unsigned long data = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, request, pid, addr, data);
	#endif
	#ifdef SYS_pwrite64
	} else if (__sysno == SYS_pwrite64 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> pwrite64, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		char * buf = va_arg(syscall_args, char *);
		size_t count = va_arg(syscall_args, size_t);
		loff_t pos = va_arg(syscall_args, loff_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, buf, count, pos);
	#endif
	#ifdef SYS_pwritev
	} else if (__sysno == SYS_pwritev && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> pwritev, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long fd = va_arg(syscall_args, unsigned long);
		struct iovec * vec = va_arg(syscall_args, struct iovec *);
		unsigned long vlen = va_arg(syscall_args, unsigned long);
		unsigned long pos_l = va_arg(syscall_args, unsigned long);
		unsigned long pos_h = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, vec, vlen, pos_l, pos_h);
	#endif
	#ifdef SYS_pwritev2
	} else if (__sysno == SYS_pwritev2 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> pwritev2, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long fd = va_arg(syscall_args, unsigned long);
		struct iovec * vec = va_arg(syscall_args, struct iovec *);
		unsigned long vlen = va_arg(syscall_args, unsigned long);
		unsigned long pos_l = va_arg(syscall_args, unsigned long);
		unsigned long pos_h = va_arg(syscall_args, unsigned long);
		rwf_t flags = va_arg(syscall_args, rwf_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, vec, vlen, pos_l, pos_h, flags);
	#endif
	#ifdef SYS_quotactl
	} else if (__sysno == SYS_quotactl && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> quotactl, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int cmd = va_arg(syscall_args, unsigned int);
		char * special = va_arg(syscall_args, char *);
		qid_t id = va_arg(syscall_args, qid_t);
		void * addr = va_arg(syscall_args, void *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, cmd, special, id, addr);
	#endif
	#ifdef SYS_read
	} else if (__sysno == SYS_read && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> read, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		char * buf = va_arg(syscall_args, char *);
		size_t count = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, buf, count);
	#endif
	#ifdef SYS_readahead
	} else if (__sysno == SYS_readahead && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> readahead, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		loff_t offset = va_arg(syscall_args, loff_t);
		size_t count = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, offset, count);
	#endif
	#ifdef SYS_readlink
	} else if (__sysno == SYS_readlink && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> readlink, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * path = va_arg(syscall_args, char *);
		char * buf = va_arg(syscall_args, char *);
		int bufsiz = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, path, buf, bufsiz);
	#endif
	#ifdef SYS_readlinkat
	} else if (__sysno == SYS_readlinkat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> readlinkat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char * path = va_arg(syscall_args, char *);
		char * buf = va_arg(syscall_args, char *);
		int bufsiz = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd, path, buf, bufsiz);
	#endif
	#ifdef SYS_readv
	} else if (__sysno == SYS_readv && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> readv, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long fd = va_arg(syscall_args, unsigned long);
		struct iovec * vec = va_arg(syscall_args, struct iovec *);
		unsigned long vlen = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, vec, vlen);
	#endif
	#ifdef SYS_reboot
	} else if (__sysno == SYS_reboot && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> reboot, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int magic1 = va_arg(syscall_args, int);
		int magic2 = va_arg(syscall_args, int);
		unsigned int cmd = va_arg(syscall_args, unsigned int);
		void * arg = va_arg(syscall_args, void *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, magic1, magic2, cmd, arg);
	#endif
	#ifdef SYS_recv
	} else if (__sysno == SYS_recv && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> recv, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int unknown_name0 = va_arg(syscall_args, int);
		void * unknown_name1 = va_arg(syscall_args, void *);
		size_t unknown_name2 = va_arg(syscall_args, size_t);
		unsigned unknown_name3 = va_arg(syscall_args, unsigned);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2, unknown_name3);
	#endif
	#ifdef SYS_recvfrom
	} else if (__sysno == SYS_recvfrom && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> recvfrom, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int unknown_name0 = va_arg(syscall_args, int);
		void * unknown_name1 = va_arg(syscall_args, void *);
		size_t unknown_name2 = va_arg(syscall_args, size_t);
		unsigned unknown_name3 = va_arg(syscall_args, unsigned);
		struct sockaddr * unknown_name4 = va_arg(syscall_args, struct sockaddr *);
		int * unknown_name5 = va_arg(syscall_args, int *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2, unknown_name3, unknown_name4, unknown_name5);
	#endif
	#ifdef SYS_recvmmsg
	} else if (__sysno == SYS_recvmmsg && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> recvmmsg, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		struct mmsghdr * msg = va_arg(syscall_args, struct mmsghdr *);
		unsigned int vlen = va_arg(syscall_args, unsigned int);
		unsigned flags = va_arg(syscall_args, unsigned);
		struct timespec * timeout = va_arg(syscall_args, struct timespec *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, msg, vlen, flags, timeout);
	#endif
	#ifdef SYS_recvmsg
	} else if (__sysno == SYS_recvmsg && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> recvmsg, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		struct user_msghdr * msg = va_arg(syscall_args, struct user_msghdr *);
		unsigned flags = va_arg(syscall_args, unsigned);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, msg, flags);
	#endif
	#ifdef SYS_remap_file_pages
	} else if (__sysno == SYS_remap_file_pages && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> remap_file_pages, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long start = va_arg(syscall_args, unsigned long);
		unsigned long size = va_arg(syscall_args, unsigned long);
		unsigned long prot = va_arg(syscall_args, unsigned long);
		unsigned long pgoff = va_arg(syscall_args, unsigned long);
		unsigned long flags = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, start, size, prot, pgoff, flags);
	#endif
	#ifdef SYS_removexattr
	} else if (__sysno == SYS_removexattr && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> removexattr, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * path = va_arg(syscall_args, char *);
		char * name = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, path, name);
	#endif
	#ifdef SYS_rename
	} else if (__sysno == SYS_rename && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> rename, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * oldname = va_arg(syscall_args, char *);
		char * newname = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, oldname, newname);
	#endif
	#ifdef SYS_renameat
	} else if (__sysno == SYS_renameat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> renameat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int olddfd = va_arg(syscall_args, int);
		char *  oldname = va_arg(syscall_args, char *);
		int newdfd = va_arg(syscall_args, int);
		char *  newname = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, olddfd,  oldname, newdfd,  newname);
	#endif
	#ifdef SYS_request_key
	} else if (__sysno == SYS_request_key && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> request_key, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * _type = va_arg(syscall_args, char *);
		char * _description = va_arg(syscall_args, char *);
		char * _callout_info = va_arg(syscall_args, char *);
		key_serial_t destringid = va_arg(syscall_args, key_serial_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, _type, _description, _callout_info, destringid);
	#endif
	#ifdef SYS_restart_syscall
	} else if (__sysno == SYS_restart_syscall && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> restart_syscall, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_rmdir
	} else if (__sysno == SYS_rmdir && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> rmdir, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * pathname = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pathname);
	#endif
	#ifdef SYS_rseq
	} else if (__sysno == SYS_rseq && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> rseq, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		struct rseq * rseq = va_arg(syscall_args, struct rseq *);
		uint32_t rseq_len = va_arg(syscall_args, uint32_t);
		int flags = va_arg(syscall_args, int);
		uint32_t sig = va_arg(syscall_args, uint32_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, rseq, rseq_len, flags, sig);
	#endif
	#ifdef SYS_rt_sigaction
	} else if (__sysno == SYS_rt_sigaction && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> rt_sigaction, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int unknown_name0 = va_arg(syscall_args, int);
		struct sigaction * unknown_name1 = va_arg(syscall_args, struct sigaction *);
		struct sigaction * unknown_name2 = va_arg(syscall_args, struct sigaction *);
		size_t unknown_name3 = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2, unknown_name3);
	#endif
	#ifdef SYS_rt_sigpending
	} else if (__sysno == SYS_rt_sigpending && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> rt_sigpending, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		sigset_t * set = va_arg(syscall_args, sigset_t *);
		size_t sigsetsize = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, set, sigsetsize);
	#endif
	#ifdef SYS_rt_sigprocmask
	} else if (__sysno == SYS_rt_sigprocmask && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> rt_sigprocmask, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int how = va_arg(syscall_args, int);
		sigset_t * set = va_arg(syscall_args, sigset_t *);
		sigset_t * oset = va_arg(syscall_args, sigset_t *);
		size_t sigsetsize = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, how, set, oset, sigsetsize);
	#endif
	#ifdef SYS_rt_sigqueueinfo
	} else if (__sysno == SYS_rt_sigqueueinfo && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> rt_sigqueueinfo, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		int sig = va_arg(syscall_args, int);
		siginfo_t * uinfo = va_arg(syscall_args, siginfo_t *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, sig, uinfo);
	#endif
	#ifdef SYS_rt_sigsuspend
	} else if (__sysno == SYS_rt_sigsuspend && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> rt_sigsuspend, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		sigset_t * unewset = va_arg(syscall_args, sigset_t *);
		size_t sigsetsize = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unewset, sigsetsize);
	#endif
	#ifdef SYS_rt_sigtimedwait
	} else if (__sysno == SYS_rt_sigtimedwait && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> rt_sigtimedwait, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		sigset_t * uthese = va_arg(syscall_args, sigset_t *);
		siginfo_t * uinfo = va_arg(syscall_args, siginfo_t *);
		struct timespec * uts = va_arg(syscall_args, struct timespec *);
		size_t sigsetsize = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, uthese, uinfo, uts, sigsetsize);
	#endif
	#ifdef SYS_rt_tgsigqueueinfo
	} else if (__sysno == SYS_rt_tgsigqueueinfo && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> rt_tgsigqueueinfo, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t tgid = va_arg(syscall_args, pid_t);
		pid_t pid = va_arg(syscall_args, pid_t);
		int sig = va_arg(syscall_args, int);
		siginfo_t * uinfo = va_arg(syscall_args, siginfo_t *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, tgid, pid, sig, uinfo);
	#endif
	#ifdef SYS_sched_get_priority_max
	} else if (__sysno == SYS_sched_get_priority_max && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sched_get_priority_max, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int policy = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, policy);
	#endif
	#ifdef SYS_sched_get_priority_min
	} else if (__sysno == SYS_sched_get_priority_min && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sched_get_priority_min, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int policy = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, policy);
	#endif
	#ifdef SYS_sched_getaffinity
	} else if (__sysno == SYS_sched_getaffinity && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sched_getaffinity, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		unsigned int len = va_arg(syscall_args, unsigned int);
		unsigned long * user_mask_ptr = va_arg(syscall_args, unsigned long *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, len, user_mask_ptr);
	#endif
	#ifdef SYS_sched_getattr
	} else if (__sysno == SYS_sched_getattr && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sched_getattr, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		struct sched_attr * attr = va_arg(syscall_args, struct sched_attr *);
		unsigned int size = va_arg(syscall_args, unsigned int);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, attr, size, flags);
	#endif
	#ifdef SYS_sched_getparam
	} else if (__sysno == SYS_sched_getparam && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sched_getparam, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		struct sched_param * param = va_arg(syscall_args, struct sched_param *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, param);
	#endif
	#ifdef SYS_sched_getscheduler
	} else if (__sysno == SYS_sched_getscheduler && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sched_getscheduler, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid);
	#endif
	#ifdef SYS_sched_rr_get_interval
	} else if (__sysno == SYS_sched_rr_get_interval && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sched_rr_get_interval, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		struct timespec * interval = va_arg(syscall_args, struct timespec *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, interval);
	#endif
	#ifdef SYS_sched_setaffinity
	} else if (__sysno == SYS_sched_setaffinity && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sched_setaffinity, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		unsigned int len = va_arg(syscall_args, unsigned int);
		unsigned long * user_mask_ptr = va_arg(syscall_args, unsigned long *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, len, user_mask_ptr);
	#endif
	#ifdef SYS_sched_setattr
	} else if (__sysno == SYS_sched_setattr && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sched_setattr, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		struct sched_attr * attr = va_arg(syscall_args, struct sched_attr *);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, attr, flags);
	#endif
	#ifdef SYS_sched_setparam
	} else if (__sysno == SYS_sched_setparam && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sched_setparam, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		struct sched_param * param = va_arg(syscall_args, struct sched_param *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, param);
	#endif
	#ifdef SYS_sched_setscheduler
	} else if (__sysno == SYS_sched_setscheduler && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sched_setscheduler, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		int policy = va_arg(syscall_args, int);
		struct sched_param * param = va_arg(syscall_args, struct sched_param *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, policy, param);
	#endif
	#ifdef SYS_sched_yield
	} else if (__sysno == SYS_sched_yield && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sched_yield, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_seccomp
	} else if (__sysno == SYS_seccomp && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> seccomp, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int op = va_arg(syscall_args, unsigned int);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		char * uargs = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, op, flags, uargs);
	#endif
	#ifdef SYS_select
	} else if (__sysno == SYS_select && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> select, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int n = va_arg(syscall_args, int);
		fd_set * inp = va_arg(syscall_args, fd_set *);
		fd_set * outp = va_arg(syscall_args, fd_set *);
		fd_set * exp = va_arg(syscall_args, fd_set *);
		struct timeval * tvp = va_arg(syscall_args, struct timeval *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, n, inp, outp, exp, tvp);
	#endif
	#ifdef SYS_semctl
	} else if (__sysno == SYS_semctl && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> semctl, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int semid = va_arg(syscall_args, int);
		int semnum = va_arg(syscall_args, int);
		int cmd = va_arg(syscall_args, int);
		unsigned long arg = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, semid, semnum, cmd, arg);
	#endif
	#ifdef SYS_semget
	} else if (__sysno == SYS_semget && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> semget, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		key_t key = va_arg(syscall_args, key_t);
		int nsems = va_arg(syscall_args, int);
		int semflg = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, key, nsems, semflg);
	#endif
	#ifdef SYS_semop
	} else if (__sysno == SYS_semop && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> semop, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int semid = va_arg(syscall_args, int);
		struct sembuf * sops = va_arg(syscall_args, struct sembuf *);
		unsigned nsops = va_arg(syscall_args, unsigned);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, semid, sops, nsops);
	#endif
	#ifdef SYS_semtimedop
	} else if (__sysno == SYS_semtimedop && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> semtimedop, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int semid = va_arg(syscall_args, int);
		struct sembuf * sops = va_arg(syscall_args, struct sembuf *);
		unsigned nsops = va_arg(syscall_args, unsigned);
		struct __kernel_timespec * timeout = va_arg(syscall_args, struct __kernel_timespec *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, semid, sops, nsops, timeout);
	#endif
	#ifdef SYS_send
	} else if (__sysno == SYS_send && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> send, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int unknown_name0 = va_arg(syscall_args, int);
		void * unknown_name1 = va_arg(syscall_args, void *);
		size_t unknown_name2 = va_arg(syscall_args, size_t);
		unsigned unknown_name3 = va_arg(syscall_args, unsigned);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2, unknown_name3);
	#endif
	#ifdef SYS_sendfile
	} else if (__sysno == SYS_sendfile && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sendfile, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int out_fd = va_arg(syscall_args, int);
		int in_fd = va_arg(syscall_args, int);
		off_t * offset = va_arg(syscall_args, off_t *);
		size_t count = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, out_fd, in_fd, offset, count);
	#endif
	#ifdef SYS_sendfile64
	} else if (__sysno == SYS_sendfile64 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sendfile64, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int out_fd = va_arg(syscall_args, int);
		int in_fd = va_arg(syscall_args, int);
		loff_t * offset = va_arg(syscall_args, loff_t *);
		size_t count = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, out_fd, in_fd, offset, count);
	#endif
	#ifdef SYS_sendmmsg
	} else if (__sysno == SYS_sendmmsg && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sendmmsg, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		struct mmsghdr * msg = va_arg(syscall_args, struct mmsghdr *);
		unsigned int vlen = va_arg(syscall_args, unsigned int);
		unsigned flags = va_arg(syscall_args, unsigned);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, msg, vlen, flags);
	#endif
	#ifdef SYS_sendmsg
	} else if (__sysno == SYS_sendmsg && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sendmsg, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		struct user_msghdr * msg = va_arg(syscall_args, struct user_msghdr *);
		unsigned flags = va_arg(syscall_args, unsigned);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, msg, flags);
	#endif
	#ifdef SYS_sendto
	} else if (__sysno == SYS_sendto && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sendto, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int unknown_name0 = va_arg(syscall_args, int);
		void * unknown_name1 = va_arg(syscall_args, void *);
		size_t unknown_name2 = va_arg(syscall_args, size_t);
		unsigned unknown_name3 = va_arg(syscall_args, unsigned);
		struct sockaddr * unknown_name4 = va_arg(syscall_args, struct sockaddr *);
		int unknown_name5 = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2, unknown_name3, unknown_name4, unknown_name5);
	#endif
	#ifdef SYS_set_mempolicy
	} else if (__sysno == SYS_set_mempolicy && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> set_mempolicy, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int mode = va_arg(syscall_args, int);
		unsigned long * nmask = va_arg(syscall_args, unsigned long *);
		unsigned long maxnode = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, mode, nmask, maxnode);
	#endif
	#ifdef SYS_set_robust_list
	} else if (__sysno == SYS_set_robust_list && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> set_robust_list, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		struct robust_list_head * head = va_arg(syscall_args, struct robust_list_head *);
		size_t len = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, head, len);
	#endif
	#ifdef SYS_set_tid_address
	} else if (__sysno == SYS_set_tid_address && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> set_tid_address, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int * tidptr = va_arg(syscall_args, int *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, tidptr);
	#endif
	#ifdef SYS_setdomainname
	} else if (__sysno == SYS_setdomainname && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setdomainname, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * name = va_arg(syscall_args, char *);
		int len = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, name, len);
	#endif
	#ifdef SYS_setfsgid
	} else if (__sysno == SYS_setfsgid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setfsgid, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		gid_t gid = va_arg(syscall_args, gid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, gid);
	#endif
	#ifdef SYS_setfsgid16
	} else if (__sysno == SYS_setfsgid16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setfsgid16, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		old_gid_t gid = va_arg(syscall_args, old_gid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, gid);
	#endif
	#ifdef SYS_setfsuid
	} else if (__sysno == SYS_setfsuid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setfsuid, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		uid_t uid = va_arg(syscall_args, uid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, uid);
	#endif
	#ifdef SYS_setfsuid16
	} else if (__sysno == SYS_setfsuid16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setfsuid16, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		old_uid_t uid = va_arg(syscall_args, old_uid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, uid);
	#endif
	#ifdef SYS_setgid
	} else if (__sysno == SYS_setgid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setgid, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		gid_t gid = va_arg(syscall_args, gid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, gid);
	#endif
	#ifdef SYS_setgid16
	} else if (__sysno == SYS_setgid16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setgid16, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		old_gid_t gid = va_arg(syscall_args, old_gid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, gid);
	#endif
	#ifdef SYS_setgroups
	} else if (__sysno == SYS_setgroups && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setgroups, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int gidsetsize = va_arg(syscall_args, int);
		gid_t * grouplist = va_arg(syscall_args, gid_t *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, gidsetsize, grouplist);
	#endif
	#ifdef SYS_setgroups16
	} else if (__sysno == SYS_setgroups16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setgroups16, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int gidsetsize = va_arg(syscall_args, int);
		old_gid_t * grouplist = va_arg(syscall_args, old_gid_t *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, gidsetsize, grouplist);
	#endif
	#ifdef SYS_sethostname
	} else if (__sysno == SYS_sethostname && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sethostname, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * name = va_arg(syscall_args, char *);
		int len = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, name, len);
	#endif
	#ifdef SYS_setitimer
	} else if (__sysno == SYS_setitimer && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setitimer, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int which = va_arg(syscall_args, int);
		struct itimerval * value = va_arg(syscall_args, struct itimerval *);
		struct itimerval * ovalue = va_arg(syscall_args, struct itimerval *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, which, value, ovalue);
	#endif
	#ifdef SYS_setns
	} else if (__sysno == SYS_setns && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setns, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		int nstype = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, nstype);
	#endif
	#ifdef SYS_setpgid
	} else if (__sysno == SYS_setpgid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setpgid, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		pid_t pgid = va_arg(syscall_args, pid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, pgid);
	#endif
	#ifdef SYS_setpriority
	} else if (__sysno == SYS_setpriority && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setpriority, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int which = va_arg(syscall_args, int);
		int who = va_arg(syscall_args, int);
		int niceval = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, which, who, niceval);
	#endif
	#ifdef SYS_setregid
	} else if (__sysno == SYS_setregid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setregid, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		gid_t rgid = va_arg(syscall_args, gid_t);
		gid_t egid = va_arg(syscall_args, gid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, rgid, egid);
	#endif
	#ifdef SYS_setregid16
	} else if (__sysno == SYS_setregid16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setregid16, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		old_gid_t rgid = va_arg(syscall_args, old_gid_t);
		old_gid_t egid = va_arg(syscall_args, old_gid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, rgid, egid);
	#endif
	#ifdef SYS_setresgid
	} else if (__sysno == SYS_setresgid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setresgid, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		gid_t rgid = va_arg(syscall_args, gid_t);
		gid_t egid = va_arg(syscall_args, gid_t);
		gid_t sgid = va_arg(syscall_args, gid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, rgid, egid, sgid);
	#endif
	#ifdef SYS_setresgid16
	} else if (__sysno == SYS_setresgid16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setresgid16, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		old_gid_t rgid = va_arg(syscall_args, old_gid_t);
		old_gid_t egid = va_arg(syscall_args, old_gid_t);
		old_gid_t sgid = va_arg(syscall_args, old_gid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, rgid, egid, sgid);
	#endif
	#ifdef SYS_setresuid
	} else if (__sysno == SYS_setresuid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setresuid, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		uid_t ruid = va_arg(syscall_args, uid_t);
		uid_t euid = va_arg(syscall_args, uid_t);
		uid_t suid = va_arg(syscall_args, uid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, ruid, euid, suid);
	#endif
	#ifdef SYS_setresuid16
	} else if (__sysno == SYS_setresuid16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setresuid16, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		old_uid_t ruid = va_arg(syscall_args, old_uid_t);
		old_uid_t euid = va_arg(syscall_args, old_uid_t);
		old_uid_t suid = va_arg(syscall_args, old_uid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, ruid, euid, suid);
	#endif
	#ifdef SYS_setreuid
	} else if (__sysno == SYS_setreuid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setreuid, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		uid_t ruid = va_arg(syscall_args, uid_t);
		uid_t euid = va_arg(syscall_args, uid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, ruid, euid);
	#endif
	#ifdef SYS_setreuid16
	} else if (__sysno == SYS_setreuid16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setreuid16, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		old_uid_t ruid = va_arg(syscall_args, old_uid_t);
		old_uid_t euid = va_arg(syscall_args, old_uid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, ruid, euid);
	#endif
	#ifdef SYS_setrlimit
	} else if (__sysno == SYS_setrlimit && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setrlimit, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int resource = va_arg(syscall_args, unsigned int);
		struct rlimit * rlim = va_arg(syscall_args, struct rlimit *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, resource, rlim);
	#endif
	#ifdef SYS_setsid
	} else if (__sysno == SYS_setsid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setsid, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_setsockopt
	} else if (__sysno == SYS_setsockopt && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setsockopt, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		int level = va_arg(syscall_args, int);
		int optname = va_arg(syscall_args, int);
		char * optval = va_arg(syscall_args, char *);
		int optlen = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, level, optname, optval, optlen);
	#endif
	#ifdef SYS_settimeofday
	} else if (__sysno == SYS_settimeofday && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> settimeofday, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		struct timeval * tv = va_arg(syscall_args, struct timeval *);
		struct timezone * tz = va_arg(syscall_args, struct timezone *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, tv, tz);
	#endif
	#ifdef SYS_setuid
	} else if (__sysno == SYS_setuid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setuid, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		uid_t uid = va_arg(syscall_args, uid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, uid);
	#endif
	#ifdef SYS_setuid16
	} else if (__sysno == SYS_setuid16 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setuid16, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		old_uid_t uid = va_arg(syscall_args, old_uid_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, uid);
	#endif
	#ifdef SYS_setxattr
	} else if (__sysno == SYS_setxattr && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> setxattr, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * path = va_arg(syscall_args, char *);
		char * name = va_arg(syscall_args, char *);
		void * value = va_arg(syscall_args, void *);
		size_t size = va_arg(syscall_args, size_t);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, path, name, value, size, flags);
	#endif
	#ifdef SYS_sgetmask
	} else if (__sysno == SYS_sgetmask && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sgetmask, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_shmat
	} else if (__sysno == SYS_shmat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> shmat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int shmid = va_arg(syscall_args, int);
		char * shmaddr = va_arg(syscall_args, char *);
		int shmflg = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, shmid, shmaddr, shmflg);
	#endif
	#ifdef SYS_shmctl
	} else if (__sysno == SYS_shmctl && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> shmctl, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int shmid = va_arg(syscall_args, int);
		int cmd = va_arg(syscall_args, int);
		struct shmid_ds * buf = va_arg(syscall_args, struct shmid_ds *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, shmid, cmd, buf);
	#endif
	#ifdef SYS_shmdt
	} else if (__sysno == SYS_shmdt && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> shmdt, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * shmaddr = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, shmaddr);
	#endif
	#ifdef SYS_shmget
	} else if (__sysno == SYS_shmget && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> shmget, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		key_t key = va_arg(syscall_args, key_t);
		size_t size = va_arg(syscall_args, size_t);
		int flag = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, key, size, flag);
	#endif
	#ifdef SYS_shutdown
	} else if (__sysno == SYS_shutdown && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> shutdown, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int unknown_name0 = va_arg(syscall_args, int);
		int unknown_name1 = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1);
	#endif
	#ifdef SYS_sigaction
	} else if (__sysno == SYS_sigaction && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sigaction, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int unknown_name0 = va_arg(syscall_args, int);
		struct old_sigaction * unknown_name1 = va_arg(syscall_args, struct old_sigaction *);
		struct old_sigaction * unknown_name2 = va_arg(syscall_args, struct old_sigaction *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2);
	#endif
	#ifdef SYS_sigaltstack
	} else if (__sysno == SYS_sigaltstack && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sigaltstack, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		struct sigaltstack * uss = va_arg(syscall_args, struct sigaltstack *);
		struct sigaltstack * uoss = va_arg(syscall_args, struct sigaltstack *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, uss, uoss);
	#endif
	#ifdef SYS_signal
	} else if (__sysno == SYS_signal && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> signal, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int sig = va_arg(syscall_args, int);
		__sighandler_t handler = va_arg(syscall_args, __sighandler_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, sig, handler);
	#endif
	#ifdef SYS_signalfd
	} else if (__sysno == SYS_signalfd && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> signalfd, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int ufd = va_arg(syscall_args, int);
		sigset_t * user_mask = va_arg(syscall_args, sigset_t *);
		size_t sizemask = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, ufd, user_mask, sizemask);
	#endif
	#ifdef SYS_signalfd4
	} else if (__sysno == SYS_signalfd4 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> signalfd4, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int ufd = va_arg(syscall_args, int);
		sigset_t * user_mask = va_arg(syscall_args, sigset_t *);
		size_t sizemask = va_arg(syscall_args, size_t);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, ufd, user_mask, sizemask, flags);
	#endif
	#ifdef SYS_sigpending
	} else if (__sysno == SYS_sigpending && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sigpending, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		old_sigset_t * uset = va_arg(syscall_args, old_sigset_t *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, uset);
	#endif
	#ifdef SYS_sigprocmask
	} else if (__sysno == SYS_sigprocmask && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sigprocmask, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int how = va_arg(syscall_args, int);
		old_sigset_t * set = va_arg(syscall_args, old_sigset_t *);
		old_sigset_t * oset = va_arg(syscall_args, old_sigset_t *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, how, set, oset);
	#endif
	#ifdef SYS_sigsuspend
	} else if (__sysno == SYS_sigsuspend && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sigsuspend, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		old_sigset_t mask = va_arg(syscall_args, old_sigset_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, mask);
	#endif
	#ifdef SYS_socket
	} else if (__sysno == SYS_socket && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> socket, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int unknown_name0 = va_arg(syscall_args, int);
		int unknown_name1 = va_arg(syscall_args, int);
		int unknown_name2 = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2);
	#endif
	#ifdef SYS_socketcall
	} else if (__sysno == SYS_socketcall && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> socketcall, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int call = va_arg(syscall_args, int);
		unsigned long * args = va_arg(syscall_args, unsigned long *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, call, args);
	#endif
	#ifdef SYS_socketpair
	} else if (__sysno == SYS_socketpair && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> socketpair, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int unknown_name0 = va_arg(syscall_args, int);
		int unknown_name1 = va_arg(syscall_args, int);
		int unknown_name2 = va_arg(syscall_args, int);
		int * unknown_name3 = va_arg(syscall_args, int *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0, unknown_name1, unknown_name2, unknown_name3);
	#endif
	#ifdef SYS_splice
	} else if (__sysno == SYS_splice && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> splice, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd_in = va_arg(syscall_args, int);
		loff_t * off_in = va_arg(syscall_args, loff_t *);
		int fd_out = va_arg(syscall_args, int);
		loff_t * off_out = va_arg(syscall_args, loff_t *);
		size_t len = va_arg(syscall_args, size_t);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd_in, off_in, fd_out, off_out, len, flags);
	#endif
	#ifdef SYS_spu_create
	} else if (__sysno == SYS_spu_create && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> spu_create, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * name = va_arg(syscall_args, char *);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		umode_t mode = (umode_t)va_arg(syscall_args, unsigned int);
		int fd = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, name, flags, mode, fd);
	#endif
	#ifdef SYS_spu_run
	} else if (__sysno == SYS_spu_run && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> spu_run, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		__u32 * unpc = va_arg(syscall_args, __u32 *);
		__u32 * ustatus = va_arg(syscall_args, __u32 *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, unpc, ustatus);
	#endif
	#ifdef SYS_ssetmask
	} else if (__sysno == SYS_ssetmask && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> ssetmask, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int newmask = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, newmask);
	#endif
	#ifdef SYS_stat
	} else if (__sysno == SYS_stat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> stat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		struct __old_kernel_stat * statbuf = va_arg(syscall_args, struct __old_kernel_stat *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename, statbuf);
	#endif
	#ifdef SYS_stat64
	} else if (__sysno == SYS_stat64 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> stat64, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		struct stat64 * statbuf = va_arg(syscall_args, struct stat64 *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename, statbuf);
	#endif
	#ifdef SYS_statfs
	} else if (__sysno == SYS_statfs && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> statfs, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char *  path = va_arg(syscall_args, char *);
		struct statfs * buf = va_arg(syscall_args, struct statfs *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno,  path, buf);
	#endif
	#ifdef SYS_statfs64
	} else if (__sysno == SYS_statfs64 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> statfs64, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * path = va_arg(syscall_args, char *);
		size_t sz = va_arg(syscall_args, size_t);
		struct statfs64 * buf = va_arg(syscall_args, struct statfs64 *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, path, sz, buf);
	#endif
	#ifdef SYS_statx
	} else if (__sysno == SYS_statx && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> statx, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char * path = va_arg(syscall_args, char *);
		unsigned flags = va_arg(syscall_args, unsigned);
		unsigned mask = va_arg(syscall_args, unsigned);
		struct statx * buffer = va_arg(syscall_args, struct statx *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd, path, flags, mask, buffer);
	#endif
	#ifdef SYS_stime
	} else if (__sysno == SYS_stime && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> stime, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		time_t * tptr = va_arg(syscall_args, time_t *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, tptr);
	#endif
	#ifdef SYS_swapoff
	} else if (__sysno == SYS_swapoff && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> swapoff, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * specialfile = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, specialfile);
	#endif
	#ifdef SYS_swapon
	} else if (__sysno == SYS_swapon && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> swapon, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * specialfile = va_arg(syscall_args, char *);
		int swap_flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, specialfile, swap_flags);
	#endif
	#ifdef SYS_symlink
	} else if (__sysno == SYS_symlink && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> symlink, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * old = va_arg(syscall_args, char *);
		char * new = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, old, new);
	#endif
	#ifdef SYS_symlinkat
	} else if (__sysno == SYS_symlinkat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> symlinkat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char *  oldname = va_arg(syscall_args, char *);
		int newdfd = va_arg(syscall_args, int);
		char *  newname = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno,  oldname, newdfd,  newname);
	#endif
	#ifdef SYS_sync
	} else if (__sysno == SYS_sync && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sync, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_sync_file_range
	} else if (__sysno == SYS_sync_file_range && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sync_file_range, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		loff_t offset = va_arg(syscall_args, loff_t);
		loff_t nbytes = va_arg(syscall_args, loff_t);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, offset, nbytes, flags);
	#endif
	#ifdef SYS_sync_file_range2
	} else if (__sysno == SYS_sync_file_range2 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sync_file_range2, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		loff_t offset = va_arg(syscall_args, loff_t);
		loff_t nbytes = va_arg(syscall_args, loff_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, flags, offset, nbytes);
	#endif
	#ifdef SYS_syncfs
	} else if (__sysno == SYS_syncfs && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> syncfs, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd);
	#endif
	#ifdef SYS_sysctl
	} else if (__sysno == SYS_sysctl && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sysctl, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		struct __sysctl_args * args = va_arg(syscall_args, struct __sysctl_args *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, args);
	#endif
	#ifdef SYS_sysfs
	} else if (__sysno == SYS_sysfs && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sysfs, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int option = va_arg(syscall_args, int);
		unsigned long arg1 = va_arg(syscall_args, unsigned long);
		unsigned long arg2 = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, option, arg1, arg2);
	#endif
	#ifdef SYS_sysinfo
	} else if (__sysno == SYS_sysinfo && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> sysinfo, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		struct sysinfo * info = va_arg(syscall_args, struct sysinfo *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, info);
	#endif
	#ifdef SYS_syslog
	} else if (__sysno == SYS_syslog && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> syslog, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int type = va_arg(syscall_args, int);
		char * buf = va_arg(syscall_args, char *);
		int len = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, type, buf, len);
	#endif
	#ifdef SYS_tee
	} else if (__sysno == SYS_tee && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> tee, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fdin = va_arg(syscall_args, int);
		int fdout = va_arg(syscall_args, int);
		size_t len = va_arg(syscall_args, size_t);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fdin, fdout, len, flags);
	#endif
	#ifdef SYS_tgkill
	} else if (__sysno == SYS_tgkill && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> tgkill, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t tgid = va_arg(syscall_args, pid_t);
		pid_t pid = va_arg(syscall_args, pid_t);
		int sig = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, tgid, pid, sig);
	#endif
	#ifdef SYS_time
	} else if (__sysno == SYS_time && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> time, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		time_t * tloc = va_arg(syscall_args, time_t *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, tloc);
	#endif
	#ifdef SYS_timer_create
	} else if (__sysno == SYS_timer_create && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> timer_create, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		clockid_t which_clock = va_arg(syscall_args, clockid_t);
		struct sigevent * timer_event_spec = va_arg(syscall_args, struct sigevent *);
		timer_t *  created_timer_id = va_arg(syscall_args, timer_t *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, which_clock, timer_event_spec,  created_timer_id);
	#endif
	#ifdef SYS_timer_delete
	} else if (__sysno == SYS_timer_delete && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> timer_delete, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		timer_t timer_id = va_arg(syscall_args, timer_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, timer_id);
	#endif
	#ifdef SYS_timer_getoverrun
	} else if (__sysno == SYS_timer_getoverrun && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> timer_getoverrun, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		timer_t timer_id = va_arg(syscall_args, timer_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, timer_id);
	#endif
	#ifdef SYS_timer_gettime
	} else if (__sysno == SYS_timer_gettime && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> timer_gettime, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		timer_t timer_id = va_arg(syscall_args, timer_t);
		struct itimerspec * setting = va_arg(syscall_args, struct itimerspec *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, timer_id, setting);
	#endif
	#ifdef SYS_timer_settime
	} else if (__sysno == SYS_timer_settime && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> timer_settime, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		timer_t timer_id = va_arg(syscall_args, timer_t);
		int flags = va_arg(syscall_args, int);
		struct itimerspec * new_setting = va_arg(syscall_args, struct itimerspec *);
		struct itimerspec * old_setting = va_arg(syscall_args, struct itimerspec *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, timer_id, flags, new_setting, old_setting);
	#endif
	#ifdef SYS_timerfd_create
	} else if (__sysno == SYS_timerfd_create && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> timerfd_create, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int clockid = va_arg(syscall_args, int);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, clockid, flags);
	#endif
	#ifdef SYS_timerfd_gettime
	} else if (__sysno == SYS_timerfd_gettime && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> timerfd_gettime, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int ufd = va_arg(syscall_args, int);
		struct itimerspec * otmr = va_arg(syscall_args, struct itimerspec *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, ufd, otmr);
	#endif
	#ifdef SYS_timerfd_settime
	} else if (__sysno == SYS_timerfd_settime && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> timerfd_settime, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int ufd = va_arg(syscall_args, int);
		int flags = va_arg(syscall_args, int);
		struct itimerspec * utmr = va_arg(syscall_args, struct itimerspec *);
		struct itimerspec * otmr = va_arg(syscall_args, struct itimerspec *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, ufd, flags, utmr, otmr);
	#endif
	#ifdef SYS_times
	} else if (__sysno == SYS_times && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> times, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		struct tms * tbuf = va_arg(syscall_args, struct tms *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, tbuf);
	#endif
	#ifdef SYS_tkill
	} else if (__sysno == SYS_tkill && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> tkill, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		int sig = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, sig);
	#endif
	#ifdef SYS_truncate
	} else if (__sysno == SYS_truncate && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> truncate, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * path = va_arg(syscall_args, char *);
		long length = va_arg(syscall_args, long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, path, length);
	#endif
	#ifdef SYS_truncate64
	} else if (__sysno == SYS_truncate64 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> truncate64, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * path = va_arg(syscall_args, char *);
		loff_t length = va_arg(syscall_args, loff_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, path, length);
	#endif
	#ifdef SYS_umask
	} else if (__sysno == SYS_umask && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> umask, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int mask = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, mask);
	#endif
	#ifdef SYS_umount
	} else if (__sysno == SYS_umount && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> umount, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * name = va_arg(syscall_args, char *);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, name, flags);
	#endif
	#ifdef SYS_uname
	} else if (__sysno == SYS_uname && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> uname, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		struct old_utsname * unknown_name0 = va_arg(syscall_args, struct old_utsname *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unknown_name0);
	#endif
	#ifdef SYS_unlink
	} else if (__sysno == SYS_unlink && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> unlink, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * pathname = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pathname);
	#endif
	#ifdef SYS_unlinkat
	} else if (__sysno == SYS_unlinkat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> unlinkat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char *  pathname = va_arg(syscall_args, char *);
		int flag = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd,  pathname, flag);
	#endif
	#ifdef SYS_unshare
	} else if (__sysno == SYS_unshare && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> unshare, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long unshare_flags = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, unshare_flags);
	#endif
	#ifdef SYS_uselib
	} else if (__sysno == SYS_uselib && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> uselib, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * library = va_arg(syscall_args, char *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, library);
	#endif
	#ifdef SYS_userfaultfd
	} else if (__sysno == SYS_userfaultfd && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> userfaultfd, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, flags);
	#endif
	#ifdef SYS_ustat
	} else if (__sysno == SYS_ustat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> ustat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned dev = va_arg(syscall_args, unsigned);
		struct ustat * ubuf = va_arg(syscall_args, struct ustat *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dev, ubuf);
	#endif
	#ifdef SYS_utime
	} else if (__sysno == SYS_utime && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> utime, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		struct utimbuf * times = va_arg(syscall_args, struct utimbuf *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename, times);
	#endif
	#ifdef SYS_utimensat
	} else if (__sysno == SYS_utimensat && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> utimensat, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int dfd = va_arg(syscall_args, int);
		char * filename = va_arg(syscall_args, char *);
		struct timespec * utimes = va_arg(syscall_args, struct timespec *);
		int flags = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, dfd, filename, utimes, flags);
	#endif
	#ifdef SYS_utimes
	} else if (__sysno == SYS_utimes && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> utimes, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		char * filename = va_arg(syscall_args, char *);
		struct timeval * utimes = va_arg(syscall_args, struct timeval *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, filename, utimes);
	#endif
	#ifdef SYS_vfork
	} else if (__sysno == SYS_vfork && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> vfork, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_vhangup
	} else if (__sysno == SYS_vhangup && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> vhangup, will pass along\n", __sysno);
		syscall_status = syscall_fn_ptr(__sysno);
	#endif
	#ifdef SYS_vmsplice
	} else if (__sysno == SYS_vmsplice && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> vmsplice, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int fd = va_arg(syscall_args, int);
		struct iovec * iov = va_arg(syscall_args, struct iovec *);
		unsigned long nr_segs = va_arg(syscall_args, unsigned long);
		unsigned int flags = va_arg(syscall_args, unsigned int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, iov, nr_segs, flags);
	#endif
	#ifdef SYS_wait4
	} else if (__sysno == SYS_wait4 && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> wait4, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		int * stat_addr = va_arg(syscall_args, int *);
		int options = va_arg(syscall_args, int);
		struct rusage * ru = va_arg(syscall_args, struct rusage *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, stat_addr, options, ru);
	#endif
	#ifdef SYS_waitid
	} else if (__sysno == SYS_waitid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> waitid, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		int which = va_arg(syscall_args, int);
		pid_t pid = va_arg(syscall_args, pid_t);
		struct siginfo * infop = va_arg(syscall_args, struct siginfo *);
		int options = va_arg(syscall_args, int);
		struct rusage * ru = va_arg(syscall_args, struct rusage *);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, which, pid, infop, options, ru);
	#endif
	#ifdef SYS_waitpid
	} else if (__sysno == SYS_waitpid && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> waitpid, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		pid_t pid = va_arg(syscall_args, pid_t);
		int * stat_addr = va_arg(syscall_args, int *);
		int options = va_arg(syscall_args, int);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, pid, stat_addr, options);
	#endif
	#ifdef SYS_write
	} else if (__sysno == SYS_write && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> write, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned int fd = va_arg(syscall_args, unsigned int);
		char * buf = va_arg(syscall_args, char *);
		size_t count = va_arg(syscall_args, size_t);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, buf, count);
	#endif
	#ifdef SYS_writev
	} else if (__sysno == SYS_writev && syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld --> writev, will pass along\n", __sysno);
		va_start(syscall_args, __sysno);
		unsigned long fd = va_arg(syscall_args, unsigned long);
		struct iovec * vec = va_arg(syscall_args, struct iovec *);
		unsigned long vlen = va_arg(syscall_args, unsigned long);
		va_end(syscall_args);
		syscall_status = syscall_fn_ptr(__sysno, fd, vec, vlen);
	#endif

	// end of auto generated code
	} else if (syscall_fn_ptr) {
		sr_shimdebug_msg(1, "syscall %ld NOT IMPLEMENTED\n", __sysno);
		sr_log_msg(logctxptr,LOG_ERROR, "syscall (%ld) not implemented\n", __sysno);
		syscall_status = -1;
	} else {
		sr_shimdebug_msg(1, "syscall %ld no syscall_fn_ptr!\n", __sysno);
		sr_log_msg(logctxptr,LOG_ERROR, "syscall (%ld) no syscall_fn_ptr!\n", __sysno);
		syscall_status = -1;
	}
	sr_shimdebug_msg(1, "syscall %ld return %ld\n", __sysno, syscall_status);
	return syscall_status;
}
#endif
