
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <math.h>
#include <stdarg.h>
#include <errno.h>

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

void sr_shimdebug_msg(const char *format, ...)
{
     struct timespec ts;
             va_list ap;

     if (!getenv("SR_SHIMDEBUG")) return;

     clock_gettime(CLOCK_REALTIME, &ts);
     if (pid_seconds_wallclock==0) {
	     mypid=getpid();
	     fprintf(stderr, " startup " );
	     pid_seconds_wallclock=ts.tv_sec ;
     }
     fprintf(stderr, "SR_SHIMDEBUG %d %g ",  mypid, (ts.tv_sec + ts.tv_nsec / 1e9) - pid_seconds_wallclock );

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
	}
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
	sr_shimdebug_msg("setup pfo done.\n");
}

static struct sr_context *sr_c = NULL;
static int sr_connected = 0;

static int close_init_done = 0;
typedef int (*close_fn) (int);
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
	for (int i = 0; i < remembered_count; i++)
		if (!strcmp((*remembered_filenames)[i].name, fn)) {
			interval = (ts.tv_sec + ts.tv_nsec / 1e9) -
			    ((*remembered_filenames)[i].ts.tv_sec +
			     (*remembered_filenames)[i].ts.tv_nsec / 1e9);
			if (interval < sr_cfg.shim_post_minterval) {
				sr_shimdebug_msg(
					"suppress repeated post of %s (count=%d) (only: %g seconds ago, minterval is: %g)\n",
					fn, remembered_count, interval, sr_cfg.shim_post_minterval);
				(*remembered_filenames)[i].clean = 0;
				return (1);
			} else {
				sr_shimdebug_msg(
					"shim_post_minterval (%g) exceeded (%g), repeat post of %s (count=%d) \n",
					sr_cfg.shim_post_minterval, interval, fn, remembered_count);
				(*remembered_filenames)[i].ts = ts;
				(*remembered_filenames)[i].clean =
				    !(sr_c->cfg->shim_defer_posting_to_exit);
				return (0);
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

	sr_shimdebug_msg( "remembering post of %s (count=%d) \n", fn, remembered_count);
	return (0);

}

static int shim_disabled = 0;

void srshim_initialize(const char *progname)
{

	static int config_read = 0;
	static int init_in_progress=0;
	char *setstr;
	int finalize_good;

	if (init_in_progress)
		return;
	init_in_progress=1;
	sr_shimdebug_msg( "FIXME srshim_initialize %s starting..\n", progname);
	if (sr_c)
		return;

	setstr = getenv("SR_POST_CONFIG");

	if (setstr == NULL)
		return;

	
	//sr_shimdebug_msg( "FIXME srshim_initialize 2 %s setstr=%p\n", progname, setstr);

	// skip many FD to try to avoid stepping over stdout stderr, for logs & broker connection.
	if (config_read == 0) {
		setstr = strdup(setstr);
		sr_config_init(&sr_cfg, progname);
		config_read = sr_config_read(&sr_cfg, setstr, 1, 1);
		free(setstr);
		if (!config_read) {
			sr_log_msg(LOG_ERROR,
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
	finalize_good = sr_config_finalize(&sr_cfg, 0);

	if (!finalize_good) {
		shim_disabled = 1;	// turn off the library so stuff works without it.
		errno = 0;
		return;
	}

	if (sr_cfg.shim_skip_parent_open_files)
		setup_pfo();

	sr_c = sr_context_init_config(&sr_cfg, 1);

	init_in_progress=0;
	errno = 0;
}

int srshim_connect()
{
	if (!sr_connected) {

		sr_c = sr_context_connect(sr_c);
		if (sr_c)
			sr_connected = 1;

		errno = 0;
	}
	return (sr_connected);
}

char *stubborn_realpath( const char *path, char *resolved_path ) 
/*
 like realpath(3) except, it returned a "best" realpath in more cases.

    if the last element of a realpath (such as in a broken link) does not exist, realpath(3) returns NULL.
    in stubborn version, if last element does not exist, remove it, and try resolving the parent.
    if the parent resolves, then append the filename to result of the resolved parent, and return that.

    if neither resolves, then just copy input path to resolved path, so that it always returns a value,
    rather than having to deal with that case separately.
 */
{
	char *res;
        char *last_slash;
	char path_buffer[PATH_MAX + 1];

	res = realpath(path, resolved_path);

	if (res) return(res);

	//sr_shimdebug_msg( "sr_%s stubborn_realpath 2: failed initial realpath of %s\n", sr_cfg.progname, path);

        strcpy(path_buffer,path);
        last_slash=rindex(path_buffer,'/');
	*last_slash='\0';
	res = realpath(path_buffer, resolved_path);

	//sr_shimdebug_msg("sr_%s stubborn_realpath 3: tried realpath: %s result: %s\n", sr_cfg.progname, path_buffer, res);
        if (!res) {
		strcpy( resolved_path, path );
        } else { 
                *last_slash='/';
	        strcat( resolved_path, last_slash );
	        //sr_shimdebug_msg("sr_%s stubborn_realpath 4: after parent result: %s\n", sr_cfg.progname, resolved_path);
        }
        return(resolved_path);
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

	//sr_shimdebug_msg( "FIXME realpost 1 PATH %s src=%p\n", path, sr_c);

	if (!path || !sr_c)
		return;

	//sr_shimdebug_msg( "FIXME realpost 2 PATH %s\n", path);

	statres = lstat(path, &sb);

	if (!statres && !S_ISREG(sb.st_mode) && !S_ISLNK(sb.st_mode)) {
	        //sr_shimdebug_msg( "FIXME realpost 2.2 returning statres=%d, mode=%o , S_IFREG=%o, S_IFLNK=%o \n", 
                //    statres, sb.st_mode, S_IFREG, S_IFLNK );
		return;
        }
	strcpy(fn, path);

	if (sr_cfg.realpath || sr_cfg.realpath_filter) 
		stubborn_realpath(path,fnreal);

	if (sr_cfg.realpath) {
		strcpy(fn, fnreal);
        }

	if (sr_cfg.realpath_filter) {
		mask = sr_isMatchingPattern(&sr_cfg, fnreal);
	} else {
		mask = sr_isMatchingPattern(&sr_cfg, fn);
	}

	if ((mask && !(mask->accepting)) || (!mask && !(sr_cfg.accept_unmatched))) {	//reject.
		sr_shimdebug_msg(
			"mask: %p, mask->accepting=%d accept_unmatched=%d\n",
			mask, mask->accepting, sr_cfg.accept_unmatched);
		if (sr_cfg.log_reject)
			sr_log_msg(LOG_INFO, "sr_%s rejecting pattern: %s\n", sr_cfg.progname, fn);
		return;
	}
	sr_shimdebug_msg( "accepted... %s now\n", fn);

	if (should_not_post(fn))
		return;

	if (sr_c->cfg->shim_defer_posting_to_exit)
		return;

	if (!srshim_connect())
		return;

	if (statres) {
		sr_shimdebug_msg( "should be really posting %s now sr_c=%p\n", fn, sr_c);
		sr_post(sr_c, fn, NULL);
		return;
	}

	/* if it is a link, sr_post uses the path of the link...  */

	if (S_ISLNK(sb.st_mode)) {
		strcpy(fn, path);
	}

	sr_post(sr_c, fn, &sb);

}

int shimpost(const char *path, int status)
{
	char *cwd = NULL;
	char *real_path = NULL;

	if (shim_disabled)
		return (status);

	shim_disabled = 1;
	if (!status) {
		srshim_initialize("shim");

		if (path[0] == '/') {
			if (getenv("SR_SHIMDEBUG"))
				sr_shimdebug_msg( "absolute 1 shimpost %s, status=%d\n", path, status);
			srshim_realpost(path);
		} else {
			cwd = get_current_dir_name();
			real_path = (char *)malloc(strlen(cwd) + strlen(path) + 3);
			//getwd(real_path);
			strcpy(real_path, cwd);
			strcat(real_path, "/");
			strcat(real_path, path);
			if (getenv("SR_SHIMDEBUG"))
				sr_shimdebug_msg( "relative 2 shimpost %s status=%d\n", real_path, status);
			srshim_realpost(real_path);
			free(real_path);
			free(cwd);
		}
	}
	shim_disabled = 0;

	clerror(status);
	return (status);
}

static int truncate_init_done = 0;
typedef int (*truncate_fn) (const char *, off_t length);
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

static int symlink_init_done = 0;
typedef int (*symlink_fn) (const char *, const char *);
static symlink_fn symlink_fn_ptr = symlink;

int symlink(const char *target, const char *linkpath)
{
	int status;

	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( "symlink %s %s\n", target, linkpath);
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
typedef int (*symlinkat_fn) (const char *, int, const char *);
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
	        if (getenv("SR_SHIMDEBUG"))
		      sr_shimdebug_msg( "symlinkat %s %s\n", target, linkpath);
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

	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( "4 symlinkat real_path=%s target=%s linkpath=%s\n", real_path, target, linkpath );

	clerror(status);
	if (!real_return) {
		return (status);
        }
	strcat(real_path, "/");
	strcat(real_path, linkpath );

	clerror(status);
	return (shimpost(real_path, status));

}




static int unlinkat_init_done = 0;
typedef int (*unlinkat_fn) (int dirfd, const char *, int flags);
static unlinkat_fn unlinkat_fn_ptr = unlinkat;

int unlinkat(int dirfd, const char *path, int flags)
{
	int status;
	char fdpath[PATH_MAX + 1];
	char real_path[PATH_MAX + 1];
	char *real_return;

	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( "unlinkat %s dirfd=%i\n", path, dirfd);
	if (!unlinkat_init_done) {
		setup_exit();
		unlinkat_fn_ptr = (unlinkat_fn) dlsym(RTLD_NEXT, "unlinkat");
		unlinkat_init_done = 1;
	}

	status = unlinkat_fn_ptr(dirfd, path, flags);
	if (shim_disabled)
		return (status);
	clerror(status);
	if (status == -1)
		return status;

	if (dirfd == AT_FDCWD)
		return (shimpost(path, status));

	snprintf(fdpath, 32, "/proc/self/fd/%d", dirfd);
	real_return = realpath(fdpath, real_path);
	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( " unlinkat relative directory %s real_return=%p\n", fdpath, real_return);
	strcat(real_path, "/");
	strcat(real_path, path);

	clerror(status);
	if (!real_return)
		return (status);

	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( " unlinkat realpath %s\n", real_path);

	return (shimpost(real_path, status));
}

static int unlink_init_done = 0;
typedef int (*unlink_fn) (const char *);
static unlink_fn unlink_fn_ptr = unlink;

int unlink(const char *path)
{
	int status;

	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( " unlink %s\n", path);
	if (!unlink_init_done) {
		setup_exit();
		unlink_fn_ptr = (unlink_fn) dlsym(RTLD_NEXT, "unlink");
		unlink_init_done = 1;
	}
	status = unlink_fn_ptr(path);
	if (shim_disabled)
		return (status);

	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( " unlink 2 %s status=%d\n", path, status);

	if (status == -1)
		return status;

	if (!strncmp(path, "/dev/", 5)) {
		clerror(status);
		return (status);
	}

	return (shimpost(path, status));
}

static int link_init_done = 0;
typedef int (*link_fn) (const char *, const char *);
static link_fn link_fn_ptr = link;

static int linkat_init_done = 0;
typedef int (*linkat_fn) (int, const char *, int, const char *, int flags);
static linkat_fn linkat_fn_ptr = linkat;

static int renameat_init_done = 0;
typedef int (*renameat_fn) (int, const char *, int, const char *);
static renameat_fn renameat_fn_ptr = NULL;

static int renameat2_init_done = 0;
typedef int (*renameat2_fn) (int, const char *, int, const char *, unsigned int);
static renameat2_fn renameat2_fn_ptr = NULL;

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

	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( " renameorlink %s %s\n", oldpath, newpath);

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

	if (link) {
		if (linkat_fn_ptr)
			status = linkat_fn_ptr(olddirfd, oldpath, newdirfd, newpath, flags);
		else if (link_fn_ptr && !flags)
			status = link_fn_ptr(oldpath, newpath);
		else {
			sr_log_msg(LOG_ERROR,
				" renameorlink could not identify real entry point for link\n");
		}
	} else {
		if (renameat2_fn_ptr)
			status = renameat2_fn_ptr(olddirfd, oldpath, newdirfd, newpath, flags);
		else if (renameat_fn_ptr && !flags)
			status = renameat_fn_ptr(olddirfd, oldpath, newdirfd, newpath);
		else {
			sr_log_msg(LOG_ERROR,
				" renameorlink could not identify real entry point for renameat\n");
			return (-1);
		}
	}
	if (shim_disabled)
		return (status);

	if (status == -1) {
		if (getenv("SR_SHIMDEBUG"))
			sr_shimdebug_msg(
				" renameorlink %s %s failed, no post\n",
				oldpath, newpath);
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
			sr_log_msg(LOG_WARNING,
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
			sr_log_msg(LOG_WARNING,
				"srshim renameorlink could not obtain real_path for newdir=%s failed, no post\n",
				fdpath);
			clerror(status);
			return (status);
		}
		strcat(real_path, "/");
		strcat(real_path, newpath);
	}
	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg(
			" renameorlink sr_c=%p, oreal_path=%s, real_path=%s\n",
			sr_c, oreal_path, real_path);

	if (!srshim_connect())
		return (status);

	sr_post_rename(sr_c, oreal_path, real_path);

	clerror(status);
	return (status);

}

static int dup2_init_done = 0;
typedef int (*dup2_fn) (int, int);
static dup2_fn dup2_fn_ptr = dup2;

int dup2(int oldfd, int newfd)
{
	int fdstat;
	char fdpath[32];
	char real_path[PATH_MAX + 1];
	char *real_return;
	int status;

	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( " dup2 oldfd %d newfd %d\n", oldfd, newfd);

	if (!dup2_init_done) {
		setup_exit();
		dup2_fn_ptr = (dup2_fn) dlsym(RTLD_NEXT, "dup2");
		dup2_init_done = 1;
		if (getenv("SR_POST_READS"))
			srshim_initialize("shim");
	}

	errno = 0;

	if (shim_disabled || (oldfd == newfd)) {
		//if (getenv("SR_SHIMDEBUG")) sr_shimdebug_msg(  " dup2 NO POST oldfd = newfd \n" );
		return dup2_fn_ptr(oldfd, newfd);
	}

	fdstat = fcntl(newfd, F_GETFL);

	if (fdstat == -1) {
		//if (getenv("SR_SHIMDEBUG")) sr_shimdebug_msg(  " dup2 NO POST not valid fd !\n" );
		errno = 0;
		return dup2_fn_ptr(oldfd, newfd);
	}

	if ((fdstat & O_ACCMODE) == O_RDONLY) {
		//if (getenv("SR_SHIMDEBUG")) sr_shimdebug_msg(  " dup2 NO POST read mode !\n" );
		errno = 0;
		return dup2_fn_ptr(oldfd, newfd);
	}

	snprintf(fdpath, 32, "/proc/self/fd/%d", newfd);
	real_return = realpath(fdpath, real_path);

	if (!real_return) {
		//if (getenv("SR_SHIMDEBUG")) sr_shimdebug_msg(  " dup2 NO POST no path from fd !\n" );
		errno = 0;
		return dup2_fn_ptr(oldfd, newfd);
	}

	if (!strncmp(real_path, "/dev/", 5) || !strncmp(real_path, "/proc/", 6)) {
		//if (getenv("SR_SHIMDEBUG")) sr_shimdebug_msg(  " dup2 NO POST path device or proc !\n" );
		errno = 0;
		return dup2_fn_ptr(oldfd, newfd);
	}

	if (!getenv("SR_POST_READS"))
		srshim_initialize("shim");

	status = dup2_fn_ptr(oldfd, newfd);
	if (status == -1)
		return status;

	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( " dup2 posting %s status=%d\n", real_path, status);

	// because shimpost posts when:    if (!status)
	// we use a tmpstatus and call shimpost with status=0

	shimpost(real_path, 0);

	clerror(status);

	return status;
}

static int dup3_init_done = 0;
typedef int (*dup3_fn) (int, int, int);
static dup3_fn dup3_fn_ptr = dup3;

int dup3(int oldfd, int newfd, int flags)
{
	int fdstat;
	char fdpath[32];
	char real_path[PATH_MAX + 1];
	char *real_return;
	int status;

	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg(
			" dup3 oldfd %d newfd %d flags %d\n", oldfd, newfd, flags);

	if (!dup3_init_done) {
		setup_exit();
		dup3_fn_ptr = (dup3_fn) dlsym(RTLD_NEXT, "dup3");
		dup3_init_done = 1;
		if (getenv("SR_POST_READS"))
			srshim_initialize("shim");
	}

	if (shim_disabled || (oldfd == newfd)) {
		//if (getenv("SR_SHIMDEBUG")) sr_shimdebug_msg(  " dup3 NO POST oldfd = newfd \n" );
		errno = 0;
		return dup3_fn_ptr(oldfd, newfd, flags);
	}

	fdstat = fcntl(newfd, F_GETFL);

	if (fdstat == -1) {
		//if (getenv("SR_SHIMDEBUG")) sr_shimdebug_msg(  " dup3 NO POST not valid fd !\n" );
		errno = 0;
		return dup3_fn_ptr(oldfd, newfd, flags);
	}

	if ((fdstat & O_ACCMODE) == O_RDONLY) {
		//if (getenv("SR_SHIMDEBUG")) sr_shimdebug_msg(  " dup3 NO POST read mode !\n" );
		errno = 0;
		return dup3_fn_ptr(oldfd, newfd, flags);
	}

	snprintf(fdpath, 32, "/proc/self/fd/%d", newfd);
	real_return = realpath(fdpath, real_path);

	if (!real_return) {
		//if (getenv("SR_SHIMDEBUG")) sr_shimdebug_msg(  " dup3 NO POST no path from fd !\n" );
		errno = 0;
		return dup3_fn_ptr(oldfd, newfd, flags);
	}

	if (!strncmp(real_path, "/dev/", 5) || !strncmp(real_path, "/proc/", 6)) {
		//if (getenv("SR_SHIMDEBUG")) sr_shimdebug_msg(  " dup3 NO POST path device or proc !\n" );
		errno = 0;
		return dup3_fn_ptr(oldfd, newfd, flags);
	}

	if (!getenv("SR_POST_READS"))
		srshim_initialize("shim");

	errno = 0;
	status = dup3_fn_ptr(oldfd, newfd, flags);
	if (status == -1)
		return status;

	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( " dup3 posting %s %d\n", real_path, status);

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

	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( "exit_cleanup_posts, context=%p\n", sr_c);

	if (exit_cleanup_posts_ran || shim_disabled || !getenv("SR_POST_CONFIG"))
		return;

        exit_cleanup_posts_ran = 1;

	// In the current process, find files which are not opened by the parent
	// that need posting.
	fddir = opendir("/proc/self/fd");

	if (fddir) {
		while ((fdde = readdir(fddir))) {
	                //if (getenv("SR_SHIMDEBUG"))
                     	//	sr_shimdebug_msg( "exit_cleanup_posts, readdir fdde->d_name=%s\n", fdde->d_name);
			if (fdde->d_name[0] == '.')
				continue;

			fd = atoi(fdde->d_name);
			fdstat = fcntl(fd, F_GETFL);

			if (fdstat == -1)
				continue;

			if ((fdstat & O_ACCMODE) == O_RDONLY)
				continue;

			snprintf(fdpath, 499, "/proc/self/fd/%s", fdde->d_name);
			real_return = realpath(fdpath, real_path);

			if ((!real_return) || (real_path[0] != '/') ||
			    (!strncmp(real_path, "/dev/", 5))
			    || (!strncmp(real_path, "/proc/", 6)))
				continue;

			found = 0;
			for (int i = 0; (i < last_pfo); i++) {
	                        //if (getenv("SR_SHIMDEBUG"))
                     		//         sr_shimdebug_msg( "exit_cleanup_posts, last_pfo i=%d open_file=%s\n", 
				//		 i, parent_files_open[i]);
				if (!strcmp(real_path, parent_files_open[i])) {
					found = 1;
					break;
				}
			}

			if (found)
				continue;

			fsync(fd);	// ensure data is flushed to disk before post occurs.

			if (getenv("SR_SHIMDEBUG"))
				sr_shimdebug_msg( " exit posting %s\n", real_path);

			shimpost(real_path, 0);
		}
		closedir(fddir);
	}

	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( " exit posting... deferred posting start.\n" );

	/* execute deferred/remembered posts, FIXME: embarrasing n**2 algo, should do better later */
	for (int i = 0; i < remembered_count; i++) {
		// if a file was already posted and hasn't been written since.
		if (!(sr_cfg.shim_defer_posting_to_exit)
		    && (*remembered_filenames)[i].clean)
			continue;

		srshim_initialize("shim");

		if (!srshim_connect())
			continue;

		statres = lstat((*remembered_filenames)[i].name, &sb);

		if (statres) {
			sr_post(sr_c, (*remembered_filenames)[i].name, NULL);
		} else {
			if (S_ISLNK(sb.st_mode)) {
				//if ( getenv("SR_SHIMDEBUG")) sr_shimdebug_msg(  " exit reading link: %s\n", (*remembered_filenames)[i].name );
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
	if ( getenv("SR_SHIMDEBUG")) sr_shimdebug_msg(  "exit closing context sr_c=%p\n", sr_c );
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

typedef void (*exit_fn) (int) __attribute__ ((noreturn));

void exit(int status)
{
	static exit_fn exit_fn_ptr = NULL;

	if (exit_cleanup_posts_ran) _exit(status);

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

    if ( getenv("SR_SHIMDEBUG")) sr_shimdebug_msg(  "exit_group 0, context=%p\n", sr_c );

    exit_group_fn_ptr = (exit_fn) dlsym(RTLD_NEXT, "exit_group");

    if ( !getenv( "SR_POST_CONFIG" ) || shim_disabled) exit_group_fn_ptr(status);

    exit_cleanup_posts();

    // do it for real.
    exit_group_fn_ptr(status);
}

int link(const char *target, const char *linkpath)
{
	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( " link %s %s\n", target, linkpath);
	return (renameorlink(AT_FDCWD, target, AT_FDCWD, linkpath, 0, 1));
}

int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags)
{
	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg(
			"linkat olddirfd=%d, oldname=%s newdirfd=%d newname=%s flags=%d\n",
			olddirfd, oldpath, newdirfd, newpath, flags);
	return (renameorlink(olddirfd, oldpath, newdirfd, newpath, flags, 1));
}

int rename(const char *oldpath, const char *newpath)
{
	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( "rename %s %s\n", oldpath, newpath);

	return (renameorlink(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0, 0));
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( "renameat %s %s\n", oldpath, newpath);

	return (renameorlink(olddirfd, oldpath, newdirfd, newpath, 0, 0));
}

int renameat2(int olddirfd, const char *oldpath, int newdirfd,
	      const char *newpath, unsigned int flags)
{
	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( "renameat2 %s %s\n", oldpath, newpath);

	return (renameorlink(olddirfd, oldpath, newdirfd, newpath, flags, 0));
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

	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( " sendfile to %s\n", real_path);

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

	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( "copy_file_range to %s\n", real_path);

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

	if (!close_init_done) {
		setup_exit();
		close_fn_ptr = (close_fn) dlsym(RTLD_NEXT, "close");
		close_init_done = 1;
		if (getenv("SR_POST_READS"))
			srshim_initialize("shim");
	}
	if (shim_disabled)
		return close_fn_ptr(fd);

	fdstat = fcntl(fd, F_GETFL);

	if (fdstat == -1) {
		//if (getenv("SR_SHIMDEBUG")) sr_shimdebug_msg(  " close NO POST not valid fd !\n" );
		errno = 0;
		return close_fn_ptr(fd);
	}

	if ((fdstat & O_ACCMODE) == O_RDONLY) {
		errno = 0;
		return close_fn_ptr(fd);
	}
	snprintf(fdpath, 32, "/proc/self/fd/%d", fd);
	real_return = realpath(fdpath, real_path);

	if (!getenv("SR_POST_READS"))
		srshim_initialize("shim");

	errno = 0;
	status = close_fn_ptr(fd);
	if (status == -1)
		return status;

	clerror(status);
	if (!real_return)
		return status;

	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( "close %s fd=%d\n", real_path, fd);

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
typedef int (*fclose_fn) (FILE *);
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

	fdstat = fcntl(fd, F_GETFL);

	//if ( getenv("SR_SHIMDEBUG")) sr_shimdebug_msg(  " fclose %p fd=%i starting\n", f, fdstat );

	if (fdstat == -1) {
		//if (getenv("SR_SHIMDEBUG")) sr_shimdebug_msg(  " fclose NO POST not valid fd !\n" );
		errno = 0;
		return fclose_fn_ptr(f);
	}

	if ((fdstat & O_ACCMODE) == O_RDONLY) {
		//if (getenv("SR_SHIMDEBUG")) sr_shimdebug_msg(  " fclose NO POST read-only. \n" );
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

	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( "fclose %p %s status=%d\n", f, real_path, status);

	return shimpost(real_path, status);
}


static int fopen_init_done = 0;
typedef FILE* (*fopen_fn) (const char* pathname, const char *mode);
static fopen_fn fopen_fn_ptr = fopen;

FILE* fopen(const char *pathname, const char *mode)
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
	if (getenv("SR_SHIMDEBUG"))
		sr_shimdebug_msg( "fopen %s %s\n", pathname, mode);

	return( fopen_fn_ptr(pathname,mode) );
}


