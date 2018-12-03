
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

 FIXME:  1024, and PATH_MAX, should likely be replaced by code that mallocs properly.

 set following variables to non-empty strings to activate.

 SR_SHIMDEBUG - when set, debug output triggerred.

 SRSHIMMV - trigger new form of MV posting.

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
static struct sr_context *sr_c = NULL;
static struct sr_config_t sr_cfg; 
static int sr_connected = 0;


static int close_init_done = 0;
typedef int  (*close_fn) (int);
static close_fn close_fn_ptr = close;

char **deferred_post_filenames = NULL;
int  deferred_post_count = 0;
int  deferred_post_max = 0;

void defer_post(const char* fn)
{

  /* already scheduled to post? */
  for( int i= 0; i < deferred_post_count ; i++ )
    if (!strcmp(deferred_post_filenames[i],fn) )
    {
        log_msg( LOG_DEBUG, "suppress repeated post of %s (count=%d) \n", fn, deferred_post_count );
        return;
    }
  /* add to the list */
  if ( deferred_post_count >= deferred_post_max )
  {
      if (!deferred_post_filenames)
      {
            deferred_post_filenames = (char**)malloc( 1*sizeof(char *) );
            deferred_post_max=1;
      } else {
            char **saved_post_filenames = deferred_post_filenames ;
            deferred_post_max *= 2;
            deferred_post_filenames = (char**)malloc( deferred_post_max*sizeof(char *) );

            for (int i = 0; i < deferred_post_count ; i++ ) 
                deferred_post_filenames[i] = saved_post_filenames[i];
      }
  }
  deferred_post_filenames[deferred_post_count++] = strdup(fn);
  log_msg( LOG_DEBUG, "deferred post of %s (count=%d) \n", fn, deferred_post_count );
}



void srshim_initialize(const char* progname) 
{

  static int config_read = 0;
  char *setstr;
  int finalize_good;


  if (sr_c) return;
  //log_msg( LOG_CRITICAL, "FIXME srshim_initialize %s\n", progname);

  setstr = getenv( "SR_POST_CONFIG" ) ;

  if ( setstr == NULL )
      return;

  //log_msg( LOG_CRITICAL, "FIXME srshim_initialize 2 %s setstr=%p\n", progname, setstr);

   // skip many FD to try to avoid stepping over stdout stderr, for logs & broker connection.
   if ( config_read == 0 ) 
   {
       setstr = strdup(setstr);
       sr_config_init(&sr_cfg,progname);
       config_read = sr_config_read(&sr_cfg,setstr,1,1);
       free(setstr);
       if (!config_read) goto RET;
   }

   if (!close_init_done) {
         close_fn_ptr = (close_fn) dlsym(RTLD_NEXT, "close");
         close_init_done = 1;
   }

   /* FIXME: since action is *foreground*, no separate log file will be set up.
        worry that if we ever use a log file, then there might be a
        conflict where the log file uses one of the standard file descriptors.
    */
   finalize_good = sr_config_finalize( &sr_cfg, 0 );

   if ( !finalize_good ) goto RET;

   sr_c = sr_context_init_config(&sr_cfg, 1);

RET:
   errno=0;
}


void srshim_connect() 
{
  if (!sr_connected) {


     sr_c = sr_context_connect( sr_c );
     sr_connected=1;

     errno=0;
  }

}


void srshim_realpost(const char *path) 
/*
  post using initialize sr_ context.

 */
{
  struct sr_mask_t *mask; 
  struct stat sb;
  int statres;
  char *s;
  char rn[PATH_MAX+1];
  char fn[PATH_MAX+1];
  char fnreal[PATH_MAX+1];

  //log_msg( LOG_CRITICAL, "FIXME realpost PATH %s src=%p\n", path, sr_c);

  if (!path || !sr_c) return;
 
  //log_msg( LOG_CRITICAL, "FIXME realpost 2 PATH %s\n", path);

  statres = lstat( path, &sb ) ;

  if ( !S_ISREG(sb.st_mode) && !S_ISLNK(sb.st_mode) ) 
     return;

  strcpy( fn, path );

  if (sr_cfg.realpath || sr_cfg.realpath_filter)
  {
      if (!statres) 
      {
          /* realpath of a link might result in a file or directory
             the stat must be reassigned
           */
          realpath( path, fnreal );
          statres = lstat( fnreal, &sb ) ;
      } else {
          /* If the stat failed, assume ENOENT (normal for removal or move), do realpath the directory containing the entry.
             then add the filename onto the that.
           */
          strcpy( rn, path );
          s=rindex( rn, '/' );
          *s='\0';
          s++;
          if ( realpath( rn, fnreal ) )
          {
              strcat( fnreal, "/" );
              strcat( fnreal, s );
          } else {
              strcpy( fnreal, path );
          }
      }
  }

  if ( sr_cfg.realpath ) strcpy( fn, fnreal );

  if ( sr_cfg.realpath_filter) {
     mask = isMatchingPattern(&sr_cfg, fnreal);
  } else {
     mask = isMatchingPattern(&sr_cfg, fn);
  }

  if ( (mask && !(mask->accepting)) || (!mask && !(sr_cfg.accept_unmatched)) )
  { //reject.
      log_msg( LOG_DEBUG, "mask: %p, mask->accepting=%d accept_unmatched=%d\n", 
            mask, mask->accepting, sr_cfg.accept_unmatched );
      if (sr_cfg.debug) log_msg( LOG_DEBUG, "sr_%s rejected 2: %s\n", sr_cfg.progname, fn );
      return;
  }

  if( sr_c->cfg->defer_posting_to_exit ) 
  {
     defer_post(fn);
     return;
  }

  srshim_connect();

  if ( statres )  {
      sr_post( sr_c, fn, NULL );
      return;
  }

  /* if it is a link, sr_post uses the path of the link...  */

  if (S_ISLNK(sb.st_mode))  {
      strcpy( fn, path );
  }
 
  sr_post( sr_c, fn, &sb );

}


static int in_librshim_already_dammit = 0;

int shimpost( const char *path, int status )
{
    char *cwd=NULL;
    char *real_path=NULL;


    if (in_librshim_already_dammit) return(status);

    in_librshim_already_dammit=1;
    if (!status) 
    {
       srshim_initialize( "srshim" );
       if (path[0] == '/' )
       {
          if (getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG absolute shimpost %s, status=%d\n", path, status );
          srshim_realpost( path );
       } else {
          cwd = get_current_dir_name();
          real_path = (char*)malloc( strlen(cwd) + strlen(path) + 3 );
          //getwd(real_path);
          strcpy(real_path,cwd);
          strcat(real_path,"/");
          strcat(real_path,path);
          if (getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG relative shimpost %s status=%d\n", real_path, status );
          srshim_realpost( real_path );
          free(real_path);
          free(cwd);
       }
    }
    in_librshim_already_dammit=0;

    clerror(status);
    return(status);
}


static int truncate_init_done = 0;
typedef int  (*truncate_fn) (const char*,off_t length);
static truncate_fn truncate_fn_ptr = truncate;

int truncate(const char *path, off_t length) 
{
    int status;

    if (!truncate_init_done) {
        truncate_fn_ptr = (truncate_fn) dlsym(RTLD_NEXT, "truncate");
        truncate_init_done = 1;
    }
    status = truncate_fn_ptr(path,length);

    if (in_librshim_already_dammit) return(status);

    //clerror(status);
    if ( status == -1) return status;

    if ( !strncmp(path,"/dev/", 5) ) return(status);
    if ( !strncmp(path,"/proc/", 6) ) return(status);

    return(shimpost(path, status));

}




static int symlink_init_done = 0;
typedef int  (*symlink_fn) (const char*,const char*);
static symlink_fn symlink_fn_ptr = symlink;

int symlink(const char *target, const char* linkpath) 
{
    int status;

    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG symlink %s %s\n", target, linkpath );
    if (!symlink_init_done) {
        symlink_fn_ptr = (symlink_fn) dlsym(RTLD_NEXT, "symlink");
        symlink_init_done = 1;
    }
    status = symlink_fn_ptr(target,linkpath);
    if (in_librshim_already_dammit) return(status);

    clerror(status);
    if ( status == -1) return status;

    if ( !strncmp(linkpath,"/dev/", 5) ) return(status);
    if ( !strncmp(linkpath,"/proc/", 6) ) return(status);

    return(shimpost(linkpath, status));
}



static int unlinkat_init_done = 0;
typedef int  (*unlinkat_fn) (int dirfd, const char*, int flags);
static unlinkat_fn unlinkat_fn_ptr = unlinkat;

int unlinkat(int dirfd, const char *path, int flags) 
{
    int status;
    char fdpath[PATH_MAX+1];
    char real_path[PATH_MAX+1];
    char *real_return;

    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG unlinkat %s dirfd=%i\n", path, dirfd );
    if (!unlinkat_init_done) {
        unlinkat_fn_ptr = (unlinkat_fn) dlsym(RTLD_NEXT, "unlinkat");
        unlinkat_init_done = 1;
    }

    status = unlinkat_fn_ptr(dirfd, path, flags);
    if (in_librshim_already_dammit) return(status);
    clerror(status);
    if ( status == -1) return status;

    if ( dirfd == AT_FDCWD ) 
       return(shimpost(path,status));
    
    snprintf( fdpath, 32, "/proc/self/fd/%d", dirfd );
    real_return = realpath(fdpath, real_path);
    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG unlinkat relative directory %s real_return=%p\n", fdpath, real_return );
    strcat(real_path,"/");
    strcat(real_path,path);

    clerror(status);
    if (!real_return) return(status);

    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG unlinkat realpath %s\n", real_path );

    return(shimpost(real_path,status));
}

static int unlink_init_done = 0;
typedef int  (*unlink_fn) (const char*);
static unlink_fn unlink_fn_ptr = unlink;

int unlink(const char *path) 
{
    int status;

    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG unlink %s\n", path );
    if (!unlink_init_done) 
    {
        unlink_fn_ptr = (unlink_fn) dlsym(RTLD_NEXT, "unlink");
        unlink_init_done = 1;
    }
    status = unlink_fn_ptr(path);
    if (in_librshim_already_dammit) return(status);

    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG unlink 2 %s status=%d\n", path, status );

    if ( status == -1) return status;

    if ( !strncmp(path,"/dev/", 5) ) 
    {
        clerror(status);
        return(status);
    }

    return(shimpost(path,status));
}


static int link_init_done = 0;
typedef int  (*link_fn) (const char*,const char*);
static link_fn link_fn_ptr = link;

static int linkat_init_done = 0;
typedef int  (*linkat_fn) (int, const char*, int, const char *, int flags);
static linkat_fn linkat_fn_ptr = linkat;

static int renameat_init_done = 0;
typedef int  (*renameat_fn) (int, const char*, int, const char*);
static renameat_fn renameat_fn_ptr = NULL;

static int renameat2_init_done = 0;
typedef int  (*renameat2_fn) (int, const char*, int, const char*, unsigned int);
static renameat2_fn renameat2_fn_ptr = NULL;

int renameorlink(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags, int link)
/*
  The real implementation of all renames.
 */
{
    int status;
    char fdpath[32];
    char real_path[PATH_MAX+1];
    char *real_return;
    char oreal_path[PATH_MAX+1];
    char *oreal_return;

    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG renameorlink %s %s\n", oldpath, newpath );

    if (!renameat2_init_done) 
    {
        renameat2_fn_ptr = (renameat2_fn) dlsym(RTLD_NEXT, "renameat2");
        renameat2_init_done = 1;
    }
    if (!renameat_init_done) 
    {
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

    if (link)
    {
       if (linkat_fn_ptr) 
          status = linkat_fn_ptr(olddirfd, oldpath, newdirfd, newpath, flags);
       else if (link_fn_ptr && !flags )
          status = link_fn_ptr(oldpath, newpath);
       else {
          log_msg( LOG_ERROR, "SR_SHIMDEBUG renameorlink could not identify real entry point for link\n" );
       }
    } else {
       if (renameat2_fn_ptr) 
          status = renameat2_fn_ptr(olddirfd, oldpath, newdirfd, newpath, flags);
       else if (renameat_fn_ptr && !flags )
          status = renameat_fn_ptr(olddirfd, oldpath, newdirfd, newpath);
       else {
          log_msg( LOG_ERROR, "SR_SHIMDEBUG renameorlink could not identify real entry point for renameat\n" );
          return(-1);
       }
    }
    if (in_librshim_already_dammit) return(status);

    if (status == -1) 
    {
         if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG renameorlink %s %s failed, no post\n", oldpath, newpath );
         return(status);
    }

    srshim_initialize("srshim");

    clerror(status);
    if (!sr_c) return(status);

    if ( olddirfd == AT_FDCWD ) 
    {
       strcpy(oreal_path,oldpath);
    } else {
       snprintf( fdpath, 32, "/proc/self/fd/%d", olddirfd );
       oreal_return = realpath(fdpath, oreal_path);
       if (oreal_return) 
       {
         log_msg( LOG_WARNING, "srshim renameorlink could not obtain real_path for olddir=%s failed, no post\n", fdpath );
         clerror(status);
         return(status);
       }
       strcat( oreal_path, "/" );
       strcat( oreal_path, oldpath );
    }

    if ( newdirfd == AT_FDCWD ) 
    {
       strcpy(real_path,newpath);
    } else {
       snprintf( fdpath, 32, "/proc/self/fd/%d", newdirfd );
       real_return = realpath(fdpath, real_path);
       if (real_return) 
       {
         log_msg( LOG_WARNING, "srshim renameorlink could not obtain real_path for newdir=%s failed, no post\n", fdpath );
         clerror(status);
         return(status);
       }
       strcat( real_path, "/" );
       strcat( real_path, newpath );
    }
    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG renameorlink sr_c=%p, oreal_path=%s, real_path=%s\n", 
            sr_c, oreal_path, real_path );

    srshim_connect();

    sr_post_rename( sr_c, oreal_path, real_path );

    clerror(status);
    return(status);

}

static int dup2_init_done = 0;
typedef int (*dup2_fn) ( int, int  );
static dup2_fn dup2_fn_ptr = dup2;

int dup2(int oldfd, int newfd )
{   
    int  fdstat;
    char fdpath[32];
    char real_path[PATH_MAX+1];
    char *real_return;
    int  status;

    if (getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG dup2 oldfd %d newfd %d\n",oldfd,newfd );

    if (!dup2_init_done) {
        dup2_fn_ptr = (dup2_fn) dlsym(RTLD_NEXT, "dup2");
        dup2_init_done = 1;
        if (getenv("SR_POST_READS"))
           srshim_initialize( "srshim" );
    }

    errno=0;

    if (in_librshim_already_dammit  || ( oldfd == newfd )) {
         //if (getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG dup2 NO POST oldfd = newfd \n" );
         return dup2_fn_ptr(oldfd, newfd);
    }

    fdstat = fcntl(newfd, F_GETFL);

    if ( fdstat == -1) 
    {
         //if (getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG dup2 NO POST not valid fd !\n" );
         errno=0;
         return dup2_fn_ptr(oldfd, newfd);
    }

    if ( (fdstat & O_ACCMODE) == O_RDONLY  && ( !sr_c || !( SR_READ & sr_c->cfg->events ) ) )
    {
         //if (getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG dup2 NO POST read mode !\n" );
         errno=0;
         return dup2_fn_ptr(oldfd, newfd);
    }

    snprintf(fdpath, 32, "/proc/self/fd/%d", newfd);
    real_return = realpath(fdpath, real_path);

    if ( !real_return )
    {
         //if (getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG dup2 NO POST no path from fd !\n" );
         errno=0;
         return dup2_fn_ptr(oldfd, newfd);
    }

    if ( !strncmp(real_path,"/dev/", 5) || !strncmp(real_path,"/proc/", 6) ) 
    {
         //if (getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG dup2 NO POST path device or proc !\n" );
         errno=0;
         return dup2_fn_ptr(oldfd, newfd);
    }

    if (!getenv("SR_POST_READS"))
       srshim_initialize( "srshim" );

    status = dup2_fn_ptr (oldfd, newfd);
    if ( status == -1 ) return status;

    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG dup2 posting %s status=%d\n", real_path, status );

    // because shimpost posts when:    if (!status)
    // we use a tmpstatus and call shimpost with status=0

    shimpost(real_path, 0) ;

    clerror(status);

    return status;
}

static int dup3_init_done = 0;
typedef int (*dup3_fn) ( int, int, int );
static dup3_fn dup3_fn_ptr = dup3;

int dup3(int oldfd, int newfd, int flags )
{   
    int  fdstat;
    char fdpath[32];
    char real_path[PATH_MAX+1];
    char *real_return;
    int  status;

    if (getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG dup3 oldfd %d newfd %d flags %d\n",oldfd,newfd,flags );

    if (!dup3_init_done) {
        dup3_fn_ptr = (dup3_fn) dlsym(RTLD_NEXT, "dup3");
        dup3_init_done = 1;
        if (getenv("SR_POST_READS"))
           srshim_initialize( "srshim" );
    }

    if (in_librshim_already_dammit  || ( oldfd == newfd )) {
         //if (getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG dup3 NO POST oldfd = newfd \n" );
         errno=0;
         return dup3_fn_ptr(oldfd, newfd, flags);
    }

    fdstat = fcntl(newfd, F_GETFL);

    if ( fdstat == -1) {
         //if (getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG dup3 NO POST not valid fd !\n" );
         errno=0;
         return dup3_fn_ptr(oldfd, newfd, flags);
    }

    if ( (fdstat & O_ACCMODE) == O_RDONLY  && ( !sr_c || !( SR_READ & sr_c->cfg->events ) ) ){
         //if (getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG dup3 NO POST read mode !\n" );
         errno=0;
         return dup3_fn_ptr(oldfd, newfd, flags);
    }

    snprintf(fdpath, 32, "/proc/self/fd/%d", newfd);
    real_return = realpath(fdpath, real_path);

    if ( !real_return ){
         //if (getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG dup3 NO POST no path from fd !\n" );
         errno=0;
         return dup3_fn_ptr(oldfd, newfd, flags);
    }

    if ( !strncmp(real_path,"/dev/", 5) || !strncmp(real_path,"/proc/", 6) ) {
         //if (getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG dup3 NO POST path device or proc !\n" );
         errno=0;
         return dup3_fn_ptr(oldfd, newfd, flags);
    }

    if (!getenv("SR_POST_READS"))
       srshim_initialize( "srshim" );

    errno=0;
    status = dup3_fn_ptr (oldfd, newfd, flags);
    if ( status == -1 ) return status;

    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG dup3 posting %s %d\n", real_path, status );

    // because shimpost posts when:    if (!status)
    // we use a tmpstatus and call shimpost with status=0

    shimpost(real_path, 0) ;

    clerror(status);
    return status;
}

//void exit(int status) __attribute__((noreturn));

static int exit_init_done = 0;
typedef void (*exit_fn)( int ) __attribute__((noreturn));
static exit_fn exit_fn_ptr = exit;

void exit(int status) 
{   
    int  fdstat;
    struct stat sb;
    int statres;
    char fdpath[500];
    int  fdpathlen;
    char real_path[PATH_MAX+1];
    char *real_return;
    int  fd;
    int  found;
    DIR  *fddir=NULL;
    struct dirent *fdde;
    char **parent_files_open = NULL;
    int  last_pfo = 0;
    int  max_pfo = 1;
    

    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG exit 0, context=%p\n", sr_c );
    if (!exit_init_done) {
        exit_fn_ptr = (exit_fn) dlsym(RTLD_NEXT, "exit");
        exit_init_done = 1;
    }

    if ( !getenv( "SR_POST_CONFIG" ) || in_librshim_already_dammit) exit_fn_ptr(status);


    // build an array of the file names currently opened by the parent process.
    
    parent_files_open = (char**)malloc( sizeof(char*) );

    snprintf( fdpath, 499, "/proc/%d/fd", getppid() );
    fddir = opendir( fdpath );
    
    while ( (fdde = readdir( fddir )) ) 
    {
        fdpathlen = readlinkat( dirfd(fddir), fdde->d_name, fdpath, 500 );

        if ( fdpathlen < 0 )
            continue;

        fdpath[fdpathlen]='\0';

        if (!strncmp( fdpath, "/dev/", 5 )) 
            continue;

        if (!strncmp( fdpath, "/proc/", 6 )) 
            continue;

        parent_files_open[ last_pfo++ ] = strdup( fdpath ); 

        if ( last_pfo >= max_pfo )
        {
           char **save_pfo = parent_files_open;
           max_pfo *= 2;
           parent_files_open = (char**)malloc( max_pfo * sizeof(char*) );
           for (int i = 0; i < last_pfo ; i++ ) 
                parent_files_open[i] = save_pfo[i];
           free(save_pfo);
        }

    }
    closedir(fddir);


    // In the current process, find files which are not opened by the parent
    // that need posting.

    fddir = opendir( "/proc/self/fd" );

    while ( (fdde = readdir( fddir )) ) 
    {
        if ( fdde->d_name[0] == '.' ) continue;

        fd = atoi( fdde->d_name );
        fdstat = fcntl(fd, F_GETFL);

        if ( fdstat == -1)
            continue;

        if ( ((fdstat & O_ACCMODE) == O_RDONLY ) && ( !sr_c || !( SR_READ & sr_c->cfg->events ) ) )
           continue;

        snprintf( fdpath, 499, "/proc/self/fd/%s", fdde->d_name );
        real_return = realpath(fdpath, real_path);

       if ( (!real_return) || ( !strncmp(real_path,"/dev/", 5) ) || ( !strncmp(real_path,"/proc/", 6) ) )
           continue;

       found=0;
       for( int i = 0; ( i < last_pfo ) ; i++ )
          if ( !strcmp(real_path,parent_files_open[i]) ) 
          {
              found=1;
              break;
          }

       if (found) 
           continue;

       fsync(fd); // ensure data is flushed to disk before post occurs.

       if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG exit posting %s\n", real_path );

       shimpost(real_path, status);
    }
    closedir(fddir);

    /* execute deferred posts, FIXME: embarrasing n**2 algo, should do better later */
    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "deferred posting.\n" );

    for (int i=0; i < deferred_post_count; i++ )
    {
        found=0;
        for(int j=0; j < last_pfo ; j++ )
        {
          if( !strcmp(deferred_post_filenames[i],parent_files_open[j]) )
          {
            found = 1;
            break;
          }
        }

        if (!found) 
        {
           srshim_connect();

           statres = lstat( deferred_post_filenames[i], &sb );

           if (statres) 
           {
               sr_post( sr_c, deferred_post_filenames[i], NULL );
           } else {
               if (S_ISLNK(sb.st_mode))  
               {
                  statres = readlink(deferred_post_filenames[i], real_path, PATH_MAX);
                  if (statres)              
                  {
                     real_path[statres]='\0'; 
                     sr_post( sr_c, real_path, &sb );
                  }
               } else {
                  sr_post( sr_c, deferred_post_filenames[i], &sb );
               }
           }
        }
    }


    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG exit closing context %p\n", sr_c );
    if (sr_c) sr_context_close(sr_c);

    free(sr_c);
    sr_c=NULL;

    // cleaning up parent file open list.
    for( int i = 0; ( i < last_pfo ) ; i++ )
          free(parent_files_open[i]);
    free(parent_files_open);

    //FIXME: free the parent file open array...

    //sr_config_free(&sr_cfg);

    // after this point things get closed, so cannot reliably post.
    // turn off libsrshim functionality.

    in_librshim_already_dammit=1;

    // do it for real.
    exit_fn_ptr(status);
}


int link(const char *target, const char* linkpath) 
{
    if (getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG link %s %s\n", target, linkpath );
    return( renameorlink(AT_FDCWD, target, AT_FDCWD, linkpath, 0, 1 ));
}

int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags) 
{
    if ( getenv("SR_SHIMDEBUG")) 
         fprintf( stderr, "SR_SHIMDEBUG linkat olddirfd=%d, oldname=%s newdirfd=%d newname=%s flags=%d\n", 
            olddirfd, oldpath, newdirfd, newpath, flags );
    return( renameorlink(olddirfd, oldpath, newdirfd, newpath, flags, 1 ));
}

int rename(const char *oldpath, const char *newpath)
{
    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG rename %s %s\n", oldpath, newpath );

    return( renameorlink(AT_FDCWD, oldpath, AT_FDCWD, newpath, 0, 0 ));
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG renameat %s %s\n", oldpath, newpath );

    return( renameorlink(olddirfd, oldpath, newdirfd, newpath, 0, 0 ));
}

int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags)
{
    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG renameat2 %s %s\n", oldpath, newpath );

    return( renameorlink(olddirfd, oldpath, newdirfd, newpath, flags, 0 ));
}



static int sendfile_init_done = 0;
typedef ssize_t  (*sendfile_fn) (int, int, off_t *, size_t);
static sendfile_fn sendfile_fn_ptr = NULL;

ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
    ssize_t status;
    char fdpath[32];
    char real_path[PATH_MAX+1];
    char *real_return;

    if (!sendfile_init_done) 
    {
        sendfile_fn_ptr = (sendfile_fn) dlsym(RTLD_NEXT, "sendfile");
        sendfile_init_done = 1;
    }
    status = sendfile_fn_ptr( out_fd, in_fd, offset, count );
    if ( status == -1 ) return status;
    if (in_librshim_already_dammit) return(status);

    snprintf( fdpath, 32, "/proc/self/fd/%d", out_fd );
    real_return = realpath(fdpath, real_path);

    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG sendfile to %s\n", real_path );

    clerror(status);
    if (!real_return) return(status);
    if ( !strncmp(real_path,"/dev/", 5) ) return(status);
    if ( !strncmp(real_path,"/proc/", 6) ) return(status);

    shimpost(real_path,0);

    clerror(status);
    return(status);
}



static int copy_file_range_init_done = 0;
typedef ssize_t  (*copy_file_range_fn) (int, loff_t *, int, loff_t *, size_t, unsigned int);
static copy_file_range_fn copy_file_range_fn_ptr = NULL;

ssize_t copy_file_range(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags)
{
    ssize_t status;
    char fdpath[32];
    char real_path[PATH_MAX+1];
    char *real_return;

    if (!copy_file_range_init_done) 
    {
        copy_file_range_fn_ptr = (copy_file_range_fn) dlsym(RTLD_NEXT, "copy_file_range");
        copy_file_range_init_done = 1;
    }
    status = copy_file_range_fn_ptr( fd_in, off_in, fd_out, off_out, len, flags );
    if (in_librshim_already_dammit) return(status);

    snprintf( fdpath, 32, "/proc/self/fd/%d", fd_out );
    real_return = realpath(fdpath, real_path);

    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG copy_file_range to %s\n", real_path );

    if (!real_return) return(status);
    if ( !strncmp(real_path,"/dev/", 5) ) return(status);
    if ( !strncmp(real_path,"/proc/", 6) ) return(status);

    shimpost(real_path,0);

    clerror(status);
    return(status);
}


int close(int fd) 
{

    int fdstat;
    char fdpath[32];
    char real_path[PATH_MAX+1];
    char *real_return;
    int status;

    if (!close_init_done) {
        close_fn_ptr = (close_fn) dlsym(RTLD_NEXT, "close");
        close_init_done = 1;
        if (getenv("SR_POST_READS"))
           srshim_initialize( "srshim" );
    }
    if (in_librshim_already_dammit) return close_fn_ptr(fd);

    fdstat = fcntl(fd, F_GETFL);

    if ( fdstat == -1) {
         //if (getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG close NO POST not valid fd !\n" );
         errno=0;
         return close_fn_ptr(fd);
    }

    if ( ((fdstat & O_ACCMODE) == O_RDONLY ) && ( !sr_c || !( SR_READ & sr_c->cfg->events ) ) )
    {
         errno=0;
         return close_fn_ptr(fd);
    }
    snprintf(fdpath, 32, "/proc/self/fd/%d", fd);
    real_return = realpath(fdpath, real_path);

    if (!getenv("SR_POST_READS"))
       srshim_initialize( "srshim" );

    errno=0;
    status = close_fn_ptr(fd);
    if ( status == -1 ) return status;

    clerror(status);
    if (!real_return  ) return status;

    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG close %s fd=%d\n", real_path, fd );

    if ( !strncmp(real_path,"/dev/", 5) ) 
    { 
        clerror(status);
        return(status);
    }

    if ( !strncmp(real_path,"/proc/", 6) ) 
    { 
        clerror(status);
        return(status);
    }

    return shimpost(real_path, status) ;
}

static int fclose_init_done = 0;
typedef int  (*fclose_fn) (FILE *);
static fclose_fn fclose_fn_ptr = fclose;

int fclose(FILE *f) 
{

    int fd;
    int fdstat;
    char fdpath[32];
    char real_path[PATH_MAX+1];
    char *real_return;
    int status;

    if (!fclose_init_done) {
        fclose_fn_ptr = (fclose_fn) dlsym(RTLD_NEXT, "fclose");
        fclose_init_done = 1;
        if (getenv("SR_POST_READS"))
           srshim_initialize( "srshim" );
    }
    if (in_librshim_already_dammit) return fclose_fn_ptr(f);

    fd = fileno(f);
    if (fd == -1) 
    {
         clerror(fd);
         return fclose_fn_ptr(f);
    }
 
    fdstat = fcntl(fd, F_GETFL);

    //if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG fclose %p fd=%i starting\n", f, fdstat );

    if ( fdstat == -1) 
    {
         //if (getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG fclose NO POST not valid fd !\n" );
         errno=0;
         return fclose_fn_ptr(f);
    }

    if ( ((fdstat & O_ACCMODE) == O_RDONLY ) && ( !sr_c || !( SR_READ & sr_c->cfg->events ) ) )
    {
         //if (getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG fclose NO POST read-only. \n" );
         errno=0;
         return fclose_fn_ptr(f);
    }
  
    snprintf(fdpath, 32, "/proc/self/fd/%d", fd);
    real_return = realpath(fdpath, real_path);
    status = fclose_fn_ptr(f);
    clerror(status);

    if ( status != 0) return status;
    if (!real_return) return(status);

    if ( !strncmp(real_path,"/dev/", 5) ) 
    { 
        clerror(status);
        return(status);
    }

    if ( !strncmp(real_path,"/proc/", 6) ) 
    { 
        clerror(status);
        return(status);
    }


    if ( getenv("SR_SHIMDEBUG")) fprintf( stderr, "SR_SHIMDEBUG fclose %p %s status=%d\n", f, real_path, status );

    return shimpost(real_path, status) ;
}

