

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>
#include <linux/limits.h>

#include "sr_util.h"

time_t  logbase;
int     logfd = STDERR_FILENO;
char    logfn[PATH_MAX];
char    logfn_ts[PATH_MAX];
int     loglevel = LOG_INFO;
int     logmode = 0600;
int     logrotate = 5;
int     logrotate_interval = 24*60*60;

struct  timespec ts;
struct  tm tc; /* ie Time_Calendar */

struct  logfn_tab_t ltab;

void log_set_fnts();

#ifndef SR_DEBUG_LOGS
void log_msg(int prio, const char *format, ...)
{
    char *level;
    va_list ap;

    if (prio > loglevel) return;

    switch (prio) {
    case LOG_DEBUG    : level = "DEBUG";    break;
    case LOG_INFO     : level = "INFO";     break;
    case LOG_WARNING  : level = "WARNING";  break;
    case LOG_ERROR    : level = "ERROR";    break;
    case LOG_CRITICAL : level = "CRITICAL"; break;
    default           : level = "UNKNOWN";
    }

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tc);

    /* log rotation */
    if ( (logfd != STDERR_FILENO) && ((ts.tv_sec-logbase) > logrotate_interval) ) {
        logbase = ts.tv_sec;

        close(logfd);
        log_set_fnts();
        logfd = open(logfn_ts, O_WRONLY|O_CREAT|O_APPEND, logmode);

        /* delete outdated logs */
        if (logrotate > 0) {
            if (ltab.fns[ltab.i]) {
                remove(ltab.fns[ltab.i]);
                free(ltab.fns[ltab.i]);
                ltab.fns[ltab.i] = NULL;
            }
            ltab.fns[ltab.i] = strdup(logfn_ts);
            ltab.i = (ltab.i + 1) % ltab.size;
        }
    }

    /* logging */
    dprintf(logfd, "%04d-%02d-%02d %02d:%02d:%02d,%03d [%s] ",
            tc.tm_year+1900, tc.tm_mon+1, tc.tm_mday,
            tc.tm_hour, tc.tm_min, tc.tm_sec, (int)(ts.tv_nsec/1e6), level);

    va_start(ap, format);
    vdprintf(logfd, format, ap);
    va_end(ap);
}
#endif

void log_setup(const char *fn, mode_t mode, int level, int lr, int lri )
{
#ifndef SR_DEBUG_LOGS
    strcpy(logfn, fn);
    logmode = mode;
    logrotate = lr;
    logrotate_interval = lri;
    loglevel = level;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tc);
    logbase = ts.tv_sec;

    log_set_fnts();
    logfd = open(logfn_ts, O_WRONLY|O_CREAT|O_APPEND, logmode);

    if (logrotate > 0) {
        ltab.fns = (char **) malloc(sizeof(char *)*logrotate);
        for(ltab.i = 0; ltab.i < logrotate; ++ltab.i)
            ltab.fns[ltab.i] = NULL;
        ltab.i = 0;
        ltab.size = logrotate;

        ltab.fns[ltab.i] = strdup(logfn_ts);
        ltab.i = (ltab.i + 1) % ltab.size;
    }
#endif
}

/* global accessor for loglevel, ugly but better than using a global variable... */
void set_loglevel(int level)
{
    loglevel = level;
}

void log_cleanup()
{
#ifndef SR_DEBUG_LOGS
    /* (logfd != STDERR_FILENO) <> log_setup called previously */
    if (logfd != STDERR_FILENO) {
        close(logfd);
        logfd = STDERR_FILENO;

        if (logrotate > 0) {
            for(ltab.i = 0; ltab.i < logrotate; ++ltab.i)
                if (ltab.fns[ltab.i])
                    free(ltab.fns[ltab.i]);
            free(ltab.fns);
            ltab.i = 0;
            ltab.size = 0;
        }
    }
#endif
}

void log_set_fnts()
{
    char *p;
    char b[PATH_MAX];

    strcpy(b, logfn);
    p = b + strlen(logfn);

    *p++ = '.';

    int lri = logrotate_interval;
    if        ( !(lri % (24*60*60)) ) {
        /* daily resolution */
        strcpy(p, "%04d-%02d-%02d");
        sprintf(logfn_ts, b, tc.tm_year+1900, tc.tm_mon+1, tc.tm_mday);

    } else if ( !(lri % (60*60)) ) {
        /* hourly resolution */
        strcpy(p, "%04d-%02d-%02d_%02d");
        sprintf(logfn_ts, b, tc.tm_year+1900, tc.tm_mon+1, tc.tm_mday, tc.tm_hour);

    } else if ( !(lri % (60)) ) {
        /* minute resolution */
        strcpy(p, "%04d-%02d-%02d_%02d-%02d");
        sprintf(logfn_ts, b, tc.tm_year+1900, tc.tm_mon+1, tc.tm_mday, tc.tm_hour, tc.tm_min);

    } else {
        /* second resolution */
        strcpy(p, "%04d-%02d-%02d_%02d-%02d-%02d");
        sprintf(logfn_ts, b, tc.tm_year+1900, tc.tm_mon+1, tc.tm_mday, tc.tm_hour, tc.tm_min, tc.tm_sec);
    }
}

/* utf8 check, https://stackoverflow.com/questions/1031645/how-to-detect-utf-8-in-plain-c */
int is_utf8(const char * string)
{
    if(!string)
        return 0;
    const unsigned char * bytes = (const unsigned char *)string;
    while(*bytes)
    {
        if( (// ASCII
             // use bytes[0] <= 0x7F to allow ASCII control characters
                bytes[0] == 0x09 ||
                bytes[0] == 0x0A ||
                bytes[0] == 0x0D ||
                (0x20 <= bytes[0] && bytes[0] <= 0x7E)
            )
        ) {
            bytes += 1;
            continue;
        }
        if( (// non-overlong 2-byte
                (0xC2 <= bytes[0] && bytes[0] <= 0xDF) &&
                (0x80 <= bytes[1] && bytes[1] <= 0xBF)
            )
        ) {
            bytes += 2;
            continue;
        }
        if( (// excluding overlongs
                bytes[0] == 0xE0 &&
                (0xA0 <= bytes[1] && bytes[1] <= 0xBF) &&
                (0x80 <= bytes[2] && bytes[2] <= 0xBF)
            ) ||
            (// straight 3-byte
                ((0xE1 <= bytes[0] && bytes[0] <= 0xEC) ||
                    bytes[0] == 0xEE ||
                    bytes[0] == 0xEF) &&
                (0x80 <= bytes[1] && bytes[1] <= 0xBF) &&
                (0x80 <= bytes[2] && bytes[2] <= 0xBF)
            ) ||
            (// excluding surrogates
                bytes[0] == 0xED &&
                (0x80 <= bytes[1] && bytes[1] <= 0x9F) &&
                (0x80 <= bytes[2] && bytes[2] <= 0xBF)
            )
        ) {
            bytes += 3;
            continue;
        }
        if( (// planes 1-3
                bytes[0] == 0xF0 &&
                (0x90 <= bytes[1] && bytes[1] <= 0xBF) &&
                (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
                (0x80 <= bytes[3] && bytes[3] <= 0xBF)
            ) ||
            (// planes 4-15
                (0xF1 <= bytes[0] && bytes[0] <= 0xF3) &&
                (0x80 <= bytes[1] && bytes[1] <= 0xBF) &&
                (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
                (0x80 <= bytes[3] && bytes[3] <= 0xBF)
            ) ||
            (// plane 16
                bytes[0] == 0xF4 &&
                (0x80 <= bytes[1] && bytes[1] <= 0x8F) &&
                (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
                (0x80 <= bytes[3] && bytes[3] <= 0xBF)
            )
        ) {
            bytes += 4;
            continue;
        }
        return 0;
    }
    return 1;
}

void daemonize(int close_stdout)
/* 
   fork child,  parent then exits.  child returns with proper daemon prep done.
 */
{
     pid_t pid;
     pid_t sid;

     pid = fork();

     if ( pid < 0 )
     {
        log_msg( LOG_CRITICAL, "fork failed, cannot launch as daemon\n" );
        exit(1);
     }
     if ( pid > 0 )
     {
        fprintf( stderr, "parent exiting normally, rest is upto the child pid: %d\n", pid );
        exit(0);
     }
     // child processing.

     log_msg( LOG_DEBUG, "child daemonizing start\n" );
     sid = setsid();
     if (sid < 0)
     {  
        log_msg( LOG_WARNING, "daemonizing, setsid errord, failed to completely dissociate from login process\n" );
     } 

     if (logfd == 2)
     {
        log_msg( LOG_CRITICAL, "to run as daemon log option must be set.\n" );
        exit(1);
     }

     close(0); 
     if (close_stdout) 
     {
         close(1);
         dup2(logfd, STDOUT_FILENO);
     }
     close(2);
     dup2(logfd, STDERR_FILENO);

     log_msg( LOG_DEBUG, "child daemonizing complete.\n" );
}



/* size of buffer used to read the file content in calculating checksums.
 */
#define SUMBUFSIZE (4096*1024)

// SHA512 being the longest digest...
char sumstr[ SR_SUMSTRLEN ];

unsigned char sumhash[SR_SUMHASHLEN]; 


int get_sumhashlen( char algo )
{
  switch(algo) {
    case 'd' : case 'n' : 
        return(MD5_DIGEST_LENGTH+1);

    case '0': 
        return(4+1);

    case 'p' : case 's' : case 'L' : case 'R' : 
        return(SHA512_DIGEST_LENGTH+1);

    case 'z' :
        return(2);

    default: 
        return(0);
  }
}


char *set_sumstr( char algo, char algoz, const char* fn, const char* partstr, char *linkstr,
          unsigned long block_size, unsigned long block_count, unsigned long block_rem, unsigned long block_num 
     )
 /* 
   return a correct sumstring (assume it is big enough)  as per sr_post(7)
   algo = 
     '0' - no checksum, value is random. -> now same as N.
     'd' - md5sum of block.
     'n' - md5sum of filename (fn).
     'L' - now sha512 sum of link value.
     'p' - md5sum of filename (fn) + partstr.
     'R' - no checksum, value is random. -> now same as N.
     's' - sha512 sum of block.
     'z' - downstream should recalculate with algo that is argument.
   block starts at block_size * block_num, and ends 
  */
{
   MD5_CTX md5ctx;
   SHA512_CTX shactx;

   static int fd;
   static char buf[SUMBUFSIZE];
   long bytes_read ; 
   long how_many_to_read;
   const char *just_the_name=NULL;

   unsigned long start = block_size * block_num ;
   unsigned long end;
  
   end = start + ((block_num < (block_count -(block_rem!=0)))?block_size:block_rem) ;
 

   memset( sumhash, 0, SR_SUMHASHLEN );
   sumhash[0]=algo;

   /* xattr check for checksum caching optimization */
   struct stat attr;
   time_t      stat_mtime;
   char        cache_mtime[SR_TIMESTRLEN];

   stat(fn, &attr);
   stat_mtime = attr.st_mtime;

   memset(cache_mtime, 0, SR_TIMESTRLEN);
   // are xattrs set?
   if(getxattr(fn, "user.sr_mtime", cache_mtime, SR_TIMESTRLEN) > 0) {
        // is the checksum valid? (i.e. is (cache_mtime >= stat_mtime)? )
        if(sr_str2time(cache_mtime)->tv_sec >= stat_mtime) {
            memset(sumstr, 0, SR_SUMSTRLEN);
            getxattr(fn, "user.sr_sum", sumstr, SR_SUMSTRLEN);
            // is it the right checksum algorithm?
            if(algo == sumstr[0])
                return(sumstr);
        }
   }
   /* end of xattr check */

   switch (algo) {

   case '0' : 
       sprintf( sumstr, "%c,%03ld", algo, random()%1000 );
       break;

   case 'd' :
       MD5_Init(&md5ctx);

       // keep file open through repeated calls.
       //fprintf( stderr, "opening %s to checksum\n", fn );

       if ( ! (fd > 0) ) fd = open( fn, O_RDONLY );
       if ( fd < 0 ) 
       { 
           fprintf( stderr, "unable to read file for checksumming\n" );
           strcpy(sumstr+3,"deadbeef0");
           return(NULL);
       } 
       lseek( fd, start, SEEK_SET );
       //fprintf( stderr, "checksumming start: %lu to %lu\n", start, end );
       while ( start < end ) 
       {
           how_many_to_read= ( SUMBUFSIZE < (end-start) ) ? SUMBUFSIZE : (end-start) ;

           bytes_read=read(fd,buf, how_many_to_read );           
           if ( bytes_read > 0 ) 
           {
              MD5_Update(&md5ctx, buf, bytes_read );
              start += bytes_read;
           } else {
              fprintf( stderr, "error reading %s for MD5\n", fn );
              close(fd);
              fd=0;
              return(NULL);
           } 
       }

       // close fd, when end of file reached.
       if ((block_count == 1)  || ( end >= ((block_count-1)*block_size+block_rem))) 
       { 
             close(fd);
             fd=0;
       }

       MD5_Final(sumhash+1, &md5ctx);
       sr_hash2sumstr(sumhash);
       break;

   case 'n' :
       MD5_Init(&md5ctx);
       just_the_name = rindex(fn,'/')+1;
       if (!just_the_name) just_the_name=fn;
       MD5_Update(&md5ctx, just_the_name, strlen(just_the_name) );
       MD5_Final(sumhash+1, &md5ctx);
       sr_hash2sumstr(sumhash);
       break;
       
   case 'L' : // symlink case
        just_the_name=linkstr;       
        SHA512_Init(&shactx);
        SHA512_Update(&shactx, linkstr, strlen(linkstr) );
        SHA512_Final(sumhash+1, &shactx);
        sr_hash2sumstr(sumhash);
        break;

   case 'R' : // null, or removal.
        just_the_name = rindex(fn,'/')+1;
        if (just_the_name<(char*)2) just_the_name=fn;
        SHA512_Init(&shactx);
        SHA512_Update(&shactx, just_the_name, strlen(just_the_name) );
        SHA512_Final(sumhash+1, &shactx);
        sr_hash2sumstr(sumhash);
        break;

   case 'p' :
       SHA512_Init(&shactx);
       just_the_name = rindex(fn,'/')+1;
       if (just_the_name<(char*)2) just_the_name=fn;
       strcpy( buf, just_the_name);
       sprintf( buf , "%s%c,%lu,%lu,%lu,%lu", just_the_name, algo, block_size, block_count, block_rem, block_num );
       SHA512_Update(&shactx, buf, strlen(buf) );
       SHA512_Final(sumhash+1, &shactx);
       sr_hash2sumstr(sumhash);
       break;

   case 's' : 
       SHA512_Init(&shactx);

       // keep file open through repeated calls.
       if ( ! (fd > 0) ) fd = open( fn, O_RDONLY );
       if ( fd < 0 ) 
       { 
           fprintf( stderr, "unable to read file for SHA checksumming\n" );
           return(NULL);
       } 
       lseek( fd, start, SEEK_SET );
       //fprintf( stderr, "DBG checksumming start: %lu to %lu\n", start, end );
       while ( start < end ) 
       {
           how_many_to_read= ( SUMBUFSIZE < (end-start) ) ? SUMBUFSIZE : (end-start) ;

           bytes_read=read(fd,buf, how_many_to_read );           

            //fprintf( stderr, "checksumming how_many_to_read: %lu bytes_read: %lu\n", 
            //   how_many_to_read, bytes_read );

           if ( bytes_read >= 0 ) 
           {
              SHA512_Update(&shactx, buf, bytes_read );
              start += bytes_read;
           } else {
              fprintf( stderr, "error reading %s for SHA\n", fn );
              close(fd);
              fd=0;
              return(NULL);
           } 
       }

       // close fd, when end of file reached.
       if ((block_count == 1)  || ( end >= ((block_count-1)*block_size+block_rem))) 
       { 
             close(fd);
             fd=0;
       }
       SHA512_Final(sumhash+1, &shactx);
       sr_hash2sumstr(sumhash);
       break;

   case 'z':
       sumhash[1]=algoz;
       sumhash[2]='\0';
       sr_hash2sumstr(sumhash);
       break;

   default:
       fprintf( stderr, "sum algorithm %c unimplemented\n", algo );
       return(NULL);
   }

   /* xattr set for checksum caching optimization */
   // can we set xattrs? let's try and find out!
   setxattr(fn, "user.sr_sum", sumstr, strlen(sumstr), 0);
   char *t2s = sr_time2str(&attr.st_mtim);
   setxattr(fn, "user.sr_mtime", t2s, strlen(t2s), 0);
   // if the calls above fail, ignore and proceed
   /* end of xattr set */

   return(sumstr);
}

char nibble2hexchr( int i )

{
   unsigned char c =  (unsigned char)(i & 0xf);
   return( (char)((c < 10) ? ( c + '0' ) : ( c -10 + 'a' ) ));
}

int hexchr2nibble( char c )
 /* return ordinal value of digit assuming a character set that has a-f sequential in both lower and upper case.
    kind of based on ASCII, because numbers are assumed to be lower in collation than upper and lower case letters.
  */
{
    if ( c < ':' ) return(c - '0');
    if ( c < 'G' ) return(c - 'A' + 10);
    if ( c < 'g' ) return(c - 'a' + 10);
    return(-1);
}

unsigned char *sr_sumstr2hash( const char *s )
{
    int i;
    if (!s) return(NULL);
    memset( sumhash, 0, SR_SUMHASHLEN );
    sumhash[0]=s[0];

    if ( s[0] == 'z' ) 
    {
       sumhash[1] = s[2];
       return(sumhash);
    }
    
    for ( i=1; ( i < get_sumhashlen(s[0]) ) ; i++ )
    {
        sumhash[i] = (unsigned char)((hexchr2nibble(s[i<<1]) << 4) + hexchr2nibble(s[(i<<1)+1]));
    }
    return(sumhash);
}


char *sr_hash2sumstr( const unsigned char *h )
{
  int i;
  memset( sumstr, 0, SR_SUMSTRLEN );
  sumstr[0] = h[0];
  sumstr[1] = ',';

  if ( sumstr[0] == 'z' )
  {
      sumstr[2] = h[1];
      sumstr[3] = '\0';;
      return(sumstr); 
  }

  for(i=1; i < get_sumhashlen(h[0]); i++ )
  {
     sumstr[ i*2   ] = nibble2hexchr( h[i]>>4 );
     sumstr[ i*2+1 ] = nibble2hexchr( h[i] );
  }
  sumstr[2*i]='\0';
  return(sumstr);
}

static char time2str_result[SR_TIMESTRLEN];

char *sr_time2str( struct timespec *tin ) 
{
   /* turn a timespec into an 18 character sr_post(7) conformant time stamp string.
      if argument is NULL, then the string should correspond to the current system time.
    */
   struct tm s;
   time_t when;
   struct timespec ts;
   long nsec;
   char nsstr[30];
   int nsl;

   memset( &s, 0, sizeof(struct tm));
   memset( &ts, 0, sizeof(struct timespec));

   if ( tin ) {
     when = tin->tv_sec;
     nsec = tin->tv_nsec ;
   } else {
     clock_gettime( CLOCK_REALTIME , &ts);
     when = ts.tv_sec;
     nsec = ts.tv_nsec ;
   }

   if (nsec > 0)
   {
     nsstr[0]='\0';
     sprintf( nsstr, "%09ld", nsec );

     // remove trailing 0's, not relevant after a decimal place.
     nsl=strlen(nsstr)-1;
     while ( nsstr[nsl] == '0' ) 
     {
       nsstr[nsl]='\0';
       nsl--;
     }
   } else {
     strcpy( nsstr, "0" );
   }


   gmtime_r(&when,&s);
   /*                         YYYY  MM  DD  hh  mm  ss */
   sprintf( time2str_result, "%04d%02d%02d%02d%02d%02d.%s", s.tm_year+1900, s.tm_mon+1,
        s.tm_mday, s.tm_hour, s.tm_min, s.tm_sec, nsstr );
   return(time2str_result);
}

int ipow(int base, int exp)
/* all hail stack overflow: 
   https://stackoverflow.com/questions/101439/the-most-efficient-way-to-implement-an-integer-based-power-function-powint-int
 */
{
    int result = 1;
    while (exp)
    {
        if (exp & 1)
            result *= base;
        exp >>= 1;
        base *= base;
    }

    return result;
}

struct timespec ts;

struct timespec *sr_str2time( char *s )
  /* inverse of above: convert SR_TIMESTRLEN character string into a timespec.
    
   */
{
  struct tm tm;
  memset( &tm, 0, sizeof(struct tm));
  memset( &ts, 0, sizeof(struct timespec));
  int dl; // length of decimal string.

  strptime( s, "%Y%m%d%H%M%S", &tm);
  ts.tv_sec = timegm(&tm);
  
  dl = strlen(s+15); // how many digits after decimal point?
  ts.tv_nsec = atol(s+15) * ipow( 10, dl );
  return(&ts);
}


