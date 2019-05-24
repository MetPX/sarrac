
#ifndef SR_UTIL_H
#define SR_UTIL_H

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include <time.h>
#include <openssl/sha.h>

// log message severities.
#define LOG_DEBUG     (5)
#define LOG_INFO      (4)
#define LOG_WARNING   (3)
#define LOG_ERROR     (2)
#define LOG_CRITICAL  (1)

#ifdef SR_DEBUG_LOGS

// following macro allows compiler to find errors in log_msg's variadic arguments.
//  it disables use of log files, redirecting it all to stderr.
#define log_msg(prio, ... ) fprintf( stderr, __VA_ARGS__ )

/* install libexplain, and libexplain-dev, and add -lexplain and you might get some messages.
#include <libexplain/fprintf.h>
#define log_msg(prio, ... ) explain_fprintf_or_die( stderr, __VA_ARGS__ )
 */

#else

void log_msg(const int prio, const char *format, ...);

#endif

void log_setup(const char *fn, mode_t mode, int level, int lr, int lri);
// set up logging to the named file, suppressing messages of lower severity 
// logrotation is a floating point number of seconds, indicating number of days to retain.

void set_loglevel(int level);

/* table to hold previous log file names for log rotation */
struct logfn_tab_t {
    char **fns; /* dynamically allocated, pointer buffer size known at rt */
    int i;
    int size;
};

void log_cleanup();

int is_utf8(const char * string);

void daemonize(int close_stdout);
// executed to go from a management instance to a daemon working instance.

#define SR_TIMESTRLEN (26)

// Assumed longest possible hash. typeprefix + SHA512_DIGEST 
#define SR_SUMHASHLEN (SHA512_DIGEST_LENGTH+1)

// SUMSTR is the printable-string representation of the hash, each digit decodes to two characters for hexadecimal digits.
#define SR_SUMSTRLEN  (2 * SHA512_DIGEST_LENGTH + 3 )


 /**
   return a correct sumstring (assume it is big enough)  as per sr_post(7)
   algo = 
     '0' - no checksum, value is random. -> now same as N.
     'a' - arbitrary checksum, set sum to provided value (sum_preset)
     'd' - md5sum of block.
     'n' - md5sum of filename (fn).
     'L' - now sha512 sum of link value.
     'N' - md5sum of filename (fn) + partstr.
     'R' - no checksum, value is random. -> now same as N.
     's' - sha512 sum of block.

   block starts at block_size * block_num, and ends 

   same storage is re-used on repeated calls, so best to strdup soon after return.

  */

int get_sumhashlen( char algo );
 /**
 return the length of the hash buffer (which includes the 1 char prefix for the type.
  */

char *set_sumstr( char algo, char algoz, const char* sum_preset, const char* fn, const char* partstr, char *linkstr,
          unsigned long block_size, unsigned long block_count, unsigned long block_rem, unsigned long block_num,
          int xattr_cc);

unsigned char *sr_sumstr2hash( const char *s );

char *sr_hash2sumstr( const unsigned char *h );

char *sr_time2str( struct timespec *tin );
struct timespec *sr_str2time( char *s ); 


#endif
