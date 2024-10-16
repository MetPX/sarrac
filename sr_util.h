
#ifndef SR_UTIL_H
#define SR_UTIL_H

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/limits.h>

#include <stdbool.h>

#include <time.h>
#include <openssl/sha.h>

// log message severities.
#define LOG_DEBUG     (6)
#define LOG_INFO      (5)
#define LOG_NOTICE    (4)
#define LOG_WARNING   (3)
#define LOG_ERROR     (2)
#define LOG_CRITICAL  (1)

/* table to hold previous log file names for log rotation */
struct logfn_tab_s {
	char **fns;		/* dynamically allocated, pointer buffer size known at rt */
	int i;
	int size;
};

struct sr_log_context_s {
	time_t logbase;
	int logfd;
	char logfn[PATH_MAX];
	char metricsfn[PATH_MAX];
	bool logMetrics;
	char logfn_ts[PATH_MAX];
	char metricsfn_ts[PATH_MAX];
	int loglevel;
	int logmode;
	int logRotateCount;
	int logRotateInterval;
	struct logfn_tab_s ltab;
	struct logfn_tab_s mtab;

};

#ifdef SR_DEBUG_LOGS

// following macro allows compiler to find errors in sr_log_msg's variadic arguments.
//  it disables use of log files, redirecting it all to stderr.
#define sr_log_msg(ctx, prio, ... ) fprintf( stderr, __VA_ARGS__ )

/* install libexplain, and libexplain-dev, and add -lexplain and you might get some messages.
#include <libexplain/fprintf.h>
#define sr_log_msg(prio, ... ) explain_fprintf_or_die( stderr, __VA_ARGS__ )
 */

#else

void sr_log_msg(struct sr_log_context_s *ctx, const int prio, const char *format, ...);

#endif

struct sr_log_context_s *sr_log_setup(const char *fn, const char *metricsfn, bool logMetricsFlag, mode_t mode, int level, int lr, int lri);
// set up logging to the named file, suppressing messages of lower severity 
// logrotation is a floating point number of seconds, indicating number of days to retain.

void sr_set_loglevel(struct sr_log_context_s* ctx, int level);

void sr_log_cleanup(struct sr_log_context_s* ctx);

/* sr_is_utf8     routine to confirm that a field is utf8 encoded, taken verbatim from:
 *             https://stackoverflow.com/questions/1031645/how-to-detect-utf-8-in-plain-c 
 *             considered CC-BY-SA.  Is this a sufficient attribution?
 *             https://legalict.com/2016/01/07/what-is-the-license-status-of-stackoverflow-code-snippets/
 */

int sr_is_utf8(const char *string);

/* sr_has_vip is also inspired by stack exchange, but changed beyond all recognition.
 *
 * returns  1 if this host has the indicated virtual internet protocol (vip) address.
 * returns  0 if this host doesn't have it.
 * returns -1 on error.
 *
 * the vip argument is a string, can can be either a dotted quad, a hostname, or 
 * whatever those ipv6 address strings are called.
 */
int sr_has_vip(char const *vip, struct sr_log_context_s *logctx );

void sr_daemonize(int close_stdout, struct sr_log_context_s *logctx );
// executed to go from a management instance to a daemon working instance.

/* sr_hex2base64 returns the base64 encoded string converted from a hex-encoded input 
   This is used to produce v03 identity fields.

   no dynamic allocation is done, space is allocated in a static buffer, so use immediately, not thread safe.

 */
char *sr_hex2base64(const char *hstr);

/* sr_base642hex returns a hex-coded string given a base64 one (reverse of sr_hex2base64) */
char *sr_base642hex(const char *bstr);

#define SR_TIMESTRLEN (64)

// Assumed longest possible hash. typeprefix + SHA512_DIGEST 
#define SR_SUMHASHLEN (SHA512_DIGEST_LENGTH+1)

// SUMSTR is the printable-string representation of the hash, each digit decodes to two characters for hexadecimal digits.
#define SR_SUMSTRLEN  (2 * SHA512_DIGEST_LENGTH + 3 )

 /**
   return a correct sumstring (assume it is big enough)  as per sr_post(7)
   algo = 
     '0' - no checksum, value is random. -> now same as N.
     'd' - md5sum of block.
     'n' - md5sum of filename (fn).
     'L' - now sha512 sum of link value.
     'N' - md5sum of filename (fn) + partstr.
     'R' - no checksum, value is random. -> now same as N.
     's' - sha512 sum of block.

   block starts at block_size * block_num, and ends 

   same storage is re-used on repeated calls, so best to strdup soon after return.

  */

int sr_get_sumhashlen(char algo);
 /**
 return the length of the hash buffer (which includes the 1 char prefix for the type.
  */

char *sr_set_sumstr(char algo, char algoz, const char *fn, const char *partstr,
		    char *linkstr, unsigned long block_size,
		    unsigned long block_count, unsigned long block_rem,
		    unsigned long block_num, int xattr_cc);

unsigned char *sr_sumstr2hash(unsigned char *sumhash, const char *s);

char *sr_hash2sumstr(char *sumstr, const unsigned char *h);

char *sr_time2str(struct timespec *tin);
struct timespec *sr_str2time(char *s);

#endif
