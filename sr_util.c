
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>
#include <linux/limits.h>
#include <ctype.h>

/* following three are for sr_has_vip */
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netdb.h>

#include "sr_util.h"

static time_t logbase;
static int logfd = STDERR_FILENO;
static char logfn[PATH_MAX];
static char metricsfn[PATH_MAX];
bool logMetrics = false;
static char logfn_ts[PATH_MAX];
static char metricsfn_ts[PATH_MAX];
static int loglevel = LOG_INFO;
static int logmode = 0600;
static int logrotate_count = 5;
static int logrotate_interval = 24 * 60 * 60;

static struct timespec ts;
static struct tm tc;

static struct logfn_tab_s ltab;
static struct logfn_tab_s mtab;

char *log_set_fnts(char *basefilename);

#ifndef SR_DEBUG_LOGS
void sr_log_msg(int prio, const char *format, ...)
{
	char *level;
	va_list ap;

	if (prio > loglevel)
		return;

	switch (prio) {
	case LOG_DEBUG:
		level = "DEBUG";
		break;
	case LOG_INFO:
		level = "INFO";
		break;
	case LOG_NOTICE:
		level = "NOTICE";
		break;
	case LOG_WARNING:
		level = "WARNING";
		break;
	case LOG_ERROR:
		level = "ERROR";
		break;
	case LOG_CRITICAL:
		level = "CRITICAL";
		break;
	default:
		level = "UNKNOWN";
	}

	clock_gettime(CLOCK_REALTIME, &ts);
	localtime_r(&ts.tv_sec, &tc);

	/* log (message & metrics) rotation */
	if ((logfd != STDERR_FILENO)
	    && ((ts.tv_sec - logbase) > logrotate_interval)) {
		logbase = ts.tv_sec;

		strcpy(logfn_ts,log_set_fnts(logfn));
		close(logfd);
		rename(logfn, logfn_ts);

		strcpy(metricsfn_ts,log_set_fnts(metricsfn));
		rename(metricsfn, metricsfn_ts);

		logfd = open(logfn, O_WRONLY | O_CREAT | O_APPEND, logmode);

		/* delete outdated logs */
		if (logrotate_count > 0) {
			if (ltab.fns[ltab.i]) {
				remove(ltab.fns[ltab.i]);
				free(ltab.fns[ltab.i]);
				ltab.fns[ltab.i] = NULL;
			}
			ltab.fns[ltab.i] = strdup(logfn_ts);
			ltab.i = (ltab.i + 1) % ltab.size;
		
			if (mtab.fns[mtab.i]) {
				remove(mtab.fns[mtab.i]);
				free(mtab.fns[mtab.i]);
				mtab.fns[mtab.i] = NULL;
			}
			mtab.fns[mtab.i] = strdup(metricsfn_ts);
			mtab.i = (mtab.i + 1) % mtab.size;
		}
	}

	/* logging */
	dprintf(logfd, "%04d-%02d-%02d %02d:%02d:%02d,%03d [%s] ",
		tc.tm_year + 1900, tc.tm_mon + 1, tc.tm_mday,
		tc.tm_hour, tc.tm_min, tc.tm_sec, (int)(ts.tv_nsec / 1e6), level);

	va_start(ap, format);
	vdprintf(logfd, format, ap);
	va_end(ap);
}
#endif

void sr_log_setup(const char *fn, const char *mfn, bool logMetricsFlag, mode_t mode, int level, int lr, int lri)
{
#ifndef SR_DEBUG_LOGS
	strcpy(logfn, fn);
	strcpy(metricsfn, mfn);
	logmode = mode;
	logrotate_count = lr;
	logrotate_interval = lri;
	loglevel = level;

	logMetrics = logMetricsFlag;

	clock_gettime(CLOCK_REALTIME, &ts);
	localtime_r(&ts.tv_sec, &tc);
	logbase = ts.tv_sec;

	logfd = open(logfn, O_WRONLY | O_CREAT | O_APPEND, logmode);

	if (logrotate_count > 0) {
		ltab.fns = (char **)malloc(sizeof(char *) * logrotate_count);
		for (ltab.i = 0; ltab.i < logrotate_count; ++ltab.i)
			ltab.fns[ltab.i] = NULL;
		ltab.i = 0;
		ltab.size = logrotate_count;

                // metrics files.
		mtab.fns = (char **)malloc(sizeof(char *) * logrotate_count);
		for (mtab.i = 0; mtab.i < logrotate_count; ++mtab.i)
			mtab.fns[mtab.i] = NULL;
		mtab.i = 0;
		mtab.size = logrotate_count;
	}
#endif
}

/* global accessor for loglevel, ugly but better than using a global variable... */
void sr_set_loglevel(int level)
{
	loglevel = level;
}

void sr_log_cleanup()
{
#ifndef SR_DEBUG_LOGS
	/* (logfd != STDERR_FILENO) <> sr_log_setup called previously */
	if (logfd != STDERR_FILENO) {
		close(logfd);
		logfd = STDERR_FILENO;

		if (logrotate_count > 0) {
			for (ltab.i = 0; ltab.i < logrotate_count; ++ltab.i)
				if (ltab.fns[ltab.i])
					free(ltab.fns[ltab.i]);
			free(ltab.fns);
			ltab.i = 0;
			ltab.size = 0;
		
			for (mtab.i = 0; mtab.i < logrotate_count; ++mtab.i)
				if (mtab.fns[mtab.i])
					free(mtab.fns[mtab.i]);
			free(mtab.fns);
			mtab.i = 0;
			mtab.size = 0;
		}
	}
#endif
}

char *log_set_fnts(char *basefilename)
	/* set logging file name time stamp.
	 */
{
	static char logfn_ts[PATH_MAX];
	char *p;
	char b[PATH_MAX];

	strcpy(b, basefilename);
	p = b + strlen(basefilename);

	*p++ = '.';

	int lri = logrotate_interval;
	if (!(lri % (24 * 60 * 60))) {
		/* daily resolution */
		strcpy(p, "%04d-%02d-%02d");
		sprintf(logfn_ts, b, tc.tm_year + 1900, tc.tm_mon + 1, tc.tm_mday);

	} else if (!(lri % (60 * 60))) {
		/* hourly resolution */
		strcpy(p, "%04d-%02d-%02d_%02d");
		sprintf(logfn_ts, b, tc.tm_year + 1900, tc.tm_mon + 1, tc.tm_mday, tc.tm_hour);

	} else if (!(lri % (60))) {
		/* minute resolution */
		strcpy(p, "%04d-%02d-%02d_%02d-%02d");
		sprintf(logfn_ts, b, tc.tm_year + 1900, tc.tm_mon + 1,
			tc.tm_mday, tc.tm_hour, tc.tm_min);

	} else {
		/* second resolution */
		strcpy(p, "%04d-%02d-%02d_%02d-%02d-%02d");
		sprintf(logfn_ts, b, tc.tm_year + 1900, tc.tm_mon + 1,
			tc.tm_mday, tc.tm_hour, tc.tm_min, tc.tm_sec);
	}
	return(logfn_ts);
}

/* sr_is_utf8     routine to confirm that a field is utf8 encoded, taken verbatim from:
 *             https://stackoverflow.com/questions/1031645/how-to-detect-utf-8-in-plain-c 
 *             considered CC-BY-SA.  Is this a sufficient attribution?
 *             https://legalict.com/2016/01/07/what-is-the-license-status-of-stackoverflow-code-snippets/
 */

int sr_is_utf8(const char *string)
{
	if (!string)
		return 0;
	const unsigned char *bytes = (const unsigned char *)string;
	while (*bytes) {
		if ((		// ASCII
			    // use bytes[0] <= 0x7F to allow ASCII control characters
			    bytes[0] == 0x09 ||
			    bytes[0] == 0x0A ||
			    bytes[0] == 0x0D || (0x20 <= bytes[0] && bytes[0] <= 0x7E)
		    )
		    ) {
			bytes += 1;
			continue;
		}
		if ((		// non-overlong 2-byte
			    (0xC2 <= bytes[0] && bytes[0] <= 0xDF) &&
			    (0x80 <= bytes[1] && bytes[1] <= 0xBF)
		    )
		    ) {
			bytes += 2;
			continue;
		}
		if ((		// excluding overlongs
			    bytes[0] == 0xE0 &&
			    (0xA0 <= bytes[1] && bytes[1] <= 0xBF) &&
			    (0x80 <= bytes[2] && bytes[2] <= 0xBF)
		    ) || (	// straight 3-byte
				 ((0xE1 <= bytes[0] && bytes[0] <= 0xEC) ||
				  bytes[0] == 0xEE ||
				  bytes[0] == 0xEF) &&
				 (0x80 <= bytes[1] && bytes[1] <= 0xBF) &&
				 (0x80 <= bytes[2] && bytes[2] <= 0xBF)
		    ) || (	// excluding surrogates
				 bytes[0] == 0xED &&
				 (0x80 <= bytes[1] && bytes[1] <= 0x9F) &&
				 (0x80 <= bytes[2] && bytes[2] <= 0xBF)
		    )
		    ) {
			bytes += 3;
			continue;
		}
		if ((		// planes 1-3
			    bytes[0] == 0xF0 &&
			    (0x90 <= bytes[1] && bytes[1] <= 0xBF) &&
			    (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
			    (0x80 <= bytes[3] && bytes[3] <= 0xBF)
		    ) || (	// planes 4-15
				 (0xF1 <= bytes[0] && bytes[0] <= 0xF3) &&
				 (0x80 <= bytes[1] && bytes[1] <= 0xBF) &&
				 (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
				 (0x80 <= bytes[3] && bytes[3] <= 0xBF)
		    ) || (	// plane 16
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

/* end of code from stack exchange */

/* ok, sr_has_vip is inspired by stack exchange, but changed beyond all recognition.

   returns 1 if this host has the indicated virtual internet protocol (vip) address.
   returns 0 if this host doesn't have it.
   returns -1 on error.

   supports ipv6, and string can be either a hostname or a numeric one.
 */

int sr_has_vip(char const *vip)
{
	struct ifaddrs *ifaddr, *ifa;
	char host[NI_MAXHOST];
	char addr[NI_MAXHOST];
	int family;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return -1;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {

		if (ifa->ifa_addr == NULL)
			continue;

		family = ifa->ifa_addr->sa_family;
		if ((family != AF_INET) && (family != AF_INET6))
			continue;

		if (family == AF_INET) {
			getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host,
				    NI_MAXHOST, NULL, 0, 0);
			getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), addr,
				    NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		} else {
			getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6), host,
				    NI_MAXHOST, NULL, 0, 0);
			getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6), addr,
				    NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		}

		sr_log_msg(LOG_DEBUG, "sr_has_vip: checking interface %s host=%s addr=%s\n",
			   ifa->ifa_name, host, addr);
		if (vip && (!strcmp(host, vip) || !strcmp(addr, vip))) {
			sr_log_msg(LOG_DEBUG, "sr_has_vip: Matched!\n");
			return 1;
		}
	}

	sr_log_msg(LOG_DEBUG, "sr_has_vip: we don't have the vip\n");
	freeifaddrs(ifaddr);
	return 0;
}

void sr_daemonize(int close_stdout)
/* 
   fork child,  parent then exits.  child returns with proper daemon prep done.
 */
{
	pid_t pid;
	pid_t sid;

	pid = fork();

	if (pid < 0) {
		sr_log_msg(LOG_CRITICAL, "fork failed, cannot launch as daemon\n");
		exit(1);
	}
	if (pid > 0) {
		fprintf(stderr, "parent exiting normally, started child with pid: %d\n", pid);
		exit(0);
	}
	// child processing.

	sr_log_msg(LOG_DEBUG, "child daemonizing start\n");
	sid = setsid();
	if (sid < 0) {
		sr_log_msg(LOG_WARNING,
			   "daemonizing, setsid errord, failed to completely dissociate from login process\n");
	}

	if (logfd == 2) {
		sr_log_msg(LOG_CRITICAL, "to run as daemon log option must be set.\n");
		exit(1);
	}

	close(0);
	if (close_stdout) {
		close(1);
		dup2(logfd, STDOUT_FILENO);
	}
	close(2);
	dup2(logfd, STDERR_FILENO);

	sr_log_msg(LOG_DEBUG, "child daemonizing complete.\n");
}

/* v03 conversion code for base64 
 */

static char b64rep(char i)
{
	if (i > 64)
		fprintf(stderr,
			"errror in representation: %i should not be input to b64encode from hex\n",
			i);
	if (i == 63)
		return ('/');
	if (i == 62)
		return ('+');
	if (i >= 52)
		return (i + '0' - 52);
	if (i >= 26)
		return (i + 'a' - 26);
	return (i + 'A');
}

static char h2b(char i)
{
	if (i > 'f')
		fprintf(stderr,
			"errror in representation: %i should not be input to h2b from hex\n", i);
	if (i >= 'a')
		return (i - 'a' + 10);

	if (i > 'F')
		fprintf(stderr,
			"errror in representation: %i should not be input to h2b from hex\n", i);
	if (i >= 'A')
		return (i - 'A' + 10);

	if (i > '9')
		fprintf(stderr,
			"errror in representation: %i should not be input to h2b from hex\n", i);
	return (i - '0');

}

char *sr_hex2base64(const char *hstr)
{
	static char buf[1024];
	int hxlen;
	unsigned int h, b;
	char pad[2];

	hxlen = strlen(hstr);
	b = 0;
	for (h = 0; h < hxlen - 2; h += 3) {

		//base64 encoding requires line feed after every 76 chars...
/*
     if (!((b-1)%77)) 
         buf[b++]='\n';
 */
//   but Sarracenia expects fake line feed...
		if ((b > 10) && !((b % 78))) {
			buf[b++] = '\\';
			buf[b++] = 'n';
		}

		pad[0] = (h2b(hstr[h]) << 2) | (h2b(hstr[h + 1]) >> 2);
		pad[1] = ((h2b(hstr[h + 1]) & 0x03) << 4) | (h2b(hstr[h + 2]));
		buf[b++] = b64rep(pad[0]);
		buf[b++] = b64rep(pad[1]);
	}
	if ((hxlen - h) >= 2) {
		pad[0] = (h2b(hstr[h]) << 2) | (h2b(hstr[h + 1]) >> 2);
		buf[b++] = b64rep(pad[0]);
		pad[1] = ((h2b(hstr[h + 1]) & 0x03) << 4);
		buf[b++] = b64rep(pad[1]);
	} else if ((hxlen - h) == 1) {
		pad[0] = (h2b(hstr[h]) << 2);
		buf[b++] = b64rep(pad[0]);
	}
	while (h < hxlen) {
		buf[b++] = '=';
		h++;
	}
	buf[b] = '\0';

	return (buf);
}

static char raw2hex(char i)
{
	if (i > 15)
		fprintf(stderr, "error in represenation. hex range only 0-15: %d\n", i);
	if (i < 10)
		return (i + '0');
	return (i + 'a' - 10);
}

static char b642raw(char i)
{
	if (i > 'z')
		fprintf(stderr, "error in representation: %d invalid \n", i);
	if (i >= 'a')
		return (i - 'a' + 26);
	if (i >= 'A')
		return (i - 'A');
	if (i == '=')
		return (0);	// padding.
	if (i >= '0')
		return (i - '0' + 52);
	if (i == '/')
		return (63);
	if (i == '+')
		return (62);

	fprintf(stderr, "invalid character in base64 representation: %d\n", i);
	return (0);
}

char *sr_base642hex(const char *bstr)
{
	static char buf[1024];
	int b64len;
	int h, b;

	b64len = strlen(bstr);
	h = 0;
	for (b = 0; b < b64len; b += 2) {

		if ((bstr[b] == '\\') && (bstr[b + 1] == 'n')) {
			b += 2;
		}
		while (isspace(bstr[b])) {
			b++;
		}
		if (bstr[b] == '=') {
			h--;
			break;
		}

		buf[h++] = raw2hex(b642raw(bstr[b]) >> 2);
		buf[h++] = raw2hex(((b642raw(bstr[b]) & 0x03) << 2) | b642raw(bstr[b + 1]) >> 4);
		buf[h++] = raw2hex(b642raw(bstr[b + 1]) & 0x0f);
	}
	buf[h] = '\0';
	return (buf);
}

/* size of buffer used to read the file content in calculating checksums.
 */
#define SUMBUFSIZE (4096*1024)

// SHA512 being the longest digest...
//static char sumstr[SR_SUMSTRLEN];

//static unsigned char sumhash[SR_SUMHASHLEN];

int sr_get_sumhashlen(char algo)
{
	switch (algo) {
	case 'd':
	case 'n':
		return (MD5_DIGEST_LENGTH + 1);

	case '0':
		return (4 + 1);

	case 'p':
	case 's':
	case 'L':
	case 'R':
		return (SHA512_DIGEST_LENGTH + 1);

	case 'z':
		return (2);

	default:
		return (0);
	}
}

char *sr_set_sumstr(char algo, char algoz, const char *fn, const char *partstr,
		    char *linkstr, unsigned long block_size,
		    unsigned long block_count, unsigned long block_rem,
		    unsigned long block_num, int xattr_cc)
 /* 
    return a correct sumstring (assume it is big enough)  as per sr_post(7)
    algo = 
    '0' - no checksum, value is random. -> now same as N.
    'd' - md5sum of block.
    'n' - md5sum of filename (fn).
    'L' - now sha512 sum of link value.
    'm' - mkdir
    'p' - md5sum of filename (fn) + partstr.
    'r' - rmdir
    'R' - no checksum, value is random. -> now same as N.
    's' - sha512 sum of block.
    'z' - downstream should recalculate with algo that is argument.
    block starts at block_size * block_num, and ends 
  */
{
	EVP_MD_CTX *ctx;
	const EVP_MD *md;
	char *sumstrptr;
	static char sumstr[SR_SUMSTRLEN];
	unsigned int hashlen = 0;

	static int fd;
	static char buf[SUMBUFSIZE];
        static unsigned char sumhash[SR_SUMHASHLEN];
	long bytes_read;
	long how_many_to_read;
	const char *just_the_name = NULL;

	unsigned long start = block_size * block_num;
	unsigned long end;

	end = start + ((block_num < (block_count - (block_rem != 0))) ? block_size : block_rem);

	memset(sumhash, 0, SR_SUMHASHLEN);
	sumhash[0] = algo;

	/* xattr check for checksum caching optimization */
	struct stat attr;
	time_t stat_mtime;
	char cache_mtime[SR_TIMESTRLEN];

	stat(fn, &attr);
	stat_mtime = attr.st_mtime;

	sumstrptr=NULL;

	memset(cache_mtime, 0, SR_TIMESTRLEN);
	// are xattrs set?
	if (xattr_cc && (getxattr(fn, "user.sr_mtime", cache_mtime, SR_TIMESTRLEN) > 0)) {
		// is the checksum valid? (i.e. is (cache_mtime >= stat_mtime)? )
		if (sr_str2time(cache_mtime)->tv_sec >= stat_mtime) {
			memset(sumstr, 0, SR_SUMSTRLEN);
			getxattr(fn, "user.sr_sum", sumstr, SR_SUMSTRLEN);
			// is it the right checksum algorithm?
			if (algo == sumstr[0])
				return (sumstr);
		}
	}
	/* end of xattr check */

	switch (algo) {

	case '0':
		sprintf(sumstr, "%c,%03ld", algo, random() % 1000);
		break;

	case 'd':
		ctx = EVP_MD_CTX_create();
		md = EVP_md5();
		EVP_DigestInit_ex(ctx, md, NULL);
		// keep file open through repeated calls.
		//fprintf( stderr, "opening %s to checksum\n", fn );

		fd = open(fn, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "unable to read file for checksumming\n");
			strcpy(sumstr + 3, "deadbeef0");
			return (NULL);
		}
		lseek(fd, start, SEEK_SET);
		//fprintf( stderr, "checksumming start: %lu to %lu\n", start, end );
		while (start < end) {
			how_many_to_read =
			    (SUMBUFSIZE < (end - start)) ? SUMBUFSIZE : (end - start);

			bytes_read = read(fd, buf, how_many_to_read);
			if (bytes_read > 0) {
				EVP_DigestUpdate(ctx, buf, bytes_read);
				start += bytes_read;
			} else {
				fprintf(stderr, "error reading %s for MD5\n", fn);
				close(fd);
				return (NULL);
			}
		}
		close(fd);

		EVP_DigestFinal_ex(ctx, sumhash + 1, &hashlen);
		sumstrptr = sr_hash2sumstr(sumhash);
		break;

	case 'm':		// mkdir
		ctx = EVP_MD_CTX_create();
		md = EVP_md5();
		EVP_DigestInit_ex(ctx, md, NULL);

		just_the_name = just_the_name ? just_the_name + 1 : fn;
		EVP_DigestUpdate(ctx, just_the_name, strlen(just_the_name));
		EVP_DigestFinal_ex(ctx, sumhash + 1, &hashlen);
		sumstrptr = sr_hash2sumstr(sumhash);
		break;

	case 'r':		// rmdir
		ctx = EVP_MD_CTX_create();
		md = EVP_md5();
		EVP_DigestInit_ex(ctx, md, NULL);

		just_the_name = just_the_name ? just_the_name + 1 : fn;
		EVP_DigestUpdate(ctx, just_the_name, strlen(just_the_name));
		EVP_DigestFinal_ex(ctx, sumhash + 1, &hashlen);
		sumstrptr = sr_hash2sumstr(sumhash);
		break;

	case 'n':
		ctx = EVP_MD_CTX_create();
		md = EVP_md5();
		EVP_DigestInit_ex(ctx, md, NULL);

		just_the_name = just_the_name ? just_the_name + 1 : fn;
		EVP_DigestUpdate(ctx, just_the_name, strlen(just_the_name));
		EVP_DigestFinal_ex(ctx, sumhash + 1, &hashlen);
		sumstrptr = sr_hash2sumstr(sumhash);
		break;

	case 'L':		// symlink case
		just_the_name = linkstr;
		ctx = EVP_MD_CTX_create();
		md = EVP_sha512();
		EVP_DigestInit_ex(ctx, md, NULL);

		EVP_DigestUpdate(ctx, linkstr, strlen(linkstr));
		EVP_DigestFinal_ex(ctx, sumhash + 1, &hashlen);
		sumstrptr = sr_hash2sumstr(sumhash);
		break;

	case 'R':		// null, or removal.
		just_the_name = rindex(fn, '/') + 1;
		just_the_name = just_the_name ? just_the_name + 1 : fn;
		ctx = EVP_MD_CTX_create();
		md = EVP_sha512();
		EVP_DigestInit_ex(ctx, md, NULL);

		EVP_DigestUpdate(ctx, just_the_name, strlen(just_the_name));
		EVP_DigestFinal_ex(ctx, sumhash + 1, &hashlen);
		sumstrptr = sr_hash2sumstr(sumhash);
		break;

	case 'p':
		ctx = EVP_MD_CTX_create();
		md = EVP_sha512();
		EVP_DigestInit_ex(ctx, md, NULL);

		just_the_name = rindex(fn, '/') + 1;
		just_the_name = just_the_name ? just_the_name + 1 : fn;

		strcpy(buf, just_the_name);
		sprintf(buf, "%s%c,%lu,%lu,%lu,%lu", just_the_name, algo,
			block_size, block_count, block_rem, block_num);
		EVP_DigestUpdate(ctx, buf, strlen(buf));
		EVP_DigestFinal_ex(ctx, sumhash + 1, &hashlen);
		sumstrptr = sr_hash2sumstr(sumhash);
		break;

	case 's':
		ctx = EVP_MD_CTX_create();
		md = EVP_sha512();
		EVP_DigestInit_ex(ctx, md, NULL);

		fd = open(fn, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "unable to read file for SHA checksumming\n");
			return (NULL);
		}
		lseek(fd, start, SEEK_SET);
		//fprintf( stderr, "DBG checksumming start: %lu to %lu\n", start, end );
		while (start < end) {
			how_many_to_read =
			    (SUMBUFSIZE < (end - start)) ? SUMBUFSIZE : (end - start);

			bytes_read = read(fd, buf, how_many_to_read);

			//fprintf( stderr, "checksumming how_many_to_read: %lu bytes_read: %lu\n", 
			//   how_many_to_read, bytes_read );

			if (bytes_read >= 0) {
				EVP_DigestUpdate(ctx, buf, bytes_read);
				start += bytes_read;
			} else {
				fprintf(stderr, "error reading %s for SHA\n", fn);
				close(fd);
				return (NULL);
			}
		}

		close(fd);

		EVP_DigestFinal_ex(ctx, sumhash + 1, &hashlen);
		sumstrptr = sr_hash2sumstr(sumhash);
		break;

	case 'z':
		sumhash[1] = algoz;
		sumhash[2] = '\0';
		sumstrptr = sr_hash2sumstr(sumhash);
		break;

	default:
		fprintf(stderr, "sum algorithm %c unimplemented\n", algo);
		return (NULL);
	}

	/* xattr set for checksum caching optimization */
	if (xattr_cc) {
		// can we set xattrs? let's try and find out!
		setxattr(fn, "user.sr_sum", sumstr, strlen(sumstr), 0);
		char *t2s = sr_time2str(&attr.st_mtim);
		setxattr(fn, "user.sr_mtime", t2s, strlen(t2s), 0);
		// if the calls above fail, ignore and proceed
	}
	/* end of xattr set */

	return (sumstrptr);
}

static char nibble2hexchr(int i)
{
	unsigned char c = (unsigned char)(i & 0xf);
	return ((char)((c < 10) ? (c + '0') : (c - 10 + 'a')));
}

static int hexchr2nibble(char c)
 /* return ordinal value of digit assuming a character set that has a-f sequential in both lower and upper case.
    kind of based on ASCII, because numbers are assumed to be lower in collation than upper and lower case letters.
  */
{
	if (c < ':')
		return (c - '0');
	if (c < 'G')
		return (c - 'A' + 10);
	if (c < 'g')
		return (c - 'a' + 10);
	return (-1);
}

unsigned char *sr_sumstr2hash(const char *s)
{
	int i;
        static unsigned char sumhash[SR_SUMHASHLEN];

	if (!s)
		return (NULL);
	memset(sumhash, 0, SR_SUMHASHLEN);
	sumhash[0] = s[0];

	if (s[0] == 'z') {
		sumhash[1] = s[2];
		return (sumhash);
	}

	for (i = 1; (i < sr_get_sumhashlen(s[0])); i++) {
		sumhash[i] =
		    (unsigned char)((hexchr2nibble(s[i << 1]) << 4) +
				    hexchr2nibble(s[(i << 1) + 1]));
	}
	return (sumhash);
}

char *sr_hash2sumstr(const unsigned char *h)
{
	int i;
        static char sumstr[SR_SUMSTRLEN];
	memset(sumstr, 0, SR_SUMSTRLEN);
	sumstr[0] = h[0];
	sumstr[1] = ',';

	if (sumstr[0] == 'z') {
		sumstr[2] = h[1];
		sumstr[3] = '\0';;
		return (sumstr);
	}

	for (i = 1; i < sr_get_sumhashlen(h[0]); i++) {
		sumstr[i * 2] = nibble2hexchr(h[i] >> 4);
		sumstr[i * 2 + 1] = nibble2hexchr(h[i]);
	}
	sumstr[2 * i] = '\0';
	return (sumstr);
}


char *sr_time2str(struct timespec *tin)
{
	/* turn a timespec into an 18 character sr_post(7) conformant time stamp string.
	   if argument is NULL, then the string should correspond to the current system time.
	 */
        static char time2str_result[SR_TIMESTRLEN + 30];
	struct tm s;
	time_t when;
	struct timespec ts;
	long nsec;
	char nsstr[10];
	int nsl;

	memset(&s, 0, sizeof(struct tm));
	memset(&ts, 0, sizeof(struct timespec));

	if (tin) {
		when = tin->tv_sec;
		nsec = tin->tv_nsec;
	} else {
		clock_gettime(CLOCK_REALTIME, &ts);
		when = ts.tv_sec;
		nsec = ts.tv_nsec;
	}

	if (nsec > 0) {
		nsstr[0] = '\0';
		nsstr[10] = '\0';
                // tv_nsec is guaranteed not to exceed 9 digits...it's a nanosecond...
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-truncation"
		snprintf(nsstr, 9, "%09ld", nsec );
#pragma GCC diagnostic pop


		// remove trailing 0's, not relevant after a decimal place.
		nsl = strlen(nsstr) - 1;
		while (nsstr[nsl] == '0') {
			nsstr[nsl] = '\0';
			nsl--;
		}
	} else {
		strcpy(nsstr, "0");
	}

	gmtime_r(&when, &s);
	/*                         YYYY  MM  DD  hh  mm  ss */
	sprintf(time2str_result, "%04d%02d%02d%02d%02d%02d.%s",
		s.tm_year + 1900, s.tm_mon + 1, s.tm_mday, s.tm_hour, s.tm_min, s.tm_sec, nsstr);
	return (time2str_result);
}

static int ipow(int base, int exp)
/* all hail stack overflow: 
   https://stackoverflow.com/questions/101439/the-most-efficient-way-to-implement-an-integer-based-power-function-powint-int
 */
{
	int result = 1;
	while (exp) {
		if (exp & 1)
			result *= base;
		exp >>= 1;
		base *= base;
	}

	return result;
}

struct timespec *sr_str2time(char *s)
  /* inverse of above: convert SR_TIMESTRLEN character string into a timespec.

   */
{
	struct tm tm;
	memset(&tm, 0, sizeof(struct tm));
	memset(&ts, 0, sizeof(struct timespec));
	int dl;			// length of decimal string.

	if ((strlen(s)>8) && (s[8] == 'T')) {
		strptime(s, "%Y%m%dT%H%M%S", &tm);
        } else {
		strptime(s, "%Y%m%d%H%M%S", &tm);
	};
	ts.tv_sec = timegm(&tm);

	dl = strlen(s + 15);	// how many digits after decimal point?
	ts.tv_nsec = atol(s + 15) * ipow(10, dl);
	return (&ts);
}
