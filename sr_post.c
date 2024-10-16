/* vim:set ft=c ts=2 sw=2 sts=2 et cindent: */

/*
 * Usage info after license block.
 *
 * This code is by Peter Silva copyright (c) 2017 part of MetPX.
 * copyright is to the Government of Canada. code is GPLv2
 *
 * based on a amqp_sendstring from rabbitmq-c package
 */

/* 
  Minimal c implementation to allow posting of sr_post(7) messages.

limitations:
  will not interpret partition files to generate 'p' posts.

FIXME: posting partitioned parts Not yet implemented.

   pseudo-code::

      if (psc == 'p') 
      {
              If you find a file that ends in .p.4096.20.13.0.Part, which
              decodes as: psc.blocksize.block_count.block_rem.block_num".Part"
              then adjust: 
                   - message to contain path with suffix included.
                   - path to feed into checksum calc.
              if the part file is not found, then skip to next part.

              this algo posts all the parts present on local disk.

            confusing things:
               - I don't think it is useful to post all parts, most likely
                 end up repeatedly posting many of the parts that way.
               - likely only want to post each part once, so then would need
                 a way to specify a particular part to post?

          sprintf( suffixstr, ".%c.%lu.%lu.%lu.%lu.Part", psc, sr_c->cfg->blocksize, 
              block_count, block_rem, block_num );
           part_fn = fn + suffixstr
             stat( partfn, partsb );  
          if (Parf_file_found) {
          } else {
             suffixtr[0]='\0';
          }
      };

 
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <errno.h>
#define EBUFLEN (127)
static char *es;
static char error_buf[EBUFLEN + 1];

#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>

#include <unistd.h>
#include <fcntl.h>
#include <linux/limits.h>

#include <openssl/md5.h>
#include <openssl/sha.h>

#include <stdint.h>
#include <amqp_tcp_socket.h>
#include <amqp_ssl_socket.h>
#include <amqp.h>
#include <amqp_framing.h>

#include "sr_context.h"

// needed for sr_post_message.
#include "sr_consume.h"

#include "sr_version.h"

/*
 Statically assign the maximum number of headers that can be included in a message.
 just picked a number.  I remember picking a larger one before, and it bombed, don't know why.

 */
#define HDRMAX (255)

static amqp_table_entry_t headers[HDRMAX];

static int hdrcnt = 0;
static int bad_hdrcnt = 0;

int rmdir_in_progress = 0;

static void header_reset()
{
	hdrcnt--;
	for (; (hdrcnt >= 0); hdrcnt--) {
		headers[hdrcnt].key = amqp_cstring_bytes("");
		headers[hdrcnt].value.kind = AMQP_FIELD_KIND_VOID;
		headers[hdrcnt].value.value.bytes = amqp_cstring_bytes("");
	}
	hdrcnt = 0;
	bad_hdrcnt = 0;
}

static void amqp_header_add(struct sr_log_context_s *logctx, char *tag, const char *value)
{

	/* check utf8 compliance of tag and value for message headers */
	if (!sr_is_utf8(tag) || !sr_is_utf8(value)) {
		sr_log_msg(logctx,LOG_ERROR,
			   "amqp header (tag, value)<>(%s,%s) not utf8 encoded, Message corrupt.\n",
			   tag, value);
		return;
	}

	char value2[AMQP_MAX_SS];

	if (hdrcnt >= HDRMAX) {
		sr_log_msg(logctx,LOG_ERROR,
			   "too many headers! (only support %d) ignoring %s=%s Message corrupt.\n",
			   HDRMAX, tag, value);
		bad_hdrcnt++;
		return;
	}
	headers[hdrcnt].key = amqp_cstring_bytes(tag);
	headers[hdrcnt].value.kind = AMQP_FIELD_KIND_UTF8;

	if (strlen(value) > AMQP_MAX_SS) {
		strncpy(value2, value, AMQP_MAX_SS);
		value2[AMQP_MAX_SS - 1] = '\0';
		sr_log_msg(logctx,LOG_ERROR,
			   "header %s too long (%lu bytes), truncating to: %s. Message corrupt.\n",
			   tag, (unsigned long)strlen(value), value2);
		headers[hdrcnt].value.value.bytes = amqp_cstring_bytes(value2);
		bad_hdrcnt++;
	} else {
		headers[hdrcnt].value.value.bytes = amqp_cstring_bytes(value);
	}
	hdrcnt++;
	//sr_log_msg(logctx,LOG_DEBUG, "Adding header: %s=%s hdrcnt=%d\n", tag, value, hdrcnt );
}

static void set_url(char *m, char *spec)
  /* Pick a URL from the spec (round-robin) copy it to the given buffer
   */
{
	static const char *cu_url = NULL;
	char *sp;

	if (strchr(spec, ',')) {
		if (cu_url) {
			cu_url = strchr(cu_url, ',');	// if there is a previous one, pick the next one.
		}
		if (cu_url) {
			cu_url++;	// skip to after the comma.
		} else {
			cu_url = spec;	// start from the beginning.
		}
		sp = strchr(cu_url, ',');
		if (sp)
			strncpy(m, cu_url, sp - cu_url);
		else
			strcpy(m, cu_url);
	} else {
		strcpy(m, spec);
	}
}

static unsigned long int set_blocksize(long int bssetting, size_t fsz)
{
	unsigned long int tfactor = (50 * 1024 * 1024);

	switch (bssetting) {
	case 0:		// autocompute 
		if (fsz > 100 * tfactor)
			return (10 * tfactor);
		else if (fsz > 10 * tfactor)
			return ((unsigned long int)((fsz + 9) / 10));
		else if (fsz > tfactor)
			return ((unsigned long int)((fsz + 2) / 3));
		else
			return (fsz);
		break;

	case 1:		// send file as one piece.
		return (fsz);
		break;

	default:		// partstr=i
		return (bssetting);
		break;
	}

}

char *v03content(struct sr_log_context_s *logctx, struct sr_message_s *m)
{

	sr_log_msg(logctx,LOG_ERROR, "Content inlinining not implemented. Faking it for now\n");
	return "\"encoding\" : \"_encoding_\", \"value\" : \"_value_\"";
}

char *v03time(struct sr_log_context_s *logctx, char *v02time)
{
	static char buf[128];

	if (strlen(v02time) > 9) {
	     if ( v02time[8] != 'T' ) {
		    strncpy(buf, v02time, 8);
		    buf[8] = 'T';
    		    buf[9] = '\0';
		    strcat(buf, v02time + 8);
	    }
	} else {
	    sr_log_msg(logctx,LOG_ERROR, "v03time invalid timestamp: %s. returning unmodified\n", v02time);
            strcpy(buf,v02time);
	}
	//sr_log_msg(logctx,LOG_ERROR, "v03time input: %s, output: %s\n", v02time, buf);
	return (buf);
}

/*
 * return cc string with tag value pair appended in JSON ( "tag" : "value" )
 * separator is hard-coded here (beginning of sprintf.)
 * FIXME: dumps core whenever this is used... something to fix.
 */
static void v03amqp_header_add(struct sr_log_context_s *logctx, char **c, const char *tag, const char *value)
{
	int status;

	/* check utf8 compliance of tag and value for message headers */
	if (!sr_is_utf8(tag) || !sr_is_utf8(value)) {
		sr_log_msg(logctx,LOG_ERROR,
			   "amqp header (tag, value)<>(%s,%s) not utf8 encoded, ignoring header\n",
			   tag, value);
	} else {
		status = sprintf(*c, ", \"%s\" : \"%s\"", tag, value);
		(*c) += status;
	}
}

void v03encode(char *message_body, struct sr_context *sr_c, struct sr_message_s *m)
{
	char *c;
	char *ci;
	char *rename_value = NULL;
	char sep[8];
	char smallbuf[256];
	signed int status;
	struct sr_header_s *uh;

	// convert routing key, if necessary.
	// FIXME: a generic conversion replacing topicPrefix by post_topicPrefix
	//        would be much better, but this >99% answer is good enough for now.
	if (m->routing_key[2] != '3')
		m->routing_key[2] = '3';

	strcpy(message_body, "{");
	c = message_body + 1;

	strncpy(sep, "\n\t", 8);
	strncpy(sep, " ", 8);

	status = sprintf(c, "%s\"pubTime\" : \"%s\"", sep, v03time(sr_c->cfg->logctx,m->datestamp));
	c += status;

	v03amqp_header_add(sr_c->cfg->logctx, &c, "baseUrl", m->url);

	v03amqp_header_add(sr_c->cfg->logctx, &c, "relPath", m->relPath);

	ci = v03identity(m);
	if (ci) {
		status = sprintf(c, ",%s\"identity\" : { %s }", sep, v03identity(m));
		c += status;
	}

	if (sr_c->cfg->strip != 0)
		v03amqp_header_add(sr_c->cfg->logctx, &c, "rename", m->rename);

	if (m->source[0])
		v03amqp_header_add(sr_c->cfg->logctx, &c, "source", m->source);

	if ((m->sum[0] != 'R') && (m->sum[0] != 'L') && (m->sum[0] != 'm') && (m->sum[0] != 'r')) {
		if (m->parts_s != '1') {
			status = sprintf(c,
					 ",%s\"blocks\" : { \"method\": \"%s\", \"size\" : "
					 "\"%0ld\", \"count\": \"%ld\", \"remainder\": \"%ld\", "
					 "\"number\" : \"%ld\" }",
					 sep, (m->parts_s == 'i') ? "inplace" : "partitioned",
					 m->parts_blksz, m->parts_blkcount, m->parts_rem,
					 m->parts_num);
			c += status;
		} else {
			sprintf(smallbuf, "%ld", m->parts_blksz);
			v03amqp_header_add(sr_c->cfg->logctx, &c, "size", smallbuf);
		}

		if (m->atime[0] && (strlen(m->atime)>9)) {
			v03amqp_header_add(sr_c->cfg->logctx, &c, "atime", v03time(sr_c->cfg->logctx,m->atime));
		}

		if (m->mtime[0] && (strlen(m->mtime)>9)) {
			v03amqp_header_add(sr_c->cfg->logctx, &c, "mtime", v03time(sr_c->cfg->logctx,m->mtime));
		}
	}
	if ((m->sum[0] != 'R') && (m->sum[0] != 'L') && (m->sum[0] != 'r')) {
		if (m->mode > 0) {
			sprintf(smallbuf, "%03o", m->mode);
			v03amqp_header_add(sr_c->cfg->logctx, &c, "mode", smallbuf);
		}
	}

	rename_value = NULL;
	for (uh = m->user_headers; uh; uh = uh->next) {
		if (!strcmp(uh->key, "oldname")) {
			rename_value = uh->value;
		} else {
			v03amqp_header_add(sr_c->cfg->logctx, &c, uh->key, uh->value);
		}
	}
	if (m->sum[0] == 'L') {
		if (rename_value) {
			status =
			    sprintf(c, ", \"fileOp\": { \"link\":\"%s\", \"rename\": \"%s\"}",
				    m->link, rename_value);
		} else {
			status = sprintf(c, ", \"fileOp\": { \"link\":\"%s\" }", m->link);
		}
		c += status;
	} else if (m->sum[0] == 'R') {
		if (rename_value) {
			status =
			    sprintf(c, ", \"fileOp\": { \"remove\":\"\", \"rename\": \"%s\"}",
				    rename_value);
		} else {
			status = sprintf(c, ", \"fileOp\": { \"remove\" : \"\"} ");
		}
		c += status;
	} else if (m->sum[0] == 'm') {
		if (rename_value) {
			status =
			    sprintf(c, ", \"fileOp\": { \"directory\":\"\", \"rename\": \"%s\"}",
				    rename_value);
		} else {
			status = sprintf(c, ", \"fileOp\": { \"directory\" : \"\"} ");
		}
		c += status;
	} else if (m->sum[0] == 'r') {
		if (rename_value) {
			status =
			    sprintf(c,
				    ", \"fileOp\": { \"remove\": \"\", \"directory\": \"\", \"rename\": \"%s\"}",
				    rename_value);
		} else {
			status =
			    sprintf(c, ", \"fileOp\": { \"remove\" : \"\", \"directory\" : \"\"} ");
		}
		c += status;
	} else if (rename_value) {
		status = sprintf(c, ", \"fileOp\": { \"rename\":\"%s\" }", rename_value);
		c += status;
	}

	sprintf(c, "%s}  \n", sep);
	c += status;
}

void sr_post_message(struct sr_context *sr_c, struct sr_message_s *m)
{
	char fn[PATH_MAXNUL];
	char message_body[1024 * 1024];
	char smallbuf[256];
	char thisexchange[256];
	char *c, *d;
	amqp_table_t table;
	amqp_basic_properties_t props;
	amqp_tx_commit_ok_t *commit_status;
	amqp_rpc_reply_t reply;
	signed int status;
	struct sr_header_s *uh;
	time_t to_sleep = 1;
	static time_t this_second = 0;
	static time_t new_second = 0;
	static int posted_this_second = 0;

	// rate limiting.        

	if (sr_c->cfg->messageRateMax > 0) {

		if (posted_this_second >= sr_c->cfg->messageRateMax) {
			sr_log_msg(sr_c->cfg->logctx,LOG_INFO, "messageRateMax %d per second\n",
				   sr_c->cfg->messageRateMax);
			sleep(1);
		}

		new_second = time(NULL);
		if (new_second > this_second) {
			this_second = new_second;
			posted_this_second = 0;
		}
		posted_this_second++;
	}

	if (!sr_message_valid(sr_c->cfg->logctx, m)) {
		sr_log_msg(sr_c->cfg->logctx,LOG_INFO, "invalid message. not posting\n");
		return;
	}
	// MG white space in filename
	strcpy(fn, m->relPath);
	c = strchr(m->relPath, ' ');
	if (c != NULL) {
		c = fn;
		d = m->relPath;
		//while ( *d ) { if ( *d == ' ' ) { *c++='%'; *c++='2'; *c++='0'; } else *c++ = *d; d++; }

		while (*d) {
			if (*d == ' ') {
				*c++ = '%';
				*c++ = '2';
				*c++ = '0';
			} else {
				if (*d == '#') {
					*c++ = '%';
					*c++ = '2';
					*c++ = '3';
				} else
					*c++ = *d;
			}
			d++;
		}
		*c = '\0';
	}
	//  resume posting
	while (1) {
		if (!strncmp("v02.", sr_c->cfg->post_topicPrefix, 4)) {
			strcpy(message_body, m->datestamp);
			strcat(message_body, " ");
			strcat(message_body, m->url);
			strcat(message_body, " ");
			strcat(message_body, fn);
			strcat(message_body, " \n");

			header_reset();

			if (sr_c->cfg->strip > 0)
				amqp_header_add(sr_c->cfg->logctx, "rename", m->rename);

			if ((m->sum[0] != 'R') && (m->sum[0] != 'L')) {
				amqp_header_add(sr_c->cfg->logctx, "parts", sr_message_partstr(m));

				if (m->atime[0])
					amqp_header_add(sr_c->cfg->logctx, "atime", m->atime);

				if (m->mode > 0) {
					sprintf(smallbuf, "%03o", m->mode);
					amqp_header_add(sr_c->cfg->logctx, "mode", smallbuf);
				}

				if (m->mtime[0])
					amqp_header_add(sr_c->cfg->logctx, "mtime", m->mtime);
			}

			if (m->sum[0] == 'L') {
				amqp_header_add(sr_c->cfg->logctx, "link", m->link);
			}

			amqp_header_add(sr_c->cfg->logctx, "sum", m->sum);

			for (uh = m->user_headers; uh; uh = uh->next)
				amqp_header_add(sr_c->cfg->logctx, uh->key, uh->value);

			table.num_entries = hdrcnt;
			table.entries = headers;

			props._flags =
			    AMQP_BASIC_CONTENT_ENCODING_FLAG | AMQP_BASIC_HEADERS_FLAG |
			    AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
			props.content_encoding = amqp_cstring_bytes("utf-8");
			props.content_type = amqp_cstring_bytes("text/plain");
			props.delivery_mode = 2;	/* persistent delivery mode */
			props.headers = table;

			strcpy(thisexchange, sr_c->cfg->post_broker->exchange);

			if (sr_c->cfg->post_broker->exchangeSplit > 0) {
				sprintf(strchr(thisexchange, '\0'), "%02d",
					m->sum[sr_get_sumhashlen(m->sum[0]) -
					       1] % sr_c->cfg->post_broker->exchangeSplit);
			}
			if (bad_hdrcnt == 0)
				status =
				    amqp_basic_publish(sr_c->cfg->post_broker->conn, 1,
						       amqp_cstring_bytes(thisexchange),
						       amqp_cstring_bytes(m->routing_key), 0, 0,
						       &props, amqp_cstring_bytes(message_body));
		} else {	/* v03 */
			sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "v03 pubTime=%s\n", m->datestamp);
			v03encode(message_body, sr_c, m);
			sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "v03 body=%s\n", message_body);

			props._flags = AMQP_BASIC_CONTENT_ENCODING_FLAG |
			    AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
			props.content_encoding = amqp_cstring_bytes("utf-8");
			props.content_type = amqp_cstring_bytes("application/json");
			props.delivery_mode = 2;	/* persistent delivery mode */
			table.num_entries = 0;
			table.entries = 0;

			strcpy(thisexchange, sr_c->cfg->post_broker->exchange);

			if (sr_c->cfg->post_broker->exchangeSplit > 0) {
				sprintf(strchr(thisexchange, '\0'), "%02d",
					m->sum[sr_get_sumhashlen(m->sum[0]) -
					       1] % sr_c->cfg->post_broker->exchangeSplit);
			}
			status =
			    amqp_basic_publish(sr_c->cfg->post_broker->conn, 1,
					       amqp_cstring_bytes(thisexchange),
					       amqp_cstring_bytes(m->routing_key), 0, 0,
					       &props, amqp_cstring_bytes(message_body));
		}

		if (status < 0) {
			sr_log_msg(sr_c->cfg->logctx,LOG_WARNING,
				   "sr_%s: publish of message for  %s%s failed.\n",
				   sr_c->cfg->progname, m->url, fn);
			goto restart;
		}
		reply = amqp_get_rpc_reply(sr_c->cfg->post_broker->conn);
		if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
			sr_amqp_reply_print(sr_c->cfg->logctx, reply, "basic publish failed AMQP get_rpc_reply:");
			goto restart;
		}

		commit_status = amqp_tx_commit(sr_c->cfg->post_broker->conn, 1);
		if (!commit_status) {
			sr_log_msg(sr_c->cfg->logctx,LOG_WARNING, "broker failed to acknowledge publish event\n");
			reply = amqp_get_rpc_reply(sr_c->cfg->post_broker->conn);
			if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
				sr_amqp_reply_print(sr_c->cfg->logctx, reply, "failed AMQP get_rpc_reply");
			}
			goto restart;
		}
		amqp_maybe_release_buffers(sr_c->cfg->post_broker->conn);
		sr_log_msg(sr_c->cfg->logctx,LOG_INFO, "%s published: %s\n", sr_c->cfg->progname, sr_message_2log(m));
		return;

 restart:
		amqp_maybe_release_buffers(sr_c->cfg->post_broker->conn);
		sr_context_close(sr_c);
		sleep(to_sleep);
		if (to_sleep < 60)
			to_sleep <<= 1;
		sr_log_msg(sr_c->cfg->logctx,LOG_WARNING, "publish failed. Slept: %ld seconds. Retrying...\n",
			   to_sleep);
		sr_context_connect(sr_c);

	}
}

void realpath_adjust(struct sr_log_context_s *logctx, const char *input_path, char *output_path, signed int adjust)
 /* how to adjust the realpath resolution.
  * 0 - use the whole thing.
  * n < 0 - from the right work left...
  * n > 0 - from the left, work right...
  */
{
	char *last_slash;
	char *start, *spare, *end;
	char *return_value;
	char mutable_input_path[PATH_MAX];
	int i;

	i = 0;
	end = NULL;
	start = mutable_input_path;
	strcpy(mutable_input_path, input_path);

	if (adjust == 0) {
		return_value = realpath(input_path, output_path);
		if (return_value) {
			sr_log_msg(logctx,LOG_DEBUG, "realpath_adjust %d, %s -> %s \n", adjust, input_path, output_path);
			return;
		}
		// fallback to checking a directory for last path element.
		adjust = -1;
	}
	if (adjust < 0) {
		for (i = 0; i > adjust; i--) {
			spare = end;
			end = strrchr(start, '/');
			if (end) {
				if (spare)
					*spare = '/';
				*end = '\0';
			} else {
				break;
			}
		}
	} else if (adjust > 0) {
		for (i = 0; i <= adjust; i++) {
			spare = start;
			end = strchr(start, '/');
			if (end) {
				start = end + 1;
			} else {
				break;
			}
		}
		if (end) {
			*end = '\0';
		}
	}

	last_slash = end;
	if (last_slash) {
		*last_slash = '\0';
		return_value = realpath(mutable_input_path, output_path);
		sr_log_msg(logctx,LOG_DEBUG, "realpath_adjust %d, %s -> %s \n", adjust, mutable_input_path,
			   output_path);
		*last_slash = '/';
		if (return_value) {
			strcat(output_path, last_slash);
		} else {
			strcpy(output_path, input_path);
		}
	} else {
		strcpy(output_path, input_path);
	}

	return;
}

int sr_file2message_start(struct sr_context *sr_c, const char *pathspec,
			  struct stat *sb, struct sr_message_s *m)
/*
  reading a file, initialize the message that corresponds to it. Return the number of messages to post entire file.
 */
{
        bool absolute_path; /* true if path given is absolute */
	int i;
	char *drfound;
	char fn[PATH_MAXNUL];
	char *c, *d;
	int lasti;
	int linklen;
	char linkstr[PATH_MAXNUL];
	char tmprk[PATH_MAXNUL + 100];

        if ((sb) && (sr_c->cfg) && (sr_c->cfg->nodupe_ttl > 0)) {
	       time_t age = time(NULL)-sb->st_mtime ;
	       if ((sr_c->cfg->nodupe_fileAgeMax>0) && (age > sr_c->cfg->nodupe_fileAgeMax )) {
	                if (sr_c->cfg->logReject) {
			     sr_log_msg(sr_c->cfg->logctx,LOG_INFO, "rejecting older than %g: ignoring %s\n", sr_c->cfg->nodupe_fileAgeMax, fn );
       		         }
 			return(0);
	       }
	       if ((sr_c->cfg->nodupe_fileAgeMin>0) && (age < sr_c->cfg->nodupe_fileAgeMin )) {
	                if (sr_c->cfg->logReject) {
			     sr_log_msg(sr_c->cfg->logctx,LOG_INFO, "rejecting newer than %g: ignoring %s\n", sr_c->cfg->nodupe_fileAgeMin, fn );
       		         }
 			return(0);
	       }
        }
	if (*pathspec != '/') {	// need absolute path.
		getcwd(linkstr, PATH_MAX);
		strcat(linkstr, "/");
		strcat(linkstr, pathspec);
	} else {
		strcpy(linkstr, pathspec);
	}

	/* realpath stuff when it exists  sb */
	if (sr_c->cfg->realpathPost) {
		realpath_adjust(sr_c->cfg->logctx, linkstr, fn, sr_c->cfg->realpathAdjust);
	} else
		strcpy(fn, linkstr);

	linkstr[0] = '\0';

	if ((sr_c->cfg != NULL) && sr_c->cfg->debug) {
		sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG,
			   "%s file2message start with: %s sb=%p islnk=%d, isdir=%d, isreg=%d\n",
			   sr_c->cfg->progname, fn, sb,
			   sb ? S_ISLNK(sb->st_mode) : 0,
			   sb ? S_ISDIR(sb->st_mode) : 0, sb ? S_ISREG(sb->st_mode) : 0);
	}
	/* copy filename to path, but inserting %20 for every space
	 */
	c = m->relPath;
	d = fn;

	// skip initial / if present. it's called relPath...
        absolute_path = ( *d == '/') ;

        if (absolute_path) {
            d++;
        }

	while (*d) {
		if (*d == ' ') {
			*c++ = '%';
			*c++ = '2';
			*c++ = '0';
		} else {
			if (*d == '#') {
				*c++ = '%';
				*c++ = '2';
				*c++ = '3';
			} else
				*c++ = *d;
		}
		d++;
	}
	*c = '\0';

	if (sr_c->cfg->post_baseDir && (strlen(sr_c->cfg->post_baseDir) > 1 ) ) {
		// the +1 is to because baseDir is always absolute, and relPath is always relative
		drfound = strstr(fn, (sr_c->cfg->post_baseDir)+1);

		// replace only if at the beginning of the string.
		if (drfound==fn+1) {
			drfound += strlen(sr_c->cfg->post_baseDir);
			strcpy(m->relPath, drfound);
		} else if (absolute_path) {
		   	sr_log_msg(sr_c->cfg->logctx,LOG_ERROR, "%s posting outside of post_baseDir (%s) invalid path: %s\n", 
					sr_c->cfg->progname, sr_c->cfg->post_baseDir, fn );
 			return(0);
                }
	}

	// Strip option: remove prefix from path according to / #
	//               include updated path tagged as "rename" in header
	if (sr_c->cfg->strip > 0) {
		i = sr_c->cfg->strip;
		c = strdup(m->relPath);
		d = c;
		while (i--) {
			if (*c == '/')
				*c = 'x';
			c = strchrnul(c, '/');
			if (!*c)
				break;
		}
		strcpy(m->rename, *c ? c : "/");
		free(d);
	} else if (sr_c->cfg->strip == -1) {	// regex case.
		regmatch_t pmatch[1];
		//regoff_t off, len;
		const char *s = m->relPath;

#define ARRAY_SIZE(arr) (sizeof((arr)) / sizeof((arr)[0]))

#ifdef FORCE_LIBC_REGEX
		if (regexec_fn_ptr(&(sr_c->cfg->strip_regex), s, ARRAY_SIZE(pmatch), pmatch, 0)) {
#else
		if (regexec(&(sr_c->cfg->strip_regex), s, ARRAY_SIZE(pmatch), pmatch, 0)) {
#endif
			sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "strip: no match to: %s\n", sr_c->cfg->strip_pattern);
		} else {	// failure is matching case.   
			//off = pmatch[0].rm_so + (s-m->relPath); 
			//len = pmatch[0].rm_eo - pmatch[0].rm_so; 
			strncpy(m->rename, s, pmatch[0].rm_so);	// copy part before match starts.
			strcat(m->rename, s + pmatch[0].rm_eo);	// copy part after match ends
			sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "regexp strip: m->relPath: %s, m->rename: %s\n",
				   m->relPath, m->rename);
			s += pmatch[0].rm_eo;
		}
	}

	// use tmprk variable to fix  255 AMQP_SS_LEN limit
	strcpy(tmprk, sr_c->cfg->post_topicPrefix);
	if ( strlen(m->relPath) > 0 ) {
		strcat(tmprk, ".");
		strcat(tmprk, m->relPath + ((strlen(m->relPath)>1)&&(*(m->relPath) == '/')));
		if (strlen(tmprk) > 255)
			tmprk[255] = '\0';
	}
	strcpy(m->routing_key, tmprk);


	lasti = strlen(sr_c->cfg->post_topicPrefix);
	for (int i = lasti; i < strlen(m->routing_key); i++) {
		if (m->routing_key[i] == '/') {
			m->routing_key[lasti] = '.';
			lasti = i;
		}
	}
	m->routing_key[lasti] = '\0';

	strcpy(m->datestamp, sr_time2str(NULL));

	m->parts_blkcount = 1;
	m->parts_rem = 0;
	m->parts_num = 0;

	m->user_headers = sr_c->cfg->user_headers;

	m->sum[0] = sr_c->cfg->sumalgo;
	if (sr_c->cfg->sumalgo == 'z') {
		m->sum[1] = ',';
		m->sum[2] = sr_c->cfg->sumalgoz;
		m->sum[3] = '\0';
	}

	if (!sb) {
		if (!((sr_c->cfg->events) & SR_EVENT_DELETE) ||
		    (!((sr_c->cfg->events) & SR_EVENT_RMDIR) && rmdir_in_progress)
		    ) {
			rmdir_in_progress = 0;
			return (0);	// not posting deletes...
		}
		m->sum[0] = rmdir_in_progress ? 'r' : 'R';
		rmdir_in_progress = 0;

	} else if (S_ISLNK(sb->st_mode)) {
		if (!((sr_c->cfg->events) & SR_EVENT_LINK))
			return (0);	// not posting links...

		strcpy(m->atime, sr_time2str(&(sb->st_atim)));
		strcpy(m->mtime, sr_time2str(&(sb->st_mtim)));
		m->mode = sb->st_mode & 07777;

		m->sum[0] = 'L';
		linkstr[0] = '\0';
		linklen = readlink(fn, linkstr, PATH_MAX);
		linkstr[linklen] = '\0';
		strcpy(m->link, linkstr);

	} else if (S_ISDIR(sb->st_mode)) {
		if (!((sr_c->cfg->events) & SR_EVENT_MKDIR))
			return (0);	// not posting links...

		strcpy(m->atime, sr_time2str(&(sb->st_atim)));
		strcpy(m->mtime, sr_time2str(&(sb->st_mtim)));
		m->mode = sb->st_mode & 07777;
		m->sum[0] = 'm';
	} else if (S_ISREG(sb->st_mode)) {	/* regular files, add mode and determine block parameters */

		if (!((sr_c->cfg->events) & (SR_EVENT_CREATE | SR_EVENT_MODIFY)))
			return (0);

		if (access(fn, R_OK))
			return (0);	// will not be able to checksum if we cannot read.

		strcpy(m->atime, sr_time2str(&(sb->st_atim)));
		strcpy(m->mtime, sr_time2str(&(sb->st_mtim)));
		m->mode = sb->st_mode & 07777;

		m->parts_blksz = set_blocksize(sr_c->cfg->blocksize, sb->st_size);
		m->parts_s = (char)((m->parts_blksz < sb->st_size) ? 'i' : '1');

		if (m->parts_blksz == 0) {
			m->parts_rem = 0;
		} else {
			m->parts_rem = sb->st_size % (m->parts_blksz);
			m->parts_blkcount = (sb->st_size / m->parts_blksz) + (m->parts_rem ? 1 : 0);
		}

	}
	return (m->parts_blkcount);
}

struct sr_message_s *sr_file2message_seq(struct sr_context *sr_c,
					 const char *pathspec, int seq, struct sr_message_s *m)
/*
  Given a message from a "started" file, the prototype message, and a sequence number ( sequence is number of blocks of partsze )
  return the adjusted prototype message.  (requires reading part of the file to checksum it.)
 */
{
	char *sumstr;
	m->parts_num = seq;

	sumstr =
	    sr_set_sumstr(m->sum[0], m->sum[2], pathspec, NULL, m->link, m->parts_blksz,
			  m->parts_blkcount, m->parts_rem, m->parts_num, sr_c->cfg->xattr_cc);

	if (!(sumstr)) {
		sr_log_msg(sr_c->cfg->logctx,LOG_ERROR,
			   "file2message_seq unable to generate %c checksum for: %s\n",
			   m->parts_s, pathspec);
		free(sumstr);
		return (NULL);
	}
	strcpy(m->sum, sumstr);
	free(sumstr);
	return (m);
}

void sr_post(struct sr_context *sr_c, const char *pathspec, struct stat *sb)
{
	static struct sr_message_s m;
	int numblks;
	int status;

	/* check utf8 compliance of path */
	if (!sr_is_utf8(pathspec)) {
		sr_log_msg(sr_c->cfg->logctx,LOG_ERROR,
			   "file path \"%s\" not utf8 encoded, ignoring sr_post call\n", pathspec);
		return;
	}
	strcpy(m.source, sr_c->cfg->source);
	set_url(m.url, sr_c->cfg->post_baseUrl);
	m.user_headers = sr_c->cfg->user_headers;

	// report...
	// FIXME: duration, consumingurl, consuminguser, statuscode?
	numblks = sr_file2message_start(sr_c, pathspec, sb, &m);
	for (int blk = 0; (blk < numblks); blk++) {
		if (sr_file2message_seq(sr_c, pathspec, blk, &m)) {
			if (sr_c->cfg->nodupe_ttl > 0) {
				status =
				    sr_cache_check(sr_c->cfg->cachep,
						   sr_c->cfg->cache_basis,
						   m.sum[0],
						   (unsigned char *)(m.sum),
						   m.relPath, sr_message_partstr(&m));
				sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "sr_post cache_check: %s\n",
					   status ? "not found" : "already there, no post");
				if (!status) {
					if (sr_c->cfg->logReject)
						sr_log_msg(sr_c->cfg->logctx,LOG_INFO,
							   "rejecting duplicate: %s, %s\n",
							   m.relPath, sr_message_partstr(&m));
					continue;	// cache hit.
				}
			}
			sr_post_message(sr_c, &m);
		}
	}

}

void sr_post_rename(struct sr_context *sr_c, const char *oldname, const char *newname);

void sr_post_rename_dir(struct sr_context *sr_c, const char *oldname, const char *newname)
{
	DIR *dir;
	struct dirent *e;
	char oldpath[PATH_MAX + 1];
	int oldlen;
	char newpath[PATH_MAX + 1];
	int newlen;

	sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "sr_%s %s starting rename_dir: %s %s \n",
		   sr_c->cfg->progname, __sarra_version__, oldname, newname);
	dir = opendir(newname);
	if (!dir)
		return;

	// build oldname and new name as sub of current ones.
	strcpy(oldpath, oldname);
	strcat(oldpath, "/");
	oldlen = strlen(oldpath);

	strcpy(newpath, newname);
	strcat(newpath, "/");
	newlen = strlen(newpath);

	while ((e = readdir(dir))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		strcat(oldpath, e->d_name);
		strcat(newpath, e->d_name);
		sr_post_rename(sr_c, oldpath, newpath);

		oldpath[oldlen] = '\0';
		newpath[newlen] = '\0';
	}

	closedir(dir);
}

void sr_post_rename(struct sr_context *sr_c, const char *o, const char *n)
/*
   assume actual rename is completed, so newname exists.
 */
{
	struct stat sb;
	struct sr_header_s first_user_header;
	struct sr_mask_s *mask;
	char oldname[PATH_MAX];
	char oldreal[PATH_MAX];
	char newname[PATH_MAX];
	char newreal[PATH_MAX];

	if (*o == '/') {
		strcpy(oldname, o);
	} else {
		getcwd(oldname, PATH_MAX - strlen(o) - 2);
		strcat(oldname, "/");
		strcat(oldname, o);
	}
	if (*n == '/') {
		strcpy(newname, n);
	} else {
		getcwd(newname, PATH_MAX - strlen(n) - 2);
		strcat(newname, "/");
		strcat(newname, n);
	}

	if (sr_c->cfg->realpathPost || sr_c->cfg->realpathFilter) {
		realpath_adjust(sr_c->cfg->logctx, oldname, oldreal, sr_c->cfg->realpathAdjust);
		sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "applying realpath to old: %s -> %s\n", oldname, oldreal);

		//realpath(n, newreal);
		realpath_adjust(sr_c->cfg->logctx, newname, newreal, sr_c->cfg->realpathAdjust);
		sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "applying realpath to new: %s -> %s\n", newname, newreal);
	}

	if (sr_c->cfg->realpathPost) {
		strcpy(oldname, oldreal);
		strcpy(newname, newreal);
	}

	sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "sr_%s %s starting rename: %s %s \n",
		   sr_c->cfg->progname, __sarra_version__, oldname, newname);

	if (lstat(newname, &sb)) {
		es = strerror_r(errno, error_buf, EBUFLEN);
		sr_log_msg(sr_c->cfg->logctx,LOG_ERROR, "sr_%s rename cannot stat %s: %s\n", sr_c->cfg->progname,
			   newname, es);
		return;
	}
	/* 2023/01/20 - now that dirs have posts, just handle dirs normally.
	   if (S_ISDIR(sb.st_mode)) {
	   sr_post_rename_dir(sr_c, oldname, newname);
	   }
	 */

	first_user_header.next = sr_c->cfg->user_headers;
	sr_c->cfg->user_headers = &first_user_header;

	if (sr_c->cfg->v2compatRenameDoublePost) {
		sr_log_msg(sr_c->cfg->logctx,LOG_INFO, "sr_%s v2compatible 2nd post rename... newname: %s\n",
			   sr_c->cfg->progname, newname);
		first_user_header.key = strdup("newname");
		first_user_header.value = strdup(newname);

		if (sr_c->cfg->realpathFilter) {
			mask = sr_isMatchingPattern(sr_c->cfg, oldreal);
		} else {
			mask = sr_isMatchingPattern(sr_c->cfg, oldname);
		}
		if ((mask && !(mask->accepting))
		    || (!mask && !(sr_c->cfg->acceptUnmatched))) {
			if (sr_c->cfg->logReject)
				sr_log_msg(sr_c->cfg->logctx,LOG_INFO, "rejecting oldname: %s\n", oldname);
		} else {
			if (!access(oldname, F_OK)
			    && (S_ISREG(sb.st_mode) || S_ISLNK(sb.st_mode))) {
				sr_post(sr_c, oldname, &sb);
			} else {
				sr_post(sr_c, oldname, NULL);
			}
		}

		free(first_user_header.key);
		free(first_user_header.value);
	}

	first_user_header.key = strdup("oldname");
	first_user_header.value = strdup(o);

	if (sr_c->cfg->realpathFilter) {
		mask = sr_isMatchingPattern(sr_c->cfg, newreal);
	} else {
		mask = sr_isMatchingPattern(sr_c->cfg, newname);
	}
	if ((mask && !(mask->accepting))
	    || (!mask && !(sr_c->cfg->acceptUnmatched))) {
		if (sr_c->cfg->logReject)
			sr_log_msg(sr_c->cfg->logctx,LOG_INFO, "rejecting newname: %s\n", newname);
	} else
		sr_post(sr_c, newname, &sb);

	free(first_user_header.key);
	free(first_user_header.value);
	sr_c->cfg->user_headers = first_user_header.next;

}

int sr_post_cleanup(struct sr_context *sr_c)
{
	char exchange[256];
	amqp_rpc_reply_t reply;

	if (!sr_c->cfg->post_broker)
		return (1);

	if (sr_c->cfg->post_broker->exchangeSplit) {
		for (int i = 0; i < sr_c->cfg->post_broker->exchangeSplit; i++) {
			sprintf(exchange, "%s%02d", sr_c->cfg->post_broker->exchange, i);
			sr_log_msg(sr_c->cfg->logctx,LOG_INFO, "deleting exchange %s%02d\n",
				   sr_broker_uri(sr_c->cfg->post_broker), i);
			amqp_exchange_delete(sr_c->cfg->post_broker->conn, 1,
					     amqp_cstring_bytes(exchange), 0);
			reply = amqp_get_rpc_reply(sr_c->cfg->post_broker->conn);
			if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
				sr_amqp_reply_print(sr_c->cfg->logctx, reply,
						    "failed AMQP get_rpc_reply exchange delete");
			}
		}
	} else {
		sr_log_msg(sr_c->cfg->logctx,LOG_INFO, "deleting exchange %s\n",
			   sr_broker_uri(sr_c->cfg->post_broker));
		amqp_exchange_delete(sr_c->cfg->post_broker->conn, 1,
				     amqp_cstring_bytes(sr_c->cfg->post_broker->exchange), 0);
		reply = amqp_get_rpc_reply(sr_c->cfg->post_broker->conn);
		if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
			sr_amqp_reply_print(sr_c->cfg->logctx, reply, "failed AMQP get_rpc_reply exchange delete");
		}
	}
	return (1);
}

int sr_post_init(struct sr_context *sr_c)
{
	char exchange[256];
	amqp_rpc_reply_t reply;

	if (!sr_c->cfg->exchangeDeclare) {
		return (1);
	}
	if (sr_c->cfg->post_broker->exchangeSplit) {
		for (int i = 0; i < sr_c->cfg->post_broker->exchangeSplit; i++) {
			sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "declaring exchange %s%02d\n",
				   sr_broker_uri(sr_c->cfg->post_broker), i);
			sprintf(exchange, "%s%02d", sr_c->cfg->post_broker->exchange, i);
			amqp_exchange_declare(sr_c->cfg->post_broker->conn, 1,
					      amqp_cstring_bytes(exchange),
					      amqp_cstring_bytes("topic"), 0,
					      sr_c->cfg->durable, 0, 0, amqp_empty_table);
			reply = amqp_get_rpc_reply(sr_c->cfg->post_broker->conn);
			if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
				sr_amqp_reply_print(sr_c->cfg->logctx, reply,
						    "failed AMQP get_rpc_reply exchange declare");
			}
		}
	} else {
		sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "declaring exchange %s\n",
			   sr_broker_uri(sr_c->cfg->post_broker));
		amqp_exchange_declare(sr_c->cfg->post_broker->conn, 1,
				      amqp_cstring_bytes(sr_c->cfg->post_broker->exchange),
				      amqp_cstring_bytes("topic"), 0,
				      sr_c->cfg->durable, 0, 0, amqp_empty_table);
		reply = amqp_get_rpc_reply(sr_c->cfg->post_broker->conn);
		if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
			sr_amqp_reply_print(sr_c->cfg->logctx, reply, "failed AMQP get_rpc_reply exchange declare");
		}
	}

	return (1);
}
