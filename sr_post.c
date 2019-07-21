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

amqp_table_entry_t headers[HDRMAX];

int hdrcnt = 0;

void header_reset()
{
	hdrcnt--;
	for (; (hdrcnt >= 0); hdrcnt--) {
		headers[hdrcnt].key = amqp_cstring_bytes("");
		headers[hdrcnt].value.kind = AMQP_FIELD_KIND_VOID;
		headers[hdrcnt].value.value.bytes = amqp_cstring_bytes("");
	}
	hdrcnt = 0;
}

void amqp_header_add(char *tag, const char *value)
{

	/* check utf8 compliance of tag and value for message headers */
	if (!is_utf8(tag) || !is_utf8(value)) {
		log_msg(LOG_ERROR,
			"amqp header (tag, value)<>(%s,%s) not utf8 encoded, ignoring header\n",
			tag, value);
		return;
	}

	char value2[AMQP_MAX_SS];

	if (hdrcnt >= HDRMAX) {
		log_msg(LOG_ERROR, "too many headers! ignoring %s=%s\n", tag, value);
		return;
	}
	headers[hdrcnt].key = amqp_cstring_bytes(tag);
	headers[hdrcnt].value.kind = AMQP_FIELD_KIND_UTF8;

	if (strlen(value) > AMQP_MAX_SS) {
		strncpy(value2, value, AMQP_MAX_SS);
		value2[AMQP_MAX_SS - 1] = '\0';
		log_msg(LOG_WARNING,
			"header %s too long (%ld bytes), truncating to: %s\n",
			tag, strlen(value), value2);
		headers[hdrcnt].value.value.bytes = amqp_cstring_bytes(value2);
	} else {
		headers[hdrcnt].value.value.bytes = amqp_cstring_bytes(value);
	}
	hdrcnt++;
	//log_msg( LOG_DEBUG, "Adding header: %s=%s hdrcnt=%d\n", tag, value, hdrcnt );
}

void set_url(char *m, char *spec)
  /* Pick a URL from the spec (round-robin) copy it to the given buffer
   */
{
	static const char *cu_url = NULL;
	char *sp;

	if (strchr(spec, ',')) {
		//log_msg( LOG_DEBUG, "1 picking url, set=%s, cu=%s\n", spec, cu_url );
		if (cu_url) {
			cu_url = strchr(cu_url, ',');	// if there is a previous one, pick the next one.
			//log_msg( LOG_DEBUG, "2 picking url, set=%s, cu=%s\n", spec, cu_url );
		}
		if (cu_url) {
			cu_url++;	// skip to after the comma.
			//log_msg( LOG_DEBUG, "3 picking url, set=%s, cu=%s\n", spec, cu_url );
		} else {
			cu_url = spec;	// start from the beginning.
			//log_msg( LOG_DEBUG, "4 picking url, set=%s, cu=%s\n", spec, cu_url );
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

unsigned long int set_blocksize(long int bssetting, size_t fsz)
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

char *hex_to_b64str( char *hextr, int hexstrlen ) {

  return( "not implemented" );
}

const char *sum2integrity( char sum )
{
   switch (sum) {
       case '0': return( "random" );
       case 'a': return( "arbitrary" );
       case 'd': return( "md5" );
       case 'n': return( "md5name" );
       case 's': return( "sha512" );
       case 'L': return( "link" );
       case 'R': return( "remove" );
       case 'z': return( "cod" );
       default: return( "unknown" );
   }

}

char *v03integrity( struct sr_message_t *m ) 
{
   static char istr[1024]; 
   const char *value;

   switch (m->sum[0]) {
       case 'd' : case 'n' : case 's' : case 'L' : case 'R' : value = hex2base64( &(m->sum[2]) ); break;
       case 'z' : value = sum2integrity(m->sum[2]); break;
       case '0' : case 'a' : default : value = &(m->sum[2]); break;
   }
   sprintf( istr, " \"method\" : \"%s\", \"value\" : \"%s\" ", sum2integrity( m->sum[0] ), value );
   return(istr);

}

char *v03time( char *v02time )
{
   static char buf[128];

   strncpy( buf, v02time, 8 );
   buf[8]='T';
   buf[9]='\0';
   strcat( buf, v02time+8 );
   return(buf);
}

void sr_post_message(struct sr_context *sr_c, struct sr_message_t *m)
{
	char fn[PATH_MAXNUL];
	char message_body[1024*1024];
	char smallbuf[256];
	char thisexchange[256];
	char *c, *d;
	amqp_table_t table;
	amqp_basic_properties_t props;
	amqp_tx_commit_ok_t *commit_status;
	amqp_rpc_reply_t reply;
	signed int status;
	struct sr_header_t *uh;
	time_t to_sleep = 1;

	// MG white space in filename
	strcpy(fn, m->path);
	c = strchr(m->path, ' ');
	if (c != NULL) {
		c = fn;
		d = m->path;
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
         if ( !strncmp("v02.", sr_c->cfg->post_topic_prefix, 4 ) ) {
    		strcpy(message_body, m->datestamp);
    		strcat(message_body, " ");
    		strcat(message_body, m->url);
    		strcat(message_body, " ");
    		strcat(message_body, fn);
    		strcat(message_body, " \n");

    		header_reset();

    		if (sr_c->cfg->strip > 0)
    			amqp_header_add("rename", m->rename);

    		if (m->from_cluster && m->from_cluster[0])
    			amqp_header_add("from_cluster", m->from_cluster);

    		if ((m->sum[0] != 'R') && (m->sum[0] != 'L')) {
    			amqp_header_add("parts", sr_message_partstr(m));

    			if (m->atime && m->atime[0])
    				amqp_header_add("atime", m->atime);

    			if (m->mode > 0) {
    				sprintf(smallbuf, "%04o", m->mode);
    				amqp_header_add("mode", smallbuf);
    			}

    			if (m->mtime && m->mtime[0])
    				amqp_header_add("mtime", m->mtime);
    		}

    		if (m->sum[0] == 'L') {
    			amqp_header_add("link", m->link);
    		}

    		amqp_header_add("sum", m->sum);
    
    		if (m->to_clusters && m->to_clusters[0])
    			amqp_header_add("to_clusters", m->to_clusters);

    		for (uh = m->user_headers; uh; uh = uh->next)
    			amqp_header_add(uh->key, uh->value);

    		table.num_entries = hdrcnt;
    		table.entries = headers;

    		props._flags =
    		    AMQP_BASIC_HEADERS_FLAG| AMQP_BASIC_CONTENT_TYPE_FLAG | 
                AMQP_BASIC_DELIVERY_MODE_FLAG;
		    props.content_type = amqp_cstring_bytes("text/plain");
		    props.delivery_mode = 2;	/* persistent delivery mode */
            props.headers = table;

		    strcpy(thisexchange, sr_c->cfg->post_broker->exchange);

		    if (sr_c->cfg->post_broker->exchange_split > 0) {
		    	sprintf(strchr(thisexchange, '\0'), "%02d",
		    		m->sum[get_sumhashlen(m->sum[0]) -
		    		       1] % sr_c->cfg->post_broker->exchange_split);
		    }
		    status =
		        amqp_basic_publish(sr_c->cfg->post_broker->conn, 1,
				       amqp_cstring_bytes(thisexchange),
				       amqp_cstring_bytes(m->routing_key), 0, 0,
				       &props, amqp_cstring_bytes(message_body));
        } else { /* v03 */
            strcpy( message_body, "{" );
            c = message_body+1;
            status = sprintf( c, "\n\t\"pubTime\" : \"%s\"", v03time( m->datestamp ) );
            c += status ; 
            status = sprintf( c, ",\n\t\"baseUrl\" : \"%s\"", m->url );
            c += status ; 
            status = sprintf( c, ",\n\t\"relPath\" : \"%s\"", m->path );
            c += status ; 

    		if (sr_c->cfg->strip > 0) {
                status = sprintf( c, ",\n\t\"rename\" : \"%s\"", m->rename );
                c += status ; 
            }

    		if (m->from_cluster && m->from_cluster[0]) {
                status = sprintf( c, ",\n\t\"from_cluster\" : \"%s\"", m->from_cluster );
                c += status ; 
            }

    		if (m->to_clusters) {
                status = sprintf( c, ",\n\t\"to_clusters\" : \"%s\"", m->to_clusters );
                c += status ; 
            }
            if ((m->sum[0] != 'R') && (m->sum[0] != 'L')) {
                if ( m->parts_s != '1' ) {
                    status = sprintf( c, ",\n\t\"blocks\" : { ");
                    c += status ; 
                    status = sprintf( c, "\"method\" : \"%s\", ", (m->parts_s=='i')?"inplace":"partitioned"  );
                    c += status ; 
                    status = sprintf( c, "\"size\" : \"%ld\", ", m->parts_blksz  );
                    c += status ; 
                    status = sprintf( c, "\"count\" : \"%ld\", ", m->parts_blkcount  );
                    c += status ; 
                    status = sprintf( c, "\"remainder\" : \"%ld\", ", m->parts_rem  );
                    c += status ; 
                    status = sprintf( c, "\"number\" : \"%ld\" }", m->parts_num  );
                    c += status ; 
                    //m->parts_s
                    //m->parts_blksz, m->parts_blkcount, m->parts_rem, m->parts_num
                    //amqp_header_add("parts", sr_message_partstr(m));
                } else {
                    status = sprintf( c, ",\n\t\"size\" : \"%ld\"", m->parts_blksz  );
                    c += status ; 
                }
                if (m->atime && m->atime[0]) {
                    status = sprintf( c, ",\n\t\"atime\" : \"%s\"", v03time( m->atime ) );
                    c += status ; 
                }

                if (m->mode > 0) {
                    status = sprintf( c, ",\n\t\"mode\" : \"%04o\"", m->mode );
                    c += status ; 
                }

                if (m->mtime && m->mtime[0]) {
                    status = sprintf( c, ",\n\t\"mtime\" : \"%s\"", v03time( m->mtime ) );
                    c += status ; 
                }
            }

    		//amqp_header_add("sum", m->sum);
            status = sprintf( c, ",\n\t\"integrity\" : { %s } ", v03integrity(m) );
            c += status ; 
            

            if (m->sum[0] == 'L') {
                status = sprintf( c, ",\n\t\"link\" : \"%s\"", m->link );
                c += status ; 
            }

    		for (uh = m->user_headers; uh; uh = uh->next)
                status = sprintf( c, ",\n\t\"%s\" : \"%s\"", uh->key, uh->value );
                c += status ; 

            strcat( message_body, "\n}\n" );
            log_msg( LOG_DEBUG, "v03 body=%s\n", message_body );
            //return;

    		props._flags =
    		    AMQP_BASIC_CONTENT_TYPE_FLAG | AMQP_BASIC_DELIVERY_MODE_FLAG;
		    props.content_type = amqp_cstring_bytes("text/plain");
		    props.delivery_mode = 2;	/* persistent delivery mode */

		    strcpy(thisexchange, sr_c->cfg->post_broker->exchange);

		    if (sr_c->cfg->post_broker->exchange_split > 0) {
		    	sprintf(strchr(thisexchange, '\0'), "%02d",
		    		m->sum[get_sumhashlen(m->sum[0]) -
		    		       1] % sr_c->cfg->post_broker->exchange_split);
		    }
		    status =
		        amqp_basic_publish(sr_c->cfg->post_broker->conn, 1,
				       amqp_cstring_bytes(thisexchange),
				       amqp_cstring_bytes(m->routing_key), 0, 0,
				       &props, amqp_cstring_bytes(message_body));
        }

		if (status < 0) {
			log_msg(LOG_ERROR,
				"sr_%s: publish of message for  %s%s failed.\n",
				sr_c->cfg->progname, m->url, fn);
			goto restart;
		}

		commit_status = amqp_tx_commit(sr_c->cfg->post_broker->conn, 1);
		if (!commit_status) {
			log_msg(LOG_ERROR, "broker failed to acknowledge publish event\n");
			reply = amqp_get_rpc_reply(sr_c->cfg->post_broker->conn);
			if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
				sr_amqp_reply_print(reply, "failed AMQP get_rpc_reply");
			}
			goto restart;
		}
		amqp_maybe_release_buffers(sr_c->cfg->post_broker->conn);
		log_msg(LOG_INFO, "published: %s\n", sr_message_2log(m));
		return;

 restart:
		amqp_maybe_release_buffers(sr_c->cfg->post_broker->conn);
		sr_context_close(sr_c);
		sleep(to_sleep);
		if (to_sleep < 60)
			to_sleep <<= 1;
		log_msg(LOG_WARNING, "publish failed. Slept: %ld seconds. Retrying...\n", to_sleep);
		sr_context_connect(sr_c);

	}
}

int sr_file2message_start(struct sr_context *sr_c, const char *pathspec,
			  struct stat *sb, struct sr_message_t *m)
/*
  reading a file, initialize the message that corresponds to it. Return the number of messages to post entire file.
 */
{
	int i;
	char *drfound;
	char fn[PATH_MAXNUL];
	char *c, *d;
	int lasti;
	int linklen;
	char *linkp;
	char linkstr[PATH_MAXNUL];
	char tmprk[PATH_MAXNUL + 100];

	if (*pathspec != '/')	// need absolute path.
	{
		getcwd(linkstr, PATH_MAX);
		strcat(linkstr, "/");
		strcat(linkstr, pathspec);

		/* realpath stuff when it exists  sb */
		if (sb && sr_c->cfg->realpath) {
			log_msg(LOG_DEBUG, "applying realpath to relpath %s\n", pathspec);
			if (!realpath(linkstr, fn)) {
				strcpy(fn, linkstr);
			}
		} else
			strcpy(fn, linkstr);
		linkstr[0] = '\0';

	} else {
		/* realpath stuff when it exists  sb */
		if (sb && sr_c->cfg->realpath) {
			log_msg(LOG_DEBUG, "applying realpath to abspath %s\n", pathspec);
			realpath(pathspec, fn);
		} else
			strcpy(fn, pathspec);
	}

	if ((sr_c->cfg != NULL) && sr_c->cfg->debug) {
		log_msg(LOG_DEBUG,
			"sr_%s file2message start with: %s sb=%p islnk=%d, isdir=%d, isreg=%d\n",
			sr_c->cfg->progname, fn, sb,
			sb ? S_ISLNK(sb->st_mode) : 0,
			sb ? S_ISDIR(sb->st_mode) : 0, sb ? S_ISREG(sb->st_mode) : 0);
	}
	if (sb && S_ISDIR(sb->st_mode))
		return (0);	// cannot post directories.

	/* copy filename to path, but inserting %20 for every space
	 */
	c = m->path;
	d = fn;
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
	//strcpy( m->path, fn );

	if (sr_c->cfg->post_base_dir) {
		drfound = strstr(fn, sr_c->cfg->post_base_dir);

		if (drfound) {
			drfound += strlen(sr_c->cfg->post_base_dir);
			strcpy(m->path, drfound);
		}
	}
	// Strip option: remove prefix from path according to / #
	//               include updated path tagged as "rename" in header
	if (sr_c->cfg->strip > 0) {
		i = sr_c->cfg->strip;
		c = strdup(m->path);
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
	}
	// use tmprk variable to fix  255 AMQP_SS_LEN limit
	strcpy(tmprk, sr_c->cfg->post_topic_prefix);
	strcat(tmprk, ".");
	strcat(tmprk, m->path + (*(m->path) == '/'));

	if (strlen(tmprk) > 255)
		tmprk[255] = '\0';

	strcpy(m->routing_key, tmprk);

	lasti = 0;
	for (int i = strlen(sr_c->cfg->topic_prefix); i < strlen(m->routing_key); i++) {
		if (m->routing_key[i] == '/') {
			if (lasti > 0) {
				m->routing_key[lasti] = '.';
			}
			lasti = i;
		}
	}
	m->routing_key[lasti] = '\0';

	strcpy(m->datestamp, sr_time2str(NULL));
	strcpy(m->to_clusters, sr_c->cfg->to);

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
		if (!((sr_c->cfg->events) & SR_DELETE))
			return (0);	// not posting deletes...
		m->sum[0] = 'R';
	} else if (S_ISLNK(sb->st_mode)) {
		if (!((sr_c->cfg->events) & SR_LINK))
			return (0);	// not posting links...

		strcpy(m->atime, sr_time2str(&(sb->st_atim)));
		strcpy(m->mtime, sr_time2str(&(sb->st_mtim)));
		m->mode = sb->st_mode & 07777;

		m->sum[0] = 'L';
		linkstr[0] = '\0';
		linklen = readlink(fn, linkstr, PATH_MAX);
		linkstr[linklen] = '\0';
		if (sr_c->cfg->realpath) {
			linkp = realpath(linkstr, m->link);
			if (!linkp) {
				log_msg(LOG_ERROR,
					"sr_%s unable to obtain realpath for %s\n",
					sr_c->cfg->progname, fn);
				return (0);
			}
		} else {
			strcpy(m->link, linkstr);
		}

	} else if (S_ISREG(sb->st_mode)) {	/* regular files, add mode and determine block parameters */

		if (!((sr_c->cfg->events) & (SR_CREATE | SR_MODIFY)))
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

struct sr_message_t *sr_file2message_seq(struct sr_context *sr_c,
					 const char *pathspec, int seq, struct sr_message_t *m)
/*
  Given a message from a "started" file, the prototype message, and a sequence number ( sequence is number of blocks of partsze )
  return the adjusted prototype message.  (requires reading part of the file to checksum it.)
 */
{
	m->parts_num = seq;

	strcpy(m->sum,
	       set_sumstr(m->sum[0], m->sum[2], pathspec, NULL, m->link,
			  m->parts_blksz, m->parts_blkcount, m->parts_rem,
			  m->parts_num, sr_c->cfg->xattr_cc)
	    );

	if (!(m->sum)) {
		log_msg(LOG_ERROR,
			"file2message_seq unable to generate %c checksum for: %s\n",
			m->parts_s, pathspec);
		return (NULL);
	}
	return (m);
}

void sr_post(struct sr_context *sr_c, const char *pathspec, struct stat *sb)
{
	static struct sr_message_t m;
	int numblks;
	int status;

	/* check utf8 compliance of path */
	if (!is_utf8(pathspec)) {
		log_msg(LOG_ERROR,
			"file path \"%s\" not utf8 encoded, ignoring sr_post call\n", pathspec);
		return;
	}
	strcpy(m.to_clusters, sr_c->cfg->to);
	strcpy(m.from_cluster, sr_c->cfg->post_broker->hostname);
	strcpy(m.source, sr_c->cfg->source);
	set_url(m.url, sr_c->cfg->post_base_url);
	m.user_headers = sr_c->cfg->user_headers;

	// report...
	// FIXME: duration, consumingurl, consuminguser, statuscode?
	numblks = sr_file2message_start(sr_c, pathspec, sb, &m);

	for (int blk = 0; (blk < numblks); blk++) {
		if (sr_file2message_seq(sr_c, pathspec, blk, &m)) {
			if (sr_c->cfg->cache > 0) {
				status =
				    sr_cache_check(sr_c->cfg->cachep,
						   sr_c->cfg->cache_basis,
						   m.sum[0],
						   (unsigned char *)(m.sum),
						   m.path, sr_message_partstr(&m));
				log_msg(LOG_DEBUG, "sr_post cache_check: %s\n",
					status ? "not found" : "already there, no post");
				if (!status) {
					if (sr_c->cfg->log_reject)
						log_msg(LOG_INFO,
							"rejecting duplicate: %s, %s\n",
							m.path, sr_message_partstr(&m));
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

	log_msg(LOG_DEBUG, "sr_%s %s starting rename_dir: %s %s \n",
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
	struct sr_header_t first_user_header;
	struct sr_mask_t *mask;
	char *s;
	char oldname[PATH_MAX];
	char oldreal[PATH_MAX];
	char newname[PATH_MAX];
	char newreal[PATH_MAX];
	char tmpname[PATH_MAX];

	strcpy(oldname, o);
	strcpy(newname, n);

	if (sr_c->cfg->realpath || sr_c->cfg->realpath_filter) {
		strcpy(tmpname, o);
		s = rindex(tmpname, '/');
		if (s) {
			*s = '\0';
			s++;
		}
		realpath(tmpname, oldreal);	// apply to directory, not final path entry.
		if (s) {
			strcat(oldreal, "/");
			strcat(oldreal, s);
		}
		log_msg(LOG_DEBUG, "applying realpath to old: %s -> %s\n", o, oldreal);

		realpath(n, newreal);
		log_msg(LOG_DEBUG, "applying realpath to new: %s -> %s\n", n, newreal);
	}

	if (sr_c->cfg->realpath) {
		strcpy(oldname, oldreal);
		strcpy(newname, newreal);
	}

	log_msg(LOG_DEBUG, "sr_%s %s starting rename: %s %s \n",
		sr_c->cfg->progname, __sarra_version__, oldname, newname);

	if (lstat(newname, &sb)) {
		log_msg(LOG_ERROR, "sr_%s rename: %s cannot stat.\n", sr_c->cfg->progname, newname);
		return;
	}
	if (S_ISDIR(sb.st_mode)) {
		sr_post_rename_dir(sr_c, oldname, newname);
	}

	first_user_header.next = sr_c->cfg->user_headers;
	sr_c->cfg->user_headers = &first_user_header;

	first_user_header.key = strdup("newname");
	first_user_header.value = strdup(newname);

	if (sr_c->cfg->realpath_filter) {
		mask = isMatchingPattern(sr_c->cfg, oldreal);
	} else {
		mask = isMatchingPattern(sr_c->cfg, oldname);
	}
	if ((mask && !(mask->accepting))
	    || (!mask && !(sr_c->cfg->accept_unmatched))) {
		if (sr_c->cfg->log_reject)
			log_msg(LOG_INFO, "rejecting oldname: %s\n", oldname);
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
	first_user_header.key = strdup("oldname");
	first_user_header.value = strdup(oldname);

	if (sr_c->cfg->realpath_filter) {
		mask = isMatchingPattern(sr_c->cfg, newreal);
	} else {
		mask = isMatchingPattern(sr_c->cfg, newname);
	}
	if ((mask && !(mask->accepting))
	    || (!mask && !(sr_c->cfg->accept_unmatched))) {
		if (sr_c->cfg->log_reject)
			log_msg(LOG_INFO, "rejecting newname: %s\n", newname);
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

	if (sr_c->cfg->post_broker->exchange_split) {
		for (int i = 0; i < sr_c->cfg->post_broker->exchange_split; i++) {
			sprintf(exchange, "%s%02d", sr_c->cfg->post_broker->exchange, i);
			log_msg(LOG_INFO, "deleting exchange %s%02d\n",
				sr_broker_uri(sr_c->cfg->post_broker), i);
			amqp_exchange_delete(sr_c->cfg->post_broker->conn, 1,
					     amqp_cstring_bytes(exchange), 0);
			reply = amqp_get_rpc_reply(sr_c->cfg->post_broker->conn);
			if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
				sr_amqp_reply_print(reply,
						    "failed AMQP get_rpc_reply exchange delete");
			}
		}
	} else {
		log_msg(LOG_INFO, "deleting exchange %s\n", sr_broker_uri(sr_c->cfg->post_broker));
		amqp_exchange_delete(sr_c->cfg->post_broker->conn, 1,
				     amqp_cstring_bytes(sr_c->cfg->post_broker->exchange), 0);
		reply = amqp_get_rpc_reply(sr_c->cfg->post_broker->conn);
		if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
			sr_amqp_reply_print(reply, "failed AMQP get_rpc_reply exchange delete");
		}
	}
	return (1);
}

int sr_post_init(struct sr_context *sr_c)
{
	char exchange[256];
	amqp_rpc_reply_t reply;

	if (sr_c->cfg->post_broker->exchange_split) {
		for (int i = 0; i < sr_c->cfg->post_broker->exchange_split; i++) {
			log_msg(LOG_DEBUG, "declaring exchange %s%02d\n",
				sr_broker_uri(sr_c->cfg->post_broker), i);
			sprintf(exchange, "%s%02d", sr_c->cfg->post_broker->exchange, i);
			amqp_exchange_declare(sr_c->cfg->post_broker->conn, 1,
					      amqp_cstring_bytes(exchange),
					      amqp_cstring_bytes("topic"), 0,
					      sr_c->cfg->durable, 0, 0, amqp_empty_table);
			reply = amqp_get_rpc_reply(sr_c->cfg->post_broker->conn);
			if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
				sr_amqp_reply_print(reply,
						    "failed AMQP get_rpc_reply exchange declare");
			}
		}
	} else {
		log_msg(LOG_DEBUG, "declaring exchange %s\n",
			sr_broker_uri(sr_c->cfg->post_broker));
		amqp_exchange_declare(sr_c->cfg->post_broker->conn, 1,
				      amqp_cstring_bytes(sr_c->cfg->post_broker->exchange),
				      amqp_cstring_bytes("topic"), 0,
				      sr_c->cfg->durable, 0, 0, amqp_empty_table);
		reply = amqp_get_rpc_reply(sr_c->cfg->post_broker->conn);
		if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
			sr_amqp_reply_print(reply, "failed AMQP get_rpc_reply exchange declare");
		}
	}

	return (1);
}
