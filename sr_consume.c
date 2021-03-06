/* vim:set ft=c ts=2 sw=2 sts=2 et cindent: */

/*
 * Usage info after license block.
 *
 * This code is by Peter Silva copyright (c) 2017 part of MetPX.
 * copyright is to the Government of Canada. code is GPL.
 *
 * based on a amqp_sendstring from rabbitmq-c package
 * the original license is below:
 */

/* 
  Minimal c implementation to allow posting of sr_post(7) messages.
  It has a lot of limitations, and no error checking for now.

  how to use:

  In a shell, to use an sr_subscribe(1) or sr_post(1) style configuration file. 
 
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <linux/limits.h>

#include <openssl/md5.h>
#include <openssl/sha.h>

#include <stdint.h>
#include <amqp_tcp_socket.h>
#include <amqp_ssl_socket.h>
#include <amqp.h>
#include <amqp_framing.h>

#ifdef HAVE_JSONC

#include <json-c/json.h>

#endif

#include "sr_config.h"
#include "sr_consume.h"

static struct sr_message_s msg;

int sr_consume_cleanup(struct sr_context *sr_c)
{
	amqp_rpc_reply_t reply;
	char p[PATH_MAX];

	amqp_queue_delete(sr_c->cfg->broker->conn, 1,
			  amqp_cstring_bytes(sr_c->cfg->queuename), 0, 0);

	reply = amqp_get_rpc_reply(sr_c->cfg->broker->conn);
	if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
		sr_amqp_reply_print(reply, "queue delete failed");
		return (0);
	}
	/* PS - should this be in sr_config? see sr_config_finalize for the other end of this
	 */

	sprintf(p, "%s/.cache/" SR_APPNAME "/%s/%s/sr_%s.%s.%s", getenv("HOME"),
		sr_c->cfg->progname, sr_c->cfg->configname, sr_c->cfg->progname,
		sr_c->cfg->configname, sr_c->cfg->broker->user);
	unlink(p);
	return (1);
}

int sr_consume_setup(struct sr_context *sr_c)
 /*
    declare a queue and bind it to the configured exchange.

  */
{
	amqp_rpc_reply_t reply;
	amqp_boolean_t passive = 0;
	amqp_boolean_t exclusive = 0;
	amqp_boolean_t auto_delete = 0;
	struct sr_topic_s *t;
	static amqp_basic_properties_t props;
	static amqp_table_t table;
	static amqp_table_entry_t table_entries[2];

	int tecnt = 0;

	// FIXME: would be nice to add something to the effect: content-encoding: utf8
	props._flags = AMQP_BASIC_CONTENT_TYPE_FLAG;
	props.content_type = amqp_cstring_bytes("text/plain");
	if (sr_c->cfg->expire > 0) {
		table_entries[tecnt].key = amqp_cstring_bytes("x-expires");
		table_entries[tecnt].value.kind = AMQP_FIELD_KIND_I64;
		table_entries[tecnt].value.value.i64 = (sr_c->cfg->expire * 1000);	// AMQP says milliseconds.
		tecnt++;
		props._flags |= AMQP_BASIC_EXPIRATION_FLAG;
	}

	if (sr_c->cfg->message_ttl > 0) {
		table_entries[tecnt].key = amqp_cstring_bytes("x-message-ttl");
		table_entries[tecnt].value.kind = AMQP_FIELD_KIND_I64;
		table_entries[tecnt].value.value.i64 = (sr_c->cfg->message_ttl * 1000);	// is in milliseconds.
		tecnt++;
		props._flags |= AMQP_BASIC_TIMESTAMP_FLAG;
	}
	table.num_entries = tecnt;
	table.entries = table_entries;

	props.delivery_mode = 2;	/* persistent delivery mode */
	props.headers = table;

	msg.user_headers = NULL;

	//amqp_queue_declare_ok_t *r = 
	amqp_queue_declare(sr_c->cfg->broker->conn,
			   1,
			   amqp_cstring_bytes(sr_c->cfg->queuename),
			   passive, sr_c->cfg->durable, exclusive, auto_delete, table);
	/* FIXME how to parse r for error? */

	reply = amqp_get_rpc_reply(sr_c->cfg->broker->conn);
	if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
		sr_amqp_reply_print(reply, "queue declare failed");
		return (0);
	}

	/*
	   FIXME: topic bindings are not working properly...
	 */
	if (!sr_c->cfg->topics) {
		sr_add_topic(sr_c->cfg, "#");
	}
	sr_log_msg(LOG_DEBUG, "topics: %p, string=+%p+\n", sr_c->cfg->topics, sr_c->cfg->topics);

	for (t = sr_c->cfg->topics; t; t = t->next) {
		amqp_queue_bind(sr_c->cfg->broker->conn, 1,
				amqp_cstring_bytes(sr_c->cfg->queuename),
				amqp_cstring_bytes(sr_c->cfg->broker->exchange),
				amqp_cstring_bytes(t->topic), amqp_empty_table);

		reply = amqp_get_rpc_reply(sr_c->cfg->broker->conn);
		if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
			sr_amqp_reply_print(reply, "binding failed");
			return (0);
		}
		sr_log_msg(LOG_INFO, "queue %s bound with topic %s to %s\n",
			sr_c->cfg->queuename, t->topic, sr_broker_uri(sr_c->cfg->broker));
	}
	return (1);
}

char *sr_message_partstr(struct sr_message_s *m)
{
	static char smallbuf[255];

	if ((m->sum[0] != 'R') && (m->sum[0] != 'L'))
		sprintf(smallbuf, "%c,%ld,%ld,%ld,%ld", m->parts_s,
			m->parts_blksz, m->parts_blkcount, m->parts_rem, m->parts_num);
	else
		memset(smallbuf, '\0', 255);

	return (smallbuf);
}

static void assign_field(const char *key, char *value)
 /* Assign the value of the field given by key to the corresponding member
    of the static msg struct.
  */
{
	char *s;
	struct sr_header_s *h;

	//sr_log_msg( LOG_DEBUG, "parsing: \"%s\" : \"%s\"\n", key, value );
	if (!strcmp(key, "atime")) {
		strcpy(msg.atime, value);
	} else if (!strcmp(key, "from_cluster")) {
		strcpy(msg.from_cluster, value);
	} else if (!strcmp(key, "mode")) {
		msg.mode = strtoul(value, NULL, 8);
	} else if (!strcmp(key, "mtime")) {
		strcpy(msg.mtime, value);
	} else if (!strcmp(key, "parts")) {
		//FIXME: no error checking, invalid parts header will cause a bobo.
		msg.parts_s = value[0];
		s = strtok(&(value[2]), ",");
		msg.parts_blksz = atol(s);
		s = strtok(NULL, ",");
		msg.parts_blkcount = atol(s);
		s = strtok(NULL, ",");
		msg.parts_rem = atol(s);
		s = strtok(NULL, ",");
		msg.parts_num = atol(s);
	} else if (!strcmp(key, "path")) {
		strcpy(msg.path, value);
	} else if (!strcmp(key, "source")) {
		strcpy(msg.source, value);
	} else if (!strcmp(key, "sum")) {
		strcpy(msg.sum, value);
	} else if (!strcmp(key, "to_clusters")) {
		strcpy(msg.to_clusters, value);
	} else if (!strcmp(key, "url")) {
		strcpy(msg.url, value);
	} else {
		h = (struct sr_header_s *)malloc(sizeof(struct sr_header_s));
		h->key = strdup(key);
		h->value = strdup(value);
		h->next = msg.user_headers;
		msg.user_headers = h;
	}
}

#ifdef HAVE_JSONC

static void v03assign_field(const char *key, json_object *jso_v)
 /* Assign the value of the field given by key to the corresponding member
    of the static msg struct.
  */
{
    static char unsupported[15];
	struct sr_header_s *h;
    size_t tlen;
    json_object *subvalue;

    strcpy(unsupported,"unsupported");

	if (!strcmp(key, "atime")) {
        if (!json_object_is_type(jso_v,json_type_string)) {
	       sr_log_msg( LOG_ERROR, "malformed json: atime is not a string: %d\n", json_object_get_type(subvalue) );
           return;
        }
		strcpy(msg.atime, json_object_get_string(jso_v));
        tlen=strlen(msg.atime);
        if ( tlen < 16 ) {
	       sr_log_msg( LOG_ERROR, "malformed json: atime should be string: %s\n", msg.atime );
           return;
        }
        tlen -= 8 ;
        memmove( &msg.atime[8], &msg.atime[9], tlen ); //eliminate "T".
	} else if (!strcmp(key, "blocks")) {

       json_object_object_get_ex(jso_v, "method", &subvalue );
       if (!strcmp(json_object_get_string(subvalue),"inplace")) {
           msg.parts_s='i';
       } else {
           msg.parts_s='p';
       }
       json_object_object_get_ex(jso_v, "size", &subvalue );
       if (json_object_is_type(subvalue,json_type_string)) {
		   msg.parts_blksz = atol(json_object_get_string(subvalue));
       } else if (json_object_is_type(subvalue,json_type_int)) {
		   msg.parts_blksz = json_object_get_int64(subvalue);
       } else {
	       sr_log_msg( LOG_ERROR, "malformed json: blocks/size should be an int, but is: %d\n", json_object_get_type(subvalue) );
       } 
       json_object_object_get_ex(jso_v, "remainder", &subvalue );
       if (json_object_is_type(subvalue,json_type_string)) {
		   msg.parts_rem = atol(json_object_get_string(subvalue));
       } else if (json_object_is_type(subvalue,json_type_int)) {
		   msg.parts_rem = json_object_get_int64(subvalue);
       } else {
	       sr_log_msg( LOG_ERROR, "malformed json: blocks/remainder should be an int, but is: %d\n", json_object_get_type(subvalue) );
       } 
      
       json_object_object_get_ex(jso_v, "number", &subvalue );
       if (json_object_is_type(subvalue,json_type_string)) {
		   msg.parts_num = atol(json_object_get_string(subvalue));
       } else if (json_object_is_type(subvalue,json_type_int)) {
		   msg.parts_num = json_object_get_int64(subvalue);
       } else {
	       sr_log_msg( LOG_ERROR, "malformed json: blocks/number should be an int, but is: %d\n", json_object_get_type(subvalue) );
       } 
      
       json_object_object_get_ex(jso_v, "count", &subvalue );
       if (json_object_is_type(subvalue,json_type_string)) {
		   msg.parts_blkcount = atol(json_object_get_string(subvalue));
       } else if (json_object_is_type(subvalue,json_type_int)) {
		   msg.parts_blkcount = json_object_get_int64(subvalue);
       } else {
	       sr_log_msg( LOG_ERROR, "malformed json: blocks/count should be an int, but is: %d\n", json_object_get_type(subvalue) );
       } 

	} else if (!strcmp(key, "from_cluster")) {
        if (!json_object_is_type(jso_v,json_type_string)) {
	       sr_log_msg( LOG_ERROR, "malformed json: from_cluster should be string: %d\n", json_object_get_type(jso_v) );
           return;
        }
		strcpy(msg.from_cluster, json_object_get_string(jso_v));
	} else if (!strcmp(key, "mode")) {
        if (!json_object_is_type(jso_v,json_type_string)) {
	       sr_log_msg( LOG_ERROR, "malformed json: mode should be string: %d\n", json_object_get_type(jso_v) );
           return;
        }
		msg.mode = strtoul(json_object_get_string(jso_v), NULL, 8);
	} else if (!strcmp(key, "mtime")) {
        if (!json_object_is_type(jso_v,json_type_string)) {
	       sr_log_msg( LOG_ERROR, "malformed message: mtime value is not a string: %d\n", json_object_get_type(jso_v) );
           return;
        }
		strcpy(msg.mtime, json_object_get_string(jso_v));
        tlen=strlen(msg.mtime);
        if ( tlen < 16 ) {
	       sr_log_msg( LOG_ERROR, "malformed json: mtime should be string: %s\n", msg.mtime );
           return;
        }
        tlen -= 8 ;
        memmove( &msg.mtime[8], &msg.mtime[9], tlen ); //eliminate "T".
	} else if (!strcmp(key, "baseUrl")) {
        if (!json_object_is_type(jso_v,json_type_string)) {
	       sr_log_msg( LOG_ERROR, "malformed json: baseUrl should be string: %d\n", json_object_get_type(jso_v) );
           return;
        }
        strcpy( msg.url, json_object_get_string(jso_v) );
	} else if (!strcmp(key, "relPath")) {
        if (!json_object_is_type(jso_v,json_type_string)) {
	       sr_log_msg( LOG_ERROR, "malformed json: relPath should be string: %d\n", json_object_get_type(jso_v) );
           return;
        }
        strcpy( msg.path, json_object_get_string(jso_v) );
	} else if (!strcmp(key, "pubTime")) {
        if (!json_object_is_type(jso_v,json_type_string)) {
	       sr_log_msg( LOG_ERROR, "malformed json: pubTime not a string: %d\n", json_object_get_type(jso_v) );
           return;
        }
        strcpy( msg.datestamp, json_object_get_string(jso_v) );
        tlen=strlen(msg.datestamp);
        if ( tlen < 16 ) {
	       sr_log_msg( LOG_ERROR, "malformed json: pubTime value too short: %s\n", msg.datestamp );
           return;
        }
        tlen -= 8 ;
        memmove( &msg.datestamp[8], &msg.datestamp[9], tlen ); //eliminate "T".
	} else if (!strcmp(key, "integrity")) {

       //FIXME
       if( json_object_get_type(jso_v) != json_type_object ) {
	       sr_log_msg( LOG_ERROR, "malformed json: integrity should be an object: %d\n", json_object_get_type(jso_v) );
           return;
       }
       json_object_object_get_ex(jso_v, "method", &subvalue);
       const char *v3m = json_object_get_string(subvalue);
       char s;
       s='u';
       if ( !strcmp( v3m, "random" ) ) s='0';
       if ( !strcmp( v3m, "arbitrary" ) ) s='a';
       if ( !strcmp( v3m, "md5" ) ) s='d';
       if ( !strcmp( v3m, "md5name" ) ) s='n';
       if ( !strcmp( v3m, "sha512name" ) ) s='p';
       if ( !strcmp( v3m, "sha512" ))  s='s';
       if ( !strcmp( v3m, "link" ) ) s='L';
       if ( !strcmp( v3m, "remove" ) ) s='R';
       if ( !strcmp( v3m, "cod" ) ) s='z';
       if ( s == 'u' ) {
	       sr_log_msg( LOG_ERROR, "unknown checksum specified: %s\n", v3m );
           return;
       }
       json_object_object_get_ex(jso_v, "value", &subvalue);
       const char *v = json_object_get_string(subvalue);
       
       if ( ! strchr("0az",s) ) {
            v = sr_base642hex(v);
       }
       sprintf( msg.sum, "%c,%s", s, v );
       return;   

	} else if (!strcmp(key, "size")) {
		//FIXME: no error checking, invalid parts header will cause a bobo.
		msg.parts_s = '1';
		msg.parts_blksz = atol(json_object_get_string(jso_v));
		msg.parts_blkcount = 1;
		msg.parts_rem = 0;
		msg.parts_num = 0;
	} else if (!strcmp(key, "relPath")) {
        if (!json_object_is_type(jso_v,json_type_string)) {
	       sr_log_msg( LOG_ERROR, "malformed json: relPath value should be string: %d\n", json_object_get_type(jso_v) );
           return;
        }
		strcpy(msg.path,  json_object_get_string(jso_v));
	} else if (!strcmp(key, "source")) {
        if (!json_object_is_type(jso_v,json_type_string)) {
	       sr_log_msg( LOG_ERROR, "malformed json: source value should be string: %d\n", json_object_get_type(jso_v) );
           return;
        }
		strcpy(msg.source,  json_object_get_string(jso_v));
	} else if (!strcmp(key, "to_clusters")) {
        if (!json_object_is_type(jso_v,json_type_string)) {
	       sr_log_msg( LOG_ERROR, "malformed json: to_clusters should be string: %d\n", json_object_get_type(jso_v) );
           return;
        }
		strcpy(msg.to_clusters,  json_object_get_string(jso_v));
	} else {
		h = (struct sr_header_s *)malloc(sizeof(struct sr_header_s));
		h->key = strdup(key);
        if (json_object_is_type(jso_v,json_type_string)) {
		     h->value = strdup(json_object_get_string(jso_v));
        } else {
             h->value = strdup(unsupported) ;
        }
		h->next = msg.user_headers;
		msg.user_headers = h;
	}
}

#endif

static void json_dump_strheader(char *tag, char *value)
{
	printf("\"%s\": \"%s\"", tag, value);
}

char *sr_message_2log(struct sr_message_s *m)
{
	static char b[10240];	// FIXME!  need more than 10K for a log message? check?

	sprintf(b, "%s %s %s topic=%s", m->datestamp, m->url, m->path, m->routing_key);
	sprintf(strchr(b, '\0'), " sum=%s source=%s", m->sum, m->source);
	sprintf(strchr(b, '\0'), " to_clusters=%s from_cluster=%s",
		m->to_clusters, m->from_cluster);

	if ((m->sum[0] != 'R') && (m->sum[0] != 'L')) {
		sprintf(strchr(b, '\0'), " mtime=%s atime=%s", m->mtime, m->atime);

		if (m->mode)
			sprintf(strchr(b, '\0'), " mode=%04o", m->mode);

		sprintf(strchr(b, '\0'), " parts=%c,%ld,%ld,%ld,%ld",
			m->parts_s, m->parts_blksz, m->parts_blkcount, m->parts_rem, m->parts_num);
	}

	if (m->sum[0] == 'L') {
		sprintf(strchr(b, '\0'), " link=%s", m->link);
	}

	if (m->rename[0])
		sprintf(strchr(b, '\0'), " rename=%s", m->rename);

	for (struct sr_header_s * h = m->user_headers; h; h = h->next) 
    {
		sprintf(strchr(b, '\0'), " %s=%s", h->key, h->value);
    }
	return (b);
}

void sr_message_2json(struct sr_message_s *m)
{
	struct sr_header_s *h;

	printf("[");
	printf(" \"%s\", { ", m->routing_key);
	json_dump_strheader("atime", m->atime);
	printf(", ");
	printf("\"mode\": \"%04o\"", m->mode);
	printf(", ");
	json_dump_strheader("mtime", m->mtime);
	printf(", ");
	printf("\"parts\": \"%c,%ld,%ld,%ld,%ld\"",
	       m->parts_s, m->parts_blksz, m->parts_blkcount, m->parts_rem, m->parts_num);
	printf(", ");
	json_dump_strheader("from_cluster", m->from_cluster);
	printf(", ");
	json_dump_strheader("source", m->source);
	printf(", ");
	json_dump_strheader("sum", m->sum);
	printf(", ");
	json_dump_strheader("to_clusters", m->to_clusters);

	for (h = msg.user_headers; h; h = h->next) {
		printf(", ");
		json_dump_strheader(h->key, h->value);
	}
	printf(" } \"%s %s  %s\"", m->datestamp, m->url, m->path);
	printf("]\n");
}

void sr_message_2url(struct sr_message_s *m)
{
	printf("%s/%s\n", m->url, m->path);
}

struct sr_message_s *sr_consume(struct sr_context *sr_c)
 /*
    blocking read messages from queue. 

  */
{
	amqp_rpc_reply_t reply;
	amqp_frame_t frame;
	int result;
	static char buf[SR_SARRAC_MAXIMUM_MESSAGE_LEN];
	amqp_basic_deliver_t *d;
	amqp_basic_properties_t *p;
	int is_report;
	static char consumer_tag[AMQP_MAX_SS];
	char *tok;
	size_t body_target;
	size_t body_received;
	char tag[AMQP_MAX_SS];
	char value[AMQP_MAX_SS];
	struct sr_header_s *tmph;

	while (msg.user_headers) {
		tmph = msg.user_headers;
		free(tmph->key);
		free(tmph->value);
		msg.user_headers = tmph->next;
		free(tmph);
	}

	/*
	   basic_ack added as per michel's algorithm prior to consuming next.
	   formerly was:  acked on receipt, which meant if the consumer crashed before
	   it finished, the message would not be requeued.  
	   now:  only ack when starting to work on next message.
	 */
	/*
	   if (sr_c->cfg->broker->last_delivery_tag > 0)
	   {
	   sr_log_msg( LOG_DEBUG, "acking: %d\n", sr_c->cfg->broker->last_delivery_tag );
	   result = amqp_basic_ack( sr_c->cfg->broker->conn, 1, sr_c->cfg->broker->last_delivery_tag, 0 );

	   reply = amqp_get_rpc_reply(sr_c->cfg->broker->conn);
	   if (reply.reply_type != AMQP_RESPONSE_NORMAL ) 
	   {
	   sr_amqp_reply_print(reply, "basic_ack failed");
	   return(NULL);
	   }
	   }
	 */
	/*
	   FIXME: consume initializes consumer, then use consume_message later... not sure where to put this.
	   should probably move into another routine.
	 */
	if (!sr_c->cfg->broker->started) {

		amqp_basic_qos(sr_c->cfg->broker->conn, 1, 0, (uint16_t) (sr_c->cfg->prefetch), 0);
		reply = amqp_get_rpc_reply(sr_c->cfg->broker->conn);
		if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
			sr_amqp_reply_print(reply, "basic_consume failed");
			return (NULL);
		}
		sprintf(consumer_tag, "host_%s_pid_%d", sr_local_fqdn(), sr_c->cfg->pid);

		amqp_basic_consume(sr_c->cfg->broker->conn, 1,
				   amqp_cstring_bytes(sr_c->cfg->queuename),
				   //amqp_empty_bytes, // consumer_tag
				   amqp_cstring_bytes(consumer_tag), 0,	// no_local
				   1,	// no_ack ( == auto-ack ) - if set to 1, then comment out basic_ack code above.
				   0,	// not_exclusive
				   amqp_empty_table);

		reply = amqp_get_rpc_reply(sr_c->cfg->broker->conn);
		if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
			sr_amqp_reply_print(reply, "basic_consume failed");
			return (NULL);
		}
		sr_c->cfg->broker->started = 1;
	}

	amqp_maybe_release_buffers(sr_c->cfg->broker->conn);
	result = amqp_simple_wait_frame(sr_c->cfg->broker->conn, &frame);

	if (result < 0) {
	    sr_log_msg( LOG_ERROR, "wait_frame bad result: %d. aborting connection.\n", result);
		return (NULL);
	}

	if (frame.frame_type != AMQP_FRAME_METHOD) {
	    sr_log_msg( LOG_ERROR, "bad FRAME_METHOD: %d. aborting connection.\n", frame.frame_type);
		return (NULL);
	}
	if (frame.payload.method.id != AMQP_BASIC_DELIVER_METHOD) {
	    sr_log_msg( LOG_ERROR, "bad payload method: %d. aborting connection.\n", frame.payload.method.id );
		return (NULL);
	}

	d = (amqp_basic_deliver_t *) frame.payload.method.decoded;

	sr_log_msg( LOG_DEBUG, "Frame type %d, channel %d Method %s consumer_tag: %s, delivery_tag: %ld\n",
        frame.frame_type, frame.channel, amqp_method_name(frame.payload.method.id), 
    		(char *)d->consumer_tag.bytes, (long)(d->delivery_tag));

	sr_c->cfg->broker->last_delivery_tag = d->delivery_tag;

	sr_log_msg( LOG_DEBUG, "exchange: \"%.*s\", routingkey: \"%.*s\",\n",
	   (int) d->exchange.len, (char *) d->exchange.bytes,
	   (int) d->routing_key.len, (char *) d->routing_key.bytes);

	sprintf(msg.exchange, "%.*s", (int)d->exchange.len, (char *)d->exchange.bytes);
	sprintf(msg.routing_key, "%.*s", (int)d->routing_key.len, (char *)d->routing_key.bytes);

	is_report = (!strncmp(d->routing_key.bytes, "v02.report", 10));

	result = amqp_simple_wait_frame(sr_c->cfg->broker->conn, &frame);

	if (result < 0) {
		sr_log_msg(LOG_ERROR, "error receiving frame! aborting connection.");
		return(NULL);
    }

	if (frame.frame_type != AMQP_FRAME_HEADER) {
		sr_log_msg(LOG_ERROR, "Expected header! aborting connection.");
		return(NULL);
	}

	p = (amqp_basic_properties_t *) frame.payload.properties.decoded;

    /* FIXME */
    if (p->_flags & AMQP_BASIC_CONTENT_TYPE_FLAG) {
	      sr_log_msg(LOG_DEBUG, "Content-type: %.*s  frame.payload.properties.class_id: %d body_size: %ld\n", 
              (int)p->content_type.len, (char *)p->content_type.bytes, frame.payload.properties.class_id,
                 (long)frame.payload.properties.body_size );
    }

    if (p->_flags & AMQP_BASIC_HEADERS_FLAG) { 
        sr_log_msg(LOG_DEBUG, "AMQP_BASIC_HEADERS_FLAG set. %d headers in message\n", p->headers.num_entries );
    	for (int i = 0; i < p->headers.num_entries; i++) {
    
            // FIXME: bug where num_entries==2, and entries=2 instead of a pointer.... very odd.
            //        We have no idea why this shows up, this is just a work-around, around the problem.
            if ( (unsigned long)(p->headers.entries) < 1024 )  {
    			sr_log_msg(LOG_ERROR, 
                     "corrupted message, num_entries > 0 (%d), but entries close to NULL (%p).\n", 
                     p->headers.num_entries, (p->headers.entries) );
                goto after_headers;
            } else switch (p->headers.entries[i].value.kind) {
                case AMQP_FIELD_KIND_I8:
                    sr_log_msg(LOG_WARNING, "skipping I8 header %d value:%d\n", i, (p->headers.entries[i].value.value.i8) );
                    goto after_headers;
                    break;
    
                case AMQP_FIELD_KIND_TIMESTAMP:
                    sr_log_msg(LOG_WARNING, "skipping TIMESTAMP header %d value:%lld\n", i, (long long unsigned)(p->headers.entries[i].value.value.u64) );
                    break;
    
                case AMQP_FIELD_KIND_UTF8:
        			sprintf(tag, "%.*s",
        				(int)p->headers.entries[i].key.len,
        				(char *)p->headers.entries[i].key.bytes);
        
        			sprintf(value, "%.*s",
        				(int)p->headers.entries[i].value.value.bytes.len,
        				(char *)p->headers.entries[i].value.value.bytes.bytes);
        
        			assign_field(tag, value);
        
        			/*
        			   sr_log_msg( stdout, "\t\"%.*s\": \"%.*s\",\n",
        			   (int) p->headers.entries[i].key.len, 
        			   (char *) p->headers.entries[i].key.bytes,
        			   (int) p->headers.entries[i].value.value.bytes.len,
        			   (char *) p->headers.entries[i].value.value.bytes.bytes
        			   );
        			 */
                    break;
    
                case AMQP_FIELD_KIND_U64:
    		    sr_log_msg(LOG_WARNING, "skipping U64 header %d value:%lld\n", i, (long long unsigned)(p->headers.entries[i].value.value.u64) );
                    goto after_headers;
                    break;
    
    
                case AMQP_FIELD_KIND_ARRAY:
    		    sr_log_msg(LOG_WARNING, "skipping ARRAY header index: %d\n", i );
                    goto after_headers;
                    break;
    
    
                case AMQP_FIELD_KIND_I64:
    		    sr_log_msg(LOG_WARNING, "skipping I64  header %d: value:%lld\n", i, (long long)(p->headers.entries[i].value.value.i64) );
                    goto after_headers;
                    break;
    
                default:
    			    sr_log_msg(LOG_WARNING, "skipping non UTF8 headers: amount: %d, this one: %d, kind:%d\n", 
                          p->headers.num_entries, i, p->headers.entries[i].value.kind );
                    goto after_headers;
                    
            }
    	}
    } else {
        sr_log_msg( LOG_DEBUG, "message has no headers. Good.\n" );
    }

after_headers:
	body_target = frame.payload.properties.body_size;
	body_received = 0;

    if (body_target >= SR_SARRAC_MAXIMUM_MESSAGE_LEN) {
			sr_log_msg(LOG_CRITICAL, "Message too big! received: (%ld bytes) max: %d",
                 (long)body_target, SR_SARRAC_MAXIMUM_MESSAGE_LEN );
			abort();
    }

	while (body_received < body_target) {
		result = amqp_simple_wait_frame(sr_c->cfg->broker->conn, &frame);

		if (result < 0) {
	        sr_log_msg(LOG_WARNING, "broken message received: wait_frame returned %d. aborting connection.\n",  result );
			return (NULL);
        }
		if (frame.frame_type != AMQP_FRAME_BODY) {
			sr_log_msg(LOG_CRITICAL, "Expected body! aborting connection.");
			abort();
		}

		strncpy( &(buf[body_received]), (char *)frame.payload.body_fragment.bytes,
			(int)frame.payload.body_fragment.len );

		body_received += frame.payload.body_fragment.len;
	        sr_log_msg(LOG_DEBUG, "message body frame received: %lu bytes \n", (unsigned long)frame.payload.body_fragment.len );

		buf[body_received] = '\0';
    }

    if (body_received != body_target) {
	    sr_log_msg(LOG_ERROR, "incomplete message, received: %lu bytes, expected: %lu bytes.\n",  (long)body_received, (long)body_target );
		return (NULL);
    } else {
	    sr_log_msg(LOG_DEBUG, "complete message, received: %lu bytes \n",  (unsigned long)body_received );
    }
	//amqp_maybe_release_buffers(sr_c->cfg->broker->conn);

	/* Can only happen when amqp_simple_wait_frame returns <= 0 */
	/* We break here to close the connection */

    if ( buf[0] != '{' ) { // v02.
   		    tok = strtok(buf, " ");
    		//fprintf( stdout, "\t\"datestamp\" : \"%s\",\n", tok);
    		strcpy(msg.datestamp, tok);
    		tok = strtok(NULL, " ");
    		//fprintf( stdout, "\t\"url\" : \"%s\", \n", tok);
    		strcpy(msg.url, tok);
    		tok = strtok(NULL, " ");
    		//fprintf( stdout, "\t\"path\" : \"%s\", \n", tok);
    		strcpy(msg.path, tok);
    		if (is_report) {
    			tok = strtok(NULL, " ");
    			//fprintf( stdout, "\t\"statuscode\" : \"%s\", \n", tok);
    			msg.statuscode = atoi(tok);
    			tok = strtok(NULL, " ");
    			//fprintf( stdout, "\t\"consumingurl\" : \"%s\", \n", tok);
    			strcpy(msg.consumingurl, tok);
    			tok = strtok(NULL, " ");
    			//fprintf( stdout, "\t\"consuminguser\" : \"%s\", \n", tok);
    			strcpy(msg.consuminguser, tok);
    			tok = strtok(NULL, " ");
    			//fprintf( stdout, "\t\"duration\" : \"%s\", \n", tok);
    			msg.duration = (float)(atof(tok));
    		} else {
    			msg.statuscode = 0;
    			msg.consumingurl[0] = '\0';
    			msg.consuminguser[0] = '\0';
    			msg.duration = 0.0;

    		}


    } else { // v03

#ifdef HAVE_JSONC
            json_object *jo = NULL;

            jo = json_tokener_parse( buf );

            if (jo == NULL) {
			    sr_log_msg( LOG_ERROR, "failed to parse message body: %s", buf);
                return(NULL);
            } else {
			    sr_log_msg( LOG_DEBUG, "successfully parsed message body: %s", buf);
            }
            json_object_object_foreach( jo, k, jso_kv ) {
                v03assign_field(k, jso_kv);
            }
            json_object_put(jo); //attempting to free everything?
            jo=NULL;
#else
            sr_log_msg( LOG_ERROR, "v03 parsing not compiled in, recompile with libjson-c support\n" );
#endif

    }

    /* Can only happen when amqp_simple_wait_frame returns <= 0 */
    /* We break here to close the connection */
    return (&msg);
}
