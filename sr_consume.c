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
#include <stdbool.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <linux/limits.h>

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include <stdbool.h>
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

signed int sr_consume_queue_declare(struct sr_context *sr_c, amqp_boolean_t passive)
 /*
    declare a queue it to the configured exchange.

    passive means don't actually declare the queue, just pretend, used to get the message count


    returns true if successful

  */
{
	amqp_rpc_reply_t reply;
	amqp_boolean_t exclusive = 0;
	amqp_boolean_t auto_delete = 0;
	amqp_queue_declare_ok_t *r;
	static amqp_basic_properties_t props;
	static amqp_table_t table;
	static amqp_table_entry_t table_entries[2];
	signed int message_count;

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
	message_count=-2;
	if (sr_c->cfg->queueDeclare) {
		r = amqp_queue_declare(sr_c->cfg->broker->conn,
				   2,
				   amqp_cstring_bytes(sr_c->cfg->queuename),
				   passive, sr_c->cfg->durable, exclusive, auto_delete, table);
		/* FIXME how to parse r for error? */
                
		if (r) {
	               sr_log_msg(LOG_INFO, "queue declared: %s messages in queue: %d\n", 
		                sr_c->cfg->queuename, r->message_count );
		       message_count = r->message_count;
		       sr_c->metrics.brokerQueuedMessageCount = message_count;
                }
		reply = amqp_get_rpc_reply(sr_c->cfg->broker->conn);
		if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
			sr_amqp_reply_print(reply, "queue declare failed");
			message_count = -1;
		}
	}
	return(message_count);
}

bool sr_consume_setup(struct sr_context *sr_c)
{
	struct sr_binding_s *t;
	amqp_rpc_reply_t reply;
	int messageCount;

        messageCount = sr_consume_queue_declare(sr_c, 0);

	if (messageCount< 0 ) {
		return(false);
        }

	/*
	   FIXME: topic bindings are not working properly...
	 */
	if (!sr_c->cfg->bindings) {
		sr_add_binding(sr_c->cfg, "#");
	}
	sr_log_msg(LOG_DEBUG, "bindings: %p, string=+%p+\n", sr_c->cfg->bindings,
		   sr_c->cfg->bindings);

	for (t = sr_c->cfg->bindings; t; t = t->next) {
		amqp_queue_bind(sr_c->cfg->broker->conn, 1,
				amqp_cstring_bytes(sr_c->cfg->queuename),
				amqp_cstring_bytes(t->exchange),
				amqp_cstring_bytes(t->topic), amqp_empty_table);

		reply = amqp_get_rpc_reply(sr_c->cfg->broker->conn);
		if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
			sr_amqp_reply_print(reply, "binding failed");
			return (false);
		}
		sr_log_msg(LOG_INFO, "queue %s bound with topic %s to %s\n",
			   sr_c->cfg->queuename, t->topic, sr_broker_uri(sr_c->cfg->broker));
	}
	return (true);
}

char *sr_message_partstr(struct sr_message_s *m)
{
	static char smallbuf[255];

	if ((m->sum[0] != 'R') && (m->sum[0] != 'L') && (m->sum[0] != 'm') && (m->sum[0] != 'r'))
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
		strcpy(msg.relPath, value);
	} else if (!strcmp(key, "source")) {
		strcpy(msg.source, value);
	} else if (!strcmp(key, "sum")) {
		strcpy(msg.sum, value);
	} else if (!strcmp(key, "url")) {
		strcpy(msg.url, value);
	} else {
		h = (struct sr_header_s *)malloc(sizeof(struct sr_header_s));
		h->key = strdup(key);
		h->value = strdup(value);
		h->is_numeric = false;
		h->next = msg.user_headers;
		msg.user_headers = h;
	}
}

const char *sum2identity(char sum)
{
	switch (sum) {
	case '0':
		return ("random");
	case 'a':
		return ("arbitrary");
	case 'd':
		return ("md5");
	case 'n':
		return ("md5name");
	case 'p':
		return ("sha512name");
	case 's':
		return ("sha512");
	case 'L':
		return ("link");
	case 'R':
		return ("remove");
	case 'm':
		return ("directory");
	case 'r':
		return ("rmdir");
	case 'z':
		return ("cod");
	default:
		return ("unknown");
	}

}

char *v03identity(struct sr_message_s *m)
{
	static char istr[1024];
	const char *value;

	switch (m->sum[0]) {
	case 'n':
	case 'L':
	case 'R':
	case 'm':
	case 'r':
		return (NULL);
		break;
	case 'd':
	case 's':
		value = sr_hex2base64(&(m->sum[2]));
		break;
	case 'z':
		value = sum2identity(m->sum[2]);
		break;
	case '0':
	case 'a':
	default:
		value = &(m->sum[2]);
		break;
	}
	sprintf(istr, " \"method\" : \"%s\", \"value\" : \"%s\" ", sum2identity(m->sum[0]), value);
	return (istr);

}

#ifdef HAVE_JSONC

static void v03assign_field(const char *key, json_object * jso_v)
 /* Assign the value of the field given by key to the corresponding member
    of the static msg struct.
  */
{
	static char unsupported[15];
	struct sr_header_s *h;
	size_t tlen;
	json_object *subvalue;

	strcpy(unsupported, "unsupported");

	if (!strcmp(key, "atime")) {
		if (!json_object_is_type(jso_v, json_type_string)) {
			sr_log_msg(LOG_ERROR, "malformed json: atime is not a string: %d\n",
				   json_object_get_type(subvalue));
			return;
		}
		strcpy(msg.atime, json_object_get_string(jso_v));
		tlen = strlen(msg.atime);
		if (tlen < 16) {
			sr_log_msg(LOG_ERROR, "malformed json: atime should be string: %s\n",
				   msg.atime);
			return;
		}
		tlen -= 8;
		memmove(&msg.atime[8], &msg.atime[9], tlen);	//eliminate "T".
	} else if (!strcmp(key, "blocks")) {

		json_object_object_get_ex(jso_v, "method", &subvalue);
		if (!strcmp(json_object_get_string(subvalue), "inplace")) {
			msg.parts_s = 'i';
		} else {
			msg.parts_s = 'p';
		}
		json_object_object_get_ex(jso_v, "size", &subvalue);
		if (json_object_is_type(subvalue, json_type_string)) {
			msg.parts_blksz = atol(json_object_get_string(subvalue));
		} else if (json_object_is_type(subvalue, json_type_int)) {
			msg.parts_blksz = json_object_get_int64(subvalue);
		} else {
			sr_log_msg(LOG_ERROR,
				   "malformed json: blocks/size should be an int, but is: %d\n",
				   json_object_get_type(subvalue));
		}
		json_object_object_get_ex(jso_v, "remainder", &subvalue);
		if (json_object_is_type(subvalue, json_type_string)) {
			msg.parts_rem = atol(json_object_get_string(subvalue));
		} else if (json_object_is_type(subvalue, json_type_int)) {
			msg.parts_rem = json_object_get_int64(subvalue);
		} else {
			sr_log_msg(LOG_ERROR,
				   "malformed json: blocks/remainder should be an int, but is: %d\n",
				   json_object_get_type(subvalue));
		}
		json_object_object_get_ex(jso_v, "number", &subvalue);
		if (json_object_is_type(subvalue, json_type_string)) {
			msg.parts_num = atol(json_object_get_string(subvalue));
		} else if (json_object_is_type(subvalue, json_type_int)) {
			msg.parts_num = json_object_get_int64(subvalue);
		} else {
			sr_log_msg(LOG_ERROR,
				   "malformed json: blocks/number should be an int, but is: %d\n",
				   json_object_get_type(subvalue));
		}
		json_object_object_get_ex(jso_v, "count", &subvalue);
		if (json_object_is_type(subvalue, json_type_string)) {
			msg.parts_blkcount = atol(json_object_get_string(subvalue));
		} else if (json_object_is_type(subvalue, json_type_int)) {
			msg.parts_blkcount = json_object_get_int64(subvalue);
		} else {
			sr_log_msg(LOG_ERROR,
				   "malformed json: blocks/count should be an int, but is: %d\n",
				   json_object_get_type(subvalue));
		}
	} else if (!strcmp(key, "mode")) {
		if (!json_object_is_type(jso_v, json_type_string)) {
			sr_log_msg(LOG_ERROR, "malformed json: mode should be string: %d\n",
				   json_object_get_type(jso_v));
			return;
		}
		msg.mode = strtoul(json_object_get_string(jso_v), NULL, 8);
	} else if (!strcmp(key, "mtime")) {
		if (!json_object_is_type(jso_v, json_type_string)) {
			sr_log_msg(LOG_ERROR,
				   "malformed message: mtime value is not a string: %d\n",
				   json_object_get_type(jso_v));
			return;
		}
		strcpy(msg.mtime, json_object_get_string(jso_v));
		tlen = strlen(msg.mtime);
		if (tlen < 16) {
			sr_log_msg(LOG_ERROR, "malformed json: mtime should be string: %s\n",
				   msg.mtime);
			return;
		}
		tlen -= 8;
		memmove(&msg.mtime[8], &msg.mtime[9], tlen);	//eliminate "T".
	} else if (!strcmp(key, "baseUrl")) {
		if (!json_object_is_type(jso_v, json_type_string)) {
			sr_log_msg(LOG_ERROR, "malformed json: baseUrl should be string: %d\n",
				   json_object_get_type(jso_v));
			return;
		}
		strcpy(msg.url, json_object_get_string(jso_v));
	} else if (!strcmp(key, "relPath")) {
		if (!json_object_is_type(jso_v, json_type_string)) {
			sr_log_msg(LOG_ERROR, "malformed json: relPath should be string: %d\n",
				   json_object_get_type(jso_v));
			return;
		}
		strcpy(msg.relPath, json_object_get_string(jso_v));
		if (strlen(msg.relPath) == 0) {
			sr_log_msg(LOG_ERROR, "malformed message: relPath is empty string.\n");
			return;
		}
	} else if (!strcmp(key, "pubTime")) {
		if (!json_object_is_type(jso_v, json_type_string)) {
			sr_log_msg(LOG_ERROR, "malformed json: pubTime not a string: %d\n",
				   json_object_get_type(jso_v));
			return;
		}
		strcpy(msg.datestamp, json_object_get_string(jso_v));
		sr_log_msg(LOG_CRITICAL, "v03assign_field 0 msg.datestamp: %s\n", msg.datestamp );
		tlen = strlen(msg.datestamp);
		if (tlen < 16) {
			sr_log_msg(LOG_ERROR, "malformed json: pubTime value too short: %s\n",
				   msg.datestamp);
			return;
		}
		if ((strlen(msg.datestamp) > 8) && ( msg.datestamp[8] == 'T' )) {
		    tlen -= 8;
		    memmove(&msg.datestamp[8], &msg.datestamp[9], tlen);	//eliminate "T".
                }
		sr_log_msg(LOG_CRITICAL, "v03assign_field 1 msg.datestamp: %s\n", msg.datestamp );
	} else if (!strcmp(key, "fileOp")) {
		if (json_object_get_type(jso_v) != json_type_object) {
			sr_log_msg(LOG_ERROR, "malformed json: identity should be an object: %d\n",
				   json_object_get_type(jso_v));
			return;
		}

		EVP_MD_CTX *ctx;
		const EVP_MD *md;

		unsigned int hashlen = 0;
		unsigned char sumhash[SR_SUMHASHLEN];

		if (json_object_object_get_ex(jso_v, "link", &subvalue)) {
			const char *v = json_object_get_string(subvalue);
			sr_log_msg(LOG_ERROR, "link subvalue: %s\n", v);
			strcpy(msg.link, v);
			sr_log_msg(LOG_ERROR, "copied to msg.link: %s\n", msg.link);

			ctx = EVP_MD_CTX_create();
			md = EVP_sha512();
			EVP_DigestInit_ex(ctx, md, NULL);
			EVP_DigestUpdate(ctx, v, strlen(v));
			EVP_DigestFinal_ex(ctx, sumhash, &hashlen);
			sprintf(msg.sum, "L,%s", sr_hash2sumstr(sumhash));
			return;
		} else if (json_object_object_get_ex(jso_v, "remove", &subvalue)) {
			char *just_the_name;
			if (strlen(msg.relPath) > 0) {
				just_the_name = rindex(msg.relPath, '/');
				just_the_name = just_the_name ? just_the_name + 1 : msg.relPath;
			} else {
				// FIXME should defer to end of parse and find the real name.
				// This is a bug, but nobody does mirroring with v2 anyways.
				just_the_name = "placeholder";
			}
			ctx = EVP_MD_CTX_create();
			md = EVP_sha512();
			EVP_DigestInit_ex(ctx, md, NULL);
			EVP_DigestUpdate(ctx, just_the_name, strlen(just_the_name));
			EVP_DigestFinal_ex(ctx, sumhash, &hashlen);
			sprintf(msg.sum, "R,%s", sr_hash2sumstr(sumhash));
			return;
		} else if (json_object_object_get_ex(jso_v, "directory", &subvalue)) {
			char *just_the_name;
			if (strlen(msg.relPath) > 0) {
				just_the_name = rindex(msg.relPath, '/');
				just_the_name = just_the_name ? just_the_name + 1 : msg.relPath;
			} else {
				// FIXME should defer to end of parse and find the real name.
				// This is a bug, but nobody does mirroring with v2 anyways.
				just_the_name = "placeholder";
			}
			ctx = EVP_MD_CTX_create();
			md = EVP_sha512();
			EVP_DigestInit_ex(ctx, md, NULL);
			EVP_DigestUpdate(ctx, just_the_name, strlen(just_the_name));
			EVP_DigestFinal_ex(ctx, sumhash, &hashlen);
			sprintf(msg.sum, "m,%s", sr_hash2sumstr(sumhash));
			return;
		} else if (json_object_object_get_ex(jso_v, "rmdir", &subvalue)) {
			char *just_the_name;
			if (strlen(msg.relPath) > 0) {
				just_the_name = rindex(msg.relPath, '/');
				just_the_name = just_the_name ? just_the_name + 1 : msg.relPath;
			} else {
				// FIXME should defer to end of parse and find the real name.
				// This is a bug, but nobody does mirroring with v2 anyways.
				just_the_name = "placeholder";
			}
			ctx = EVP_MD_CTX_create();
			md = EVP_sha512();
			EVP_DigestInit_ex(ctx, md, NULL);
			EVP_DigestUpdate(ctx, just_the_name, strlen(just_the_name));
			EVP_DigestFinal_ex(ctx, sumhash, &hashlen);
			sprintf(msg.sum, "r,%s", sr_hash2sumstr(sumhash));
			return;
		} else if (json_object_object_get_ex(jso_v, "rename", &subvalue)) {
			const char *v = json_object_get_string(subvalue);
			h = (struct sr_header_s *)malloc(sizeof(struct sr_header_s));
			h->key = strdup("oldname");
			h->value = strdup(v);
			h->next = msg.user_headers;
			h->is_numeric = false;
			msg.user_headers = h;
		}
	} else if (!strcmp(key,"identity") || (!strcmp(key, "integrity"))) {

		//FIXME
		if (json_object_get_type(jso_v) != json_type_object) {
			sr_log_msg(LOG_ERROR, "malformed json: identity should be an object: %d\n",
				   json_object_get_type(jso_v));
			return;
		}
		json_object_object_get_ex(jso_v, "method", &subvalue);
		const char *v3m = json_object_get_string(subvalue);
		char s;
		s = 'u';
		if (!strcmp(v3m, "random"))
			s = '0';
		if (!strcmp(v3m, "arbitrary"))
			s = 'a';
		if (!strcmp(v3m, "md5"))
			s = 'd';
		if (!strcmp(v3m, "md5name"))
			s = 'n';
		if (!strcmp(v3m, "sha512name"))
			s = 'p';
		if (!strcmp(v3m, "sha512"))
			s = 's';
		if (!strcmp(v3m, "cod"))
			s = 'z';
		if (s == 'u') {
			sr_log_msg(LOG_ERROR, "unknown checksum specified: %s\n", v3m);
			return;
		}
		json_object_object_get_ex(jso_v, "value", &subvalue);
		const char *v = json_object_get_string(subvalue);

		if (!strchr("0az", s)) {
			v = sr_base642hex(v);
		}
		sprintf(msg.sum, "%c,%s", s, v);
		return;

	} else if (!strcmp(key, "size")) {
		//FIXME: no error checking, invalid parts header will cause a bobo.
		msg.parts_s = '1';
		msg.parts_blksz = atol(json_object_get_string(jso_v));
		msg.parts_blkcount = 1;
		msg.parts_rem = 0;
		msg.parts_num = 0;
	} else if (!strcmp(key, "relPath")) {
		if (!json_object_is_type(jso_v, json_type_string)) {
			sr_log_msg(LOG_ERROR,
				   "malformed json: relPath value should be string: %d\n",
				   json_object_get_type(jso_v));
			return;
		}
		strcpy(msg.relPath, json_object_get_string(jso_v));
	} else if (!strcmp(key, "source")) {
		if (!json_object_is_type(jso_v, json_type_string)) {
			sr_log_msg(LOG_ERROR, "malformed json: source value should be string: %d\n",
				   json_object_get_type(jso_v));
			return;
		}
		strcpy(msg.source, json_object_get_string(jso_v));
	} else {
		h = (struct sr_header_s *)malloc(sizeof(struct sr_header_s));
		h->key = strdup(key);
		if (json_object_is_type(jso_v, json_type_string)) {
			h->value = strdup(json_object_get_string(jso_v));
		} else {
			h->value = strdup(unsupported);
		}
		h->is_numeric = false;
		h->next = msg.user_headers;
		msg.user_headers = h;
	}
}

#endif

static void json_dump_strheader(char *tag, char *value, bool is_numeric)
{
	if (is_numeric) {
		printf("\"%s\": %s", tag, value);
	} else { 
		printf("\"%s\": \"%s\"", tag, value);
	}
}

char *sr_message_2log(struct sr_message_s *m)
{
	static char b[10240];	// FIXME!  need more than 10K for a log message? check?
	char *ci;
	char *rename;

	sprintf(b, "{ \"pubTime\":\"%s\", \"baseUrl\":\"%s\", \"relPath\":\"%s\", \"topic\":\"%s\"",
		m->datestamp, m->url, m->relPath, m->routing_key);

	ci = v03identity(m);
	if (ci && !strchr("mrRL", m->sum[0])) {
		sprintf(strchr(b, '\0'), ", \"identity\":{ %s } ", ci);
	}

	if ((m->sum[0] != 'R') && (m->sum[0] != 'L') && (m->sum[0] != 'r')) {
		sprintf(strchr(b, '\0'), ", \"mtime\":\"%s\", \"atime\":\"%s\"", m->mtime,
			m->atime);

		if (m->mode)
			sprintf(strchr(b, '\0'), ", \"mode\":\"%04o\"", m->mode);

		if (m->sum[0] != 'm')
			sprintf(strchr(b, '\0'), ", \"size\":\"%ld\"", m->parts_blksz);
	}

	/*if (m->rename)
	   sprintf(strchr(b, '\0'), ", \"fileOp\" : { \"rename\":\"%s\" }", m->rename);
	 */

	rename = NULL;
	for (struct sr_header_s * h = m->user_headers; h; h = h->next) {
		if (!strcmp(h->key, "oldname")) {
			rename = h->value;
		} else {
			sprintf(strchr(b, '\0'), ", \"%s\":\"%s\"", h->key, h->value);
		}
	}
	if (m->sum[0] == 'L') {
		sprintf(strchr(b, '\0'), ", \"fileOp\" : { \"link\":\"%s\"", m->link);
		if (rename) {
			sprintf(strchr(b, '\0'), ", \"rename\" : \"%s\" }", rename);
		} else {
			sprintf(strchr(b, '\0'), "}");
		}
	} else if (m->sum[0] == 'R') {
		sprintf(strchr(b, '\0'), ", \"fileOp\" : { \"remove\":\"\"");
		if (rename) {
			sprintf(strchr(b, '\0'), ", \"rename\" : \"%s\" }", rename);
		} else {
			sprintf(strchr(b, '\0'), "}");
		}
	} else if (m->sum[0] == 'm') {
		sprintf(strchr(b, '\0'), ", \"fileOp\" : { \"directory\":\"\"");
		if (rename) {
			sprintf(strchr(b, '\0'), ", \"rename\" : \"%s\" }", rename);
		} else {
			sprintf(strchr(b, '\0'), "}");
		}
	} else if (m->sum[0] == 'r') {
		sprintf(strchr(b, '\0'), ", \"fileOp\" : { \"rmdir\":\"\"");
		if (rename) {
			sprintf(strchr(b, '\0'), ", \"rename\" : \"%s\" }", rename);
		} else {
			sprintf(strchr(b, '\0'), "}");
		}
	} else if (rename) {
		sprintf(strchr(b, '\0'), ", \"fileOp\": { \"rename\" : \"%s\" }", rename);
	}

	sprintf(strchr(b, '\0'), "}");

	return (b);
}

void sr_message_2json(struct sr_message_s *m)
{
	struct sr_header_s *h;

	printf("[");
	printf(" \"%s\", { ", m->routing_key);
	if (strlen(m->atime) > 9) {
	    json_dump_strheader("atime", m->atime, false);
	}
	printf(", ");
	printf("\"mode\": \"%04o\"", m->mode);
	printf(", ");
	if (strlen(m->mtime) > 9) {
	    json_dump_strheader("mtime", m->mtime, false);
        }
	printf(", ");
	printf("\"parts\": \"%c,%ld,%ld,%ld,%ld\"",
	       m->parts_s, m->parts_blksz, m->parts_blkcount, m->parts_rem, m->parts_num);
	printf(", ");
	json_dump_strheader("source", m->source, false);
	printf(", ");
	json_dump_strheader("sum", m->sum, false);
	printf(", ");

	for (h = msg.user_headers; h; h = h->next) {
		printf(", ");
		json_dump_strheader(h->key, h->value, h->is_numeric);
	}
	printf(" } \"%s %s  %s\"", m->datestamp, m->url, m->relPath);
	printf("]\n");
}

void sr_message_2url(struct sr_message_s *m)
{
	printf("%s/%s\n", m->url, m->relPath);
}

struct sr_message_s *sr_consume(struct sr_context *sr_c)
 /*
    blocking read messages from queue. 

  */
{
	amqp_rpc_reply_t reply;
	amqp_frame_t frame;
	int result;
	static time_t next_qdeclare_time=0;
	static time_t now=0;
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
	struct timeval tv;
	static time_t this_second = 0;
        static int consumed_this_second = 0;

	if (now == 0) {
            time(&now);
        }

	// rate limiting.
	//sr_log_msg( LOG_INFO, "rateMax: %d, consumed_this_second: %d\n", 
	//		sr_c->cfg->messageRateMax, consumed_this_second );
        if (sr_c->cfg->messageRateMax > 0) {
                if (consumed_this_second >= sr_c->cfg->messageRateMax) {
                        sr_log_msg(LOG_INFO, "messageRateMax %d per second sleeping for a second.\n",
                                   sr_c->cfg->messageRateMax);
                        sleep(1);
                        time(&now);
                }
                if (now > this_second) {
                        this_second = now;
                        consumed_this_second = 0;
                }
                consumed_this_second++;
        }

	while (msg.user_headers) {
		tmph = msg.user_headers;
		free(tmph->key);
		free(tmph->value);
		msg.user_headers = tmph->next;
		free(tmph);
	}
	time(&now);
	if (next_qdeclare_time == 0) {
	    next_qdeclare_time=now+20;
        } else if ( now > next_qdeclare_time ) 
	{
               sr_consume_queue_declare(sr_c, 1);
	       next_qdeclare_time += 20;
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
			return (SR_CONSUME_BROKEN);
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
			return (SR_CONSUME_BROKEN);
		}
		sr_c->cfg->broker->started = 1;
	}
	amqp_maybe_release_buffers(sr_c->cfg->broker->conn);

	tv.tv_sec=0L;
	tv.tv_usec=1;

	//sr_log_msg(LOG_DEBUG, "wait_frame.\n");
	result = amqp_simple_wait_frame_noblock(sr_c->cfg->broker->conn, &frame, &tv);

	if (result == AMQP_STATUS_TIMEOUT ) {
	        //sr_log_msg(LOG_DEBUG, "no messages ready.\n" );
		return (NULL);
	}
	if (result < 0) {
		sr_log_msg(LOG_ERROR, "wait_frame bad result: %d. aborting connection.\n", result);
		return (SR_CONSUME_BROKEN);
	}
	if (frame.frame_type != AMQP_FRAME_METHOD) {
		sr_log_msg(LOG_ERROR, "bad FRAME_METHOD: %d. aborting connection.\n",
			   frame.frame_type);
		return (SR_CONSUME_BROKEN);
	}
	if (frame.payload.method.id != AMQP_BASIC_DELIVER_METHOD) {
		sr_log_msg(LOG_ERROR, "bad payload method: %d. aborting connection.\n",
			   frame.payload.method.id);
		return (SR_CONSUME_BROKEN);
	}

	d = (amqp_basic_deliver_t *) frame.payload.method.decoded;

	sr_log_msg(LOG_DEBUG,
		   "Frame type %d, channel %d Method %s consumer_tag: %s, delivery_tag: %ld\n",
		   frame.frame_type, frame.channel, amqp_method_name(frame.payload.method.id),
		   (char *)d->consumer_tag.bytes, (long)(d->delivery_tag));

	sr_c->cfg->broker->last_delivery_tag = d->delivery_tag;

	sr_log_msg(LOG_DEBUG, "exchange: \"%.*s\", routingkey: \"%.*s\",\n",
		   (int)d->exchange.len, (char *)d->exchange.bytes,
		   (int)d->routing_key.len, (char *)d->routing_key.bytes);

	sprintf(msg.exchange, "%.*s", (int)d->exchange.len, (char *)d->exchange.bytes);
	sprintf(msg.routing_key, "%.*s", (int)d->routing_key.len, (char *)d->routing_key.bytes);

	is_report = (!strncmp(d->routing_key.bytes, "v02.report", 10));

	result = amqp_simple_wait_frame(sr_c->cfg->broker->conn, &frame);

	if (result < 0) {
		sr_log_msg(LOG_ERROR, "error receiving frame! aborting connection.");
		return (SR_CONSUME_BROKEN);
	}

	if (frame.frame_type != AMQP_FRAME_HEADER) {
		sr_log_msg(LOG_ERROR, "Expected header! aborting connection.");
		return (SR_CONSUME_BROKEN);
	}

	p = (amqp_basic_properties_t *) frame.payload.properties.decoded;

	/* FIXME */
	if (p->_flags & AMQP_BASIC_CONTENT_TYPE_FLAG) {
		sr_log_msg(LOG_DEBUG,
			   "Content-type: %.*s  frame.payload.properties.class_id: %d body_size: %ld\n",
			   (int)p->content_type.len, (char *)p->content_type.bytes,
			   frame.payload.properties.class_id,
			   (long)frame.payload.properties.body_size);
	}

	if (p->_flags & AMQP_BASIC_HEADERS_FLAG) {
		sr_log_msg(LOG_DEBUG, "AMQP_BASIC_HEADERS_FLAG set. %d headers in message\n",
			   p->headers.num_entries);
		for (int i = 0; i < p->headers.num_entries; i++) {

			// FIXME: bug where num_entries==2, and entries=2 instead of a pointer.... very odd.
			//        We have no idea why this shows up, this is just a work-around, around the problem.
			if ((unsigned long)(p->headers.entries) < 1024) {
				sr_log_msg(LOG_ERROR,
					   "corrupted message, num_entries > 0 (%d), but entries close to NULL (%p).\n",
					   p->headers.num_entries, (p->headers.entries));
				goto after_headers;
			} else
				switch (p->headers.entries[i].value.kind) {
				case AMQP_FIELD_KIND_I8:
					sr_log_msg(LOG_WARNING, "skipping I8 header %d value:%d\n",
						   i, (p->headers.entries[i].value.value.i8));
					goto after_headers;
					break;

				case AMQP_FIELD_KIND_TIMESTAMP:
					sr_log_msg(LOG_WARNING,
						   "skipping TIMESTAMP header %d value:%lld\n", i,
						   (long long unsigned)(p->headers.entries[i].value.
									value.u64));
					break;

				case AMQP_FIELD_KIND_UTF8:
					sprintf(tag, "%.*s",
						(int)p->headers.entries[i].key.len,
						(char *)p->headers.entries[i].key.bytes);

					sprintf(value, "%.*s",
						(int)p->headers.entries[i].value.value.bytes.len,
						(char *)p->headers.entries[i].value.value.bytes.
						bytes);

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
					sprintf(tag, "%.*s",
						(int)p->headers.entries[i].key.len,
						(char *)p->headers.entries[i].key.bytes);

					sprintf(value, "%lu", p->headers.entries[i].value.value.u64 );

					assign_field(tag, value);
					sr_log_msg(LOG_WARNING,
						   "skipping U64 header %d value:%ld\n", i,
						   (long long unsigned)(p->headers.entries[i].value.
									value.u64));
					break;

				case AMQP_FIELD_KIND_ARRAY:
					sprintf(tag, "%.*s",
						(int)p->headers.entries[i].key.len,
						(char *)p->headers.entries[i].key.bytes);

					sr_log_msg(LOG_WARNING, "skipping ARRAY header %s index: %d\n", tag, i);
					goto after_headers;
					break;

			        case AMQP_FIELD_KIND_I32:
					sprintf(tag, "%.*s",
						(int)p->headers.entries[i].key.len,
						(char *)p->headers.entries[i].key.bytes);

					sprintf(value, "%u", p->headers.entries[i].value.value.u32 );
					assign_field(tag, value);
					break;

				case AMQP_FIELD_KIND_I64:
					sprintf(tag, "%.*s",
						(int)p->headers.entries[i].key.len,
						(char *)p->headers.entries[i].key.bytes);

					sprintf(value, "%ld", p->headers.entries[i].value.value.i64 );
					assign_field(tag, value);

					break;

				default:
					sprintf(tag, "%.*s",
						(int)p->headers.entries[i].key.len,
						(char *)p->headers.entries[i].key.bytes);

					sr_log_msg(LOG_WARNING,
						   "skipping non UTF8 headers: %s, amount: %d, this one: %d, kind:%d\n",
						   tag, p->headers.num_entries, i,
						   p->headers.entries[i].value.kind);
					goto after_headers;

				}
		}
	} else {
		sr_log_msg(LOG_DEBUG, "message has no headers. Good.\n");
	}

 after_headers:
	body_target = frame.payload.properties.body_size;
	body_received = 0;

	if (body_target >= SR_SARRAC_MAXIMUM_MESSAGE_LEN) {
		sr_log_msg(LOG_CRITICAL, "Message too big! received: (%ld bytes) max: %d",
			   (long)body_target, SR_SARRAC_MAXIMUM_MESSAGE_LEN);
		abort();
	}

	while (body_received < body_target) {
		result = amqp_simple_wait_frame(sr_c->cfg->broker->conn, &frame);

		if (result < 0) {
			sr_log_msg(LOG_WARNING,
				   "broken message received: wait_frame returned %d. aborting connection.\n",
				   result);
			return (SR_CONSUME_BROKEN);
		}
		if (frame.frame_type != AMQP_FRAME_BODY) {
			sr_log_msg(LOG_CRITICAL, "Expected body! aborting connection.");
			abort();
		}

		strncpy(&(buf[body_received]), (char *)frame.payload.body_fragment.bytes,
			(int)frame.payload.body_fragment.len);

		body_received += frame.payload.body_fragment.len;
		sr_log_msg(LOG_DEBUG, "message body frame received: %lu bytes \n",
			   (unsigned long)frame.payload.body_fragment.len);

		buf[body_received] = '\0';
	}

	if (body_received != body_target) {
		sr_log_msg(LOG_ERROR,
			   "incomplete message, received: %lu bytes, expected: %lu bytes.\n",
			   (long)body_received, (long)body_target);
		return (SR_CONSUME_BROKEN);
	} else {
		sr_log_msg(LOG_DEBUG, "complete message, received: %lu bytes \n",
			   (unsigned long)body_received);
	}

	/* Can only happen when amqp_simple_wait_frame returns <= 0 */
	/* We break here to close the connection */

	if (buf[0] != '{') {	// v02.
		tok = strtok(buf, " ");
		//fprintf( stdout, "\t\"datestamp\" : \"%s\",\n", tok);
		strcpy(msg.datestamp, tok);
		tok = strtok(NULL, " ");
		//fprintf( stdout, "\t\"url\" : \"%s\", \n", tok);
		strcpy(msg.url, tok);
		tok = strtok(NULL, " ");
		//fprintf( stdout, "\t\"path\" : \"%s\", \n", tok);
		strcpy(msg.relPath, tok);
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

	} else {		// v03

#ifdef HAVE_JSONC
		json_object *jo = NULL;

		jo = json_tokener_parse(buf);

		if (jo == NULL) {
			sr_log_msg(LOG_ERROR, "failed to parse json body: %s", buf);
			return (NULL);
		} else {
			sr_log_msg(LOG_DEBUG, "successfully parsed json body: %s", buf);
		}
		json_object_object_foreach(jo, k, jso_kv) {
			v03assign_field(k, jso_kv);
		}
		json_object_put(jo);	//attempting to free everything?
		jo = NULL;
#else
		sr_log_msg(LOG_ERROR,
			   "v03 parsing not compiled in, recompile with libjson-c support\n");
#endif

	}

	sr_log_msg(LOG_ERROR, "v03 end of parse msg.datestamp: %s\n", msg.datestamp );

	return (&msg);
}

bool sr_message_valid(struct sr_message_s *m)
{

        /* this is actually ok after all... 
	if (strlen(m->relPath) == 0) {
		sr_log_msg(LOG_ERROR, "zero length relPath\n");
		return false;
	} */

	return true;
}
