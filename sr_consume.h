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

  call an sr_context_init to set things up.
  then sr_post will post files,
  then sr_close to tear the connection down.

  there is an all in one function: connect_and_post that does all of the above.

 */

#ifndef SR_CONSUME_H

#define SR_CONSUME_H 1

/* 
  picking a maximum message size to create a static buffer.
  There is no maximum defined for Sarracenia. Maximum message size varies
  by broker implementation, so using extraordinarily large messages is risky.
  in v03 there is content embedding to satisfy WMO ET-CTS, so the messages
  can be bigger. probably not a good idea in practice.

 */
#define SR_SARRAC_MAXIMUM_MESSAGE_LEN (1024*1024)

#include "sr_context.h"

struct sr_message_s {
	char atime[SR_TIMESTRLEN];
	char datestamp[SR_TIMESTRLEN];
	char exchange[AMQP_MAX_SS];
	char link[PATH_MAXNUL];
	int mode;
	char mtime[SR_TIMESTRLEN];
	char parts_s;
	long parts_blksz;
	long parts_blkcount;
	long parts_rem;
	long parts_num;
	char path[PATH_MAXNUL];
	char queue[AMQP_MAX_SS];
	char rename[PATH_MAXNUL];
	char routing_key[AMQP_MAX_SS];
	char source[AMQP_MAX_SS];
	char sum[SR_SUMSTRLEN];
	char url[PATH_MAXNUL];
	struct sr_header_s *user_headers;

	// sr_report(7) fields.
	float duration;
	char consumingurl[PATH_MAXNUL];
	char consuminguser[PATH_MAXNUL];
	int statuscode;

};



char *v03integrity( struct sr_message_s *m );




//extern struct sr_message_s msg;

int sr_consume_setup(struct sr_context *sr_c);
/* 
   declare and bind queue over a connection already established by context_init

    return: 1 on success, 0 on failure.
 */

int sr_consume_cleanup(struct sr_context *sr_c);
/* 
   delete queue declared by setup.
 */

char *sr_message_partstr(struct sr_message_s *m);
/*
  return the parts string for an sr_message given the message structure.
 */

char *sr_message_2log(struct sr_message_s *m);
/* 
   make a string in the format for log messages. 
 */

void sr_message_2json(struct sr_message_s *m);
/* 
   print a message to stdout, the entire thing, in json save/restore format.
 */

void sr_message_2url(struct sr_message_s *m);
/* 
   print a message to stdout, just the pathname to stdout.

 */

struct sr_message_s *sr_consume(struct sr_context *sr_c);

bool sr_message_valid(struct sr_message_s *m);
/*
 * return True if the message passes validity tests (so will be properly processed.)
 * may print messages about formatting errors.
 */
#endif
