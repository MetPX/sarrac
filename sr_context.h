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

#ifndef SR_CONTEXT_H

#define SR_CONTEXT_H 1

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include <stdint.h>
#include <amqp_ssl_socket.h>
#include <amqp_tcp_socket.h>
#include <amqp.h>
#include <amqp_framing.h>

#include "sr_config.h"

struct sr_context {

	char settings[AMQP_MAX_SS];
	const char *file;
	const char *post_baseUrl;
	amqp_socket_t *socket;
	amqp_connection_state_t conn;
	int port;
	struct sr_config_s *cfg;
};

void sr_amqp_error_print(int x, char const *context);
/* utility functions for handling rabbitmq-c call return values.
   for rabbitmq-c routines that return an integer, process the output.
 */

void sr_amqp_reply_print(amqp_rpc_reply_t x, char const *context);
/* utility functions for handling rabbitmq-c call return values.
   if return value from a function is an amqp_rpc_reply_t, then feed it to this routine.
   context, is a descriptive string.
 */

struct sr_context *sr_context_init_config(struct sr_config_s *sr_cfg, const int avoid_std_fds);

/* context_init sets up a context.
   returns connection to a broker based on given configuration.
   returns an sr_context ready for use by connect.

   This routine opens a socket connection to the broker, which uses an file 
   descriptor. When called from the shim library, it can be called by code 
   like this:

   close(1)
   open("....) 
   write( 1,   ... ) 

   The above assumes and requires fd returned by open will be 1, which is 
   normally safe, however, if the broker connection is established before the 
   next file is opened, then the socket will use the first available file 
   descriptor which could be 0, 1, or 2. 

   When avoid_std_fds is set, a number of file descriptors are associated with 
   /dev/null prior to connecting to the broker to ensure that the fd assigned
   to that socket will not be one of the standard ones. When called from 
   well-behaved code such as a single C-program, this is unnecessary.

 */

struct timespec sr_time_of_last_run();

struct sr_context *sr_context_connect(struct sr_context *sr_c);
/* 
   returns open connection to a broker based on given configuration.
   returns an sr_context ready for use by post.
   connection establishment is done here.
 */

void sr_context_close(struct sr_context *sr_c);
/* clean up an initialized context.
   tears down the connection.
 */

void sr_context_housekeeping(struct sr_context *sr_c);
/* periodic processing that users should call ever *hearbeat* interval.
   triggers a print in the log, and cache cleaning, for example.
 */

float sr_context_housekeeping_check(struct sr_context *sr_c);
/* 
   Check the time.  If you need to do to run housekeeping processing, it is done.
   Returns: elapsed time since previous call, in seconds.

   Note: sr_context_init_config must be called before first call to initialize "previous call" timing.
 */

#endif
