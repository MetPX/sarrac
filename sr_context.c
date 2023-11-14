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

  In a shell, to use an sr_config(7) style configuration file:
  set the SR_POST_CONFIG environment variable to the name of the
  file to use.

 
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

#include <sys/time.h>
#include <sys/resource.h>

#include <openssl/md5.h>
#include <openssl/sha.h>

#include <stdint.h>
#include <amqp_tcp_socket.h>
#include <amqp_ssl_socket.h>
#include <amqp.h>
#include <amqp_framing.h>

#include "sr_context.h"
#include "sr_version.h"

#define PSDUPMAX (10)

static int sr_context_avoid_std_fds = 0;

void sr_amqp_error_print(int x, char const *context)
{
	if (x < 0) {
		sr_log_msg(LOG_ERROR, "%s: %s\n", context, amqp_error_string2(x));
		return;
	}
}

void sr_amqp_reply_print(amqp_rpc_reply_t x, char const *context)
{
	switch (x.reply_type) {
	case AMQP_RESPONSE_NORMAL:
		return;

	case AMQP_RESPONSE_NONE:
		sr_log_msg(LOG_ERROR, "%s: missing RPC reply type!\n", context);
		break;

	case AMQP_RESPONSE_LIBRARY_EXCEPTION:
		sr_log_msg(LOG_ERROR, "%s: %s\n", context, amqp_error_string2(x.library_error));
		break;

	case AMQP_RESPONSE_SERVER_EXCEPTION:
		switch (x.reply.id) {
		case AMQP_CONNECTION_CLOSE_METHOD:{
				amqp_connection_close_t *m =
				    (amqp_connection_close_t *) x.reply.decoded;
				sr_log_msg(LOG_ERROR,
					   "%s: server connection error %uh, message: %.*s\n",
					   context, m->reply_code,
					   (int)m->reply_text.len, (char *)m->reply_text.bytes);
				break;
			}
		case AMQP_CHANNEL_CLOSE_METHOD:{
				amqp_channel_close_t *m = (amqp_channel_close_t *) x.reply.decoded;
				sr_log_msg(LOG_ERROR,
					   "%s: server channel error %uh, message: %.*s\n",
					   context, m->reply_code,
					   (int)m->reply_text.len, (char *)m->reply_text.bytes);
				break;
			}
		default:
			sr_log_msg(LOG_ERROR,
				   "%s: unknown server error, method id 0x%08X\n",
				   context, x.reply.id);
			break;
		}
		break;
	}
}

struct sr_broker_s *sr_broker_connect(struct sr_broker_s *broker)
{

	/* set up a connection given a context.
	 */

	signed int status;
	amqp_rpc_reply_t reply;
	amqp_channel_open_ok_t *open_status;
	amqp_tx_select_ok_t *select_status;
	time_t to_sleep = 1;

	if (!broker)
		return (NULL);

	if (!(broker->password)) {
		sr_log_msg(LOG_ERROR, "No broker password found.\n");
		return (NULL);
	}

	while (1) {
		broker->conn = amqp_new_connection();
		//sr_log_msg(  LOG_DEBUG, "FIXME: broker_connecting!? broker->con=%p. user=%s, pw=%s\n", broker->conn, broker->user, broker->password );

		if (broker->ssl) {
			broker->socket = amqp_ssl_socket_new(broker->conn);
			if (!(broker->socket)) {
				sr_log_msg(LOG_ERROR, "failed to create SSL amqp client socket.\n");
				goto have_connection;
			}

			amqp_ssl_socket_set_verify_peer(broker->socket, 0);
			amqp_ssl_socket_set_verify_hostname(broker->socket, 0);

		} else {
			broker->socket = amqp_tcp_socket_new(broker->conn);
			if (!(broker->socket)) {
				sr_log_msg(LOG_ERROR, "failed to create AMQP client socket. \n");
				goto have_connection;
			}
		}

		status = amqp_socket_open(broker->socket, broker->hostname, broker->port);
		if (status < 0) {
			sr_amqp_error_print(status, "failed opening AMQP socket");
			sr_log_msg(LOG_ERROR,
				   "Failed to open AMQP socket host: %s, port: %d\n",
				   broker->hostname, broker->port);
			goto have_socket;
		}
		reply =
		    amqp_login(broker->conn, "/", 0, 131072, 0,
			       AMQP_SASL_METHOD_PLAIN, broker->user, broker->password);
		if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
			sr_amqp_reply_print(reply, "failed AMQP login");
			sr_log_msg(LOG_ERROR, "Failed AMQP login user: %s\n", broker->user);
			goto have_socket;
		}

		open_status = amqp_channel_open(broker->conn, 1);
		if (open_status == NULL) {
			sr_log_msg(LOG_ERROR, "failed AMQP amqp_channel_open 1\n");
			goto have_channel;
		}

		open_status = amqp_channel_open(broker->conn, 2);
		if (open_status == NULL) {
			sr_log_msg(LOG_ERROR, "failed AMQP amqp_channel_open 2\n");
			goto have_channel;
		}

		reply = amqp_get_rpc_reply(broker->conn);
		if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
			sr_amqp_reply_print(reply, "failed AMQP channel_open get_rpc_reply");
			goto have_channel;
		}

		select_status = amqp_tx_select(broker->conn, 1);
		if (select_status == NULL) {
			sr_log_msg(LOG_ERROR, "failed AMQP amqp_tx_select\n");
			reply = amqp_get_rpc_reply(broker->conn);
			if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
				sr_amqp_reply_print(reply, "failed AMQP tx_select get_rpc_reply");
				goto have_channel;
			}
			goto have_channel;
		}

		broker->started = 0;
		return (broker);

 have_channel:
		reply = amqp_channel_close(broker->conn, 1, AMQP_REPLY_SUCCESS);
		reply = amqp_channel_close(broker->conn, 2, AMQP_REPLY_SUCCESS);

 have_socket:
		reply = amqp_connection_close(broker->conn, AMQP_REPLY_SUCCESS);
		broker->socket = NULL;

 have_connection:
		status = amqp_destroy_connection(broker->conn);
		broker->conn = NULL;

		sleep(to_sleep);
		sr_log_msg(LOG_DEBUG,
			   "broker_connect slept %ld seconds. Trying again now.\n", to_sleep);
		if (to_sleep < 60)
			to_sleep <<= 1;

	}
}

struct sr_context *sr_context_connect(struct sr_context *sr_c)
{

	int psdup[PSDUPMAX];

	if (!sr_c)
		return (NULL);
	if (!(sr_c->cfg))
		return (NULL);

	if (sr_context_avoid_std_fds) {
		psdup[0] = open("/dev/null", O_APPEND);
		for (int i = 1; i < PSDUPMAX; i++)
			psdup[i] = dup(psdup[i - 1]);
	}

	if (sr_c->cfg->broker) {
		sr_c->cfg->broker = sr_broker_connect(sr_c->cfg->broker);
		if (!(sr_c->cfg->broker))
			return (NULL);
		if ((sr_c->cfg != NULL) && sr_c->cfg->debug)
			sr_log_msg(LOG_DEBUG,
				   "%s sr_context_connect to subscription broker succeeded!\n",
				   __sarra_version__);
	}

	if (sr_c->cfg->post_broker) {
		sr_c->cfg->post_broker = sr_broker_connect(sr_c->cfg->post_broker);
		if (!(sr_c->cfg->post_broker))
			return (NULL);
		sr_log_msg(LOG_DEBUG, "%s connected to post broker %s\n",
			   __sarra_version__, sr_broker_uri(sr_c->cfg->post_broker));
	}
	if (sr_context_avoid_std_fds) {
		for (int i = PSDUPMAX - 1; i >= 0; i--)
			close(psdup[i]);
	}

	return (sr_c);

}

/* The time that the program was started, or the last call to housekeeping check.
   
 */
static struct timespec tstart;

struct timespec sr_time_of_last_run()
{
	return (tstart);
}

void sr_context_metrics_cumulative_write(struct sr_context *sr_c)
{
        FILE *f;
        char datestamp[50];
        char c;
        char cumulativeFilename[PATH_MAX];

        if ( sr_c->cfg->logMetrics ) {
                strcpy(datestamp,sr_time2str(NULL));
                strcpy(cumulativeFilename, sr_c->cfg->metricsFilename );
                strcat( cumulativeFilename, "." );
                c=datestamp[9];
                datestamp[8]='\0';
                strcat( cumulativeFilename, datestamp );
                datestamp[8] = c;

                f = fopen( cumulativeFilename, "a+" );
		if (f) {
                	fprintf( f, "\"%s\": { \"context\" : { \"rxGoodCount\": %d, \"rxBadCount\": %d, \"rejectCount\": %d, \"txGoodCount\": %d, \"last_housekeeping\": %f, \"brokerQueuedMessageCount\": %d } }, \n" ,
                        datestamp, sr_c->metrics.rxGoodCount, sr_c->metrics.rxBadCount, sr_c->metrics.rejectCount, 
			sr_c->metrics.txGoodCount, sr_c->metrics.last_housekeeping, sr_c->metrics.brokerQueuedMessageCount 
                        );
                        fclose(f);
		}

        }
}

void sr_context_metrics_reset(struct sr_context *sr_c)
{
	struct timespec tnow;

        sr_context_metrics_cumulative_write(sr_c);
        sr_c->metrics.brokerQueuedMessageCount = 0;
        sr_c->metrics.rxGoodCount = 0;
        sr_c->metrics.rxBadCount = 0;
        sr_c->metrics.rejectCount = 0;
        sr_c->metrics.txGoodCount = 0;
	memset(&tnow, 0, sizeof(struct timespec));
	clock_gettime(CLOCK_REALTIME, &tnow);
	sr_c->metrics.last_housekeeping= tnow.tv_sec + (tnow.tv_nsec / 1e9);
}


struct sr_context *sr_context_init_config(struct sr_config_s *sr_cfg, int must_avoid_std_fds)
{

	struct sr_context *sr_c;

	if (!sr_cfg)
		return (NULL);

	sr_context_avoid_std_fds = must_avoid_std_fds;

	// seed for random checksums... random enough...
	// also initializes tstart for use by housekeeping processing.
	clock_gettime(CLOCK_REALTIME, &tstart);
	srandom(tstart.tv_nsec);

	sr_c = (struct sr_context *)malloc(sizeof(struct sr_context));

	sr_c->cfg = sr_cfg;

	// FIXME: if prog is post, then only post_broker is OK.
	// sr_c->exchange = sr_cfg->exchange ;

	sr_c->post_baseUrl = sr_cfg->post_baseUrl;

	if ((sr_c->cfg != NULL) && sr_c->cfg->debug) {
		if (sr_c->cfg->broker)
			sr_log_msg(LOG_DEBUG, "broker: amqp%s://%s:%s@%s:%d\n",
				   sr_cfg->broker->ssl ? "s" : "",
				   sr_cfg->broker->user,
				   (sr_cfg->broker->password) ? "<pw>" : "<null>",
				   sr_cfg->broker->hostname, sr_cfg->broker->port);

		if (sr_c->cfg->post_broker)
			sr_log_msg(LOG_DEBUG,
				   "post_broker: amqp%s://%s:%s@%s:%d\n",
				   sr_cfg->post_broker->ssl ? "s" : "",
				   sr_cfg->post_broker->user,
				   (sr_cfg->post_broker->password) ? "<pw>" : "<null>",
				   sr_cfg->post_broker->hostname, sr_cfg->post_broker->port);
	}
        sr_context_metrics_reset(sr_c);
	return (sr_c);

}

void sr_broker_close(struct sr_broker_s *broker)
{

	amqp_rpc_reply_t reply;
	signed int status;

	if (!(broker->conn)) {
		//sr_log_msg(LOG_DEBUG, "amqp broker close: no connection present.\n");
		return;
	}
	reply = amqp_channel_close(broker->conn, 2, AMQP_REPLY_SUCCESS);
	if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
		sr_log_msg(LOG_ERROR, "amqp channel close 2 failed.\n");
	} else {
		reply = amqp_channel_close(broker->conn, 1, AMQP_REPLY_SUCCESS);
		if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
			sr_log_msg(LOG_ERROR, "amqp channel close 1 failed.\n");
		} else {
			reply = amqp_connection_close(broker->conn, AMQP_REPLY_SUCCESS);
			if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
				sr_log_msg(LOG_ERROR, "amqp connection close failed.\n");
			}
		}
	}

	status = amqp_destroy_connection(broker->conn);
	broker->conn = NULL;
	broker->next = NULL;

	//if (broker->socket) free(broker->socket);

	broker->socket = NULL;
	broker->started = 0;
	broker->last_delivery_tag = 0;

	if (status < 0) {
		sr_log_msg(LOG_ERROR, "amqp context close failed.\n");
	}

}

void sr_context_close(struct sr_context *sr_c)
{

	if (!sr_c)
		return;
	if (!sr_c->cfg)
		return;

	if (sr_c->cfg->broker) {
		sr_broker_close(sr_c->cfg->broker);
		sr_log_msg(LOG_DEBUG, "%s subscription broker closed.\n", sr_c->cfg->progname);
	}
	if (sr_c->cfg->post_broker) {
		sr_log_msg(LOG_DEBUG, "%d %s post broker closing.\n", getpid(),
			   sr_c->cfg->progname);
		sr_broker_close(sr_c->cfg->post_broker);
		sr_log_msg(LOG_DEBUG, "%s post broker closed.\n", sr_c->cfg->progname);
	}

}

void sr_context_housekeeping(struct sr_context *sr_c)
/* run this every housekeeping interval 
 */
{
	int cached_count;
	struct rusage usage_before;
	struct rusage usage_after;

	sr_log_msg(LOG_DEBUG, "housekeeping processing start\n");

	if (sr_c->cfg->cachep) {
		getrusage(RUSAGE_SELF, &usage_before);

		sr_log_msg(LOG_INFO, "housekeeping starting to clean cache\n");
		sr_cache_clean(sr_c->cfg->cachep, sr_c->cfg->nodupe_ttl);
		sr_log_msg(LOG_DEBUG, "housekeeping cleaned, hashes left: %u\n",
			   HASH_COUNT(sr_c->cfg->cachep->data));
		if (HASH_COUNT(sr_c->cfg->cachep->data) == 0) {
			sr_c->cfg->cachep->data = NULL;
		}
		cached_count = sr_cache_save(sr_c->cfg->cachep, 0);

                sr_context_metrics_reset(sr_c);

		getrusage(RUSAGE_SELF, &usage_after);

		//FIXME
		sr_log_msg(LOG_INFO,
			   "housekeeping after cleaning, cache stores %d entries. (memory: %ld kB)\n",
			   cached_count, usage_after.ru_maxrss);
	}
	sr_log_msg(LOG_DEBUG, "housekeeping processing completed\n");
}


void sr_context_metrics_write(struct sr_context *sr_c) 

{
	FILE *f;
        
	f = fopen( sr_c->cfg->metricsFilename, "w" );
        fprintf( f, "{ \"context\" : { \"rxGoodCount\": %d, \"rxBadCount\": %d, \"rejectCount\": %d, \"txGoodCount\": %d, \"last_housekeeping\": %f , \"brokerQueuedMessageCount\": %d } }\n" ,
		sr_c->metrics.rxGoodCount, sr_c->metrics.rxBadCount, sr_c->metrics.rejectCount, 
		sr_c->metrics.txGoodCount, sr_c->metrics.last_housekeeping,  sr_c->metrics.brokerQueuedMessageCount ); 
	fclose(f);
}

float sr_context_housekeeping_check(struct sr_context *sr_c)
/* 
   Check if you need to do to run housekeeping processing.  
   Returns: elapsed time since previous call, in seconds.

   Note: sr_context_init_config must be called before first call to initialize "previous call" timing.
 */
{
	static struct timespec tend;
	static float elapsed;
	static float since_last_housekeeping = 0;
	static float since_last_metrics_write=0;

	clock_gettime(CLOCK_REALTIME, &tend);
	elapsed = (float)((tend.tv_sec + (tend.tv_nsec / 1e9)) -
			  (tstart.tv_sec + (tstart.tv_nsec / 1e9)));

	since_last_housekeeping = since_last_housekeeping + elapsed;

	if ( since_last_metrics_write > 10 ) {
            sr_context_metrics_write(sr_c);
	    since_last_metrics_write=0;
        } else {
	    since_last_metrics_write += elapsed;
	}
	clock_gettime(CLOCK_REALTIME, &tstart);

	if (since_last_housekeeping >= sr_c->cfg->housekeeping) {
		sr_context_housekeeping(sr_c);
		since_last_housekeeping = 0.0;
	}

	return (elapsed);
}
