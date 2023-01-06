
/*
 This file is part of MetPX-Sarrac.
 The sarracenia suite is Free and is proudly provided by the Government of Canada
 Copyright (C) Her Majesty The Queen in Right of Canada, Environment Canada, 2017-2019

 author: Peter Silva

status: 
  Purpose is to have something that parses the sarracenia configuration files in C.

  See mainly:

  https://github.com/MetPX/sarracenia/tree/master/doc/sr_subscribe.1.rst

 */

#ifndef SR_CONFIG_H

#define SR_CONFIG_H 1

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <regex.h>
#include <linux/limits.h>
#include <time.h>
#include <openssl/sha.h>

// for kill(2)
#include <sys/types.h>
#include <signal.h>

// AMQP stuff.
#include <stdint.h>
#include <amqp_ssl_socket.h>
#include <amqp_tcp_socket.h>
#include <amqp.h>
#include <amqp_framing.h>

#include "sr_util.h"
#include "sr_event.h"


// AMQP PROTOCOL LIMIT IMPOSED HERE... see definition of short strings.
// 255 characters, + terminating nul
#define AMQP_MAX_SS (255+1)

#define PATH_MAXNUL (PATH_MAX+1)

#define RANDID_LEN  (4)

#include "sr_cache.h"

/**
 * struct sr_path_s - Non option arguments (paths, either of config files, or files to be posted.)
 */

struct sr_path_s {
	char path[PATH_MAX];
			/**< the path itself. */
	struct sr_path_s *next;
			   /**< link to the next item in the singly linked list. */
};

/**
 * struct sr_topic_s - topic arguments.
 */

struct sr_topic_s {
	char topic[AMQP_MAX_SS];
			   /**< the topic itself. */
	struct sr_topic_s *next;
			   /**< link to the next item in the singly linked list. */
};

/**
 * struct sr_header_s -  store headers: a list of key-value string pairs.
 */

struct sr_header_s {
	char *key;
	     /**< the key string */
	char *value;
	       /**< the value string */
	struct sr_header_s *next;
			    /**< link to the next item in the singly linked list. */
};

/**
 * struct sr_mask_s -  store a list of accept/reject file filter masks: 
 */

struct sr_mask_s {
	char *clause;/**< the original regexp string */
	char *directory;
		     /**<  the directory in effect when the clause is applied */
	regex_t regexp;
		     /**<  The compiled representation of the clause. */
	int accepting;
		     /**<  boolean:  reject(0) / accept(1)  the direction to apply the clause */
	struct sr_mask_s *next;
			  /**< link to the next item in the singly linked list. */
};

/**
 * struct sr_broker_s -  store a list of brokers
 */

struct sr_broker_s {
	int ssl;
	   /**< whether the connection includes encryption (TLS at this point) */
	char *user;
	      /**< user name to authenticate to the broker */
	char *password;
		  /**< password to authenticate to the broker. */
	char *hostname;
		  /**< broker host name. */
	int port;
	      /**< broker port number ( 1-65535 ) */
	char *exchange;
		  /**< name of the exchange to publish to on the broker. */
	int exchange_split;
			/**< number of exchanges to split publishes among. */
	uint64_t last_delivery_tag;
			      /**< some AMQP thing... no idea. */
	amqp_socket_t *socket;
			 /**< part of an established connection to a broker */
	amqp_connection_state_t conn;
				/**< part of an established connection to a broker */
	int started;
	       /**< boolean whether the connection has been established or not. */
	struct sr_broker_s *next;
			    /**< link to the next item in the singly linked list. */
};

/**
 * struct sr_config_s - the master config struct hold an entire one.
 *
 * Contains the entire configuration for a component.
 */

struct sr_config_s {
	int acceptUnmatched;		/**< if no masks match, reject(0), or accept(1) the file.*/
	char *action;	      /**< the action to perform: start, stop, status, add, remove, foreground, enable, disable, etc...*/
	char appname[128];	      /**< the name of the application, also the name of subdirectory used to find config and state files (default: sarra) */
	long unsigned blocksize; /**< blocksize: 
          the size of blocks 0 (guess), 
                             1 ( send entire file in one block ),  
                             else a literal blocksize
          used for partitioning of large files.*/
	struct sr_broker_s *broker;
			      /**< broker: the rabbitmq AMQP broker to connect to.*/
	float cache;	     /**< cache: the expiry age, in seconds of entries in the recent files cache.*/
	struct sr_cache_s *cachep;
			      /**< the recent files cache.*/
	char *cache_basis;	   /**< 'file' | 'path' | 'none' -> modifies which cache entries are comparable.*/
	mode_t chmod_log;	 /**< permission mode bits to use for the log files.*/
	char *configname;	  /**< the configuration being run (name of the main configuration file.)*/
	int debug;	     /**< turn on debug output.*/
        int exchangeDeclare; //**< declare exchange before use */
        int queueDeclare; //**< declare queue before use */
	int delete;	      /**< flag to mark that files downloaded should be deleted (unimplemented)*/
	char *directory;	 /**< the current directory setting (used when building masks)*/
	int durable;	       /**< flag to pass to broker to set corresponding Queue property*/
	sr_event_s events;    /**< set of events to produce/monitor (create/delete, etc...)*/
	char *exchange;		 /**< the exchange to subscribe to.*/
	char *exchangeSuffix;		/**< something to append to the exchange.*/
	float expire;	      /**< a time (in seconds) passed to the broker as queue lifetime.*/
	int follow_symlinks;	       /**< flag to indicate whether one should visit the destination of symlinks.*/
	int force_polling;	     /**< flag to switch watch algorithms , either brute polling or Inotify*/
	float heartbeat;	 /**< interval, in seconds between periodic processing events.*/
	int help;	     /**< flag to trigger printing help message.*/
	int instance;		/**< the instance number of the current process within a component's configuration.*/
	char *last_matched;	    /**< the value of the last matched mask. */
	char *list;		/**< method to generate initial input list:  file or queue*/
	int log;		/**< Use a log file, rather than standard files.*/
	int log_reject;		   /**< normally rejections are silent, when set, make INFO message. */
	char *logfn;		  /**< Use this log file, rather than standard files.*/
	int logrotate;		  /**< number of log files to keep around.*/
	int logrotate_interval;		  /**< number of seconds between log rotations.*/
	int loglevel;		/**< severity of messages to log (regardless of where.)*/
	struct sr_mask_s *masks;
			     /**< the list of masks to compare file names to.*/
	struct sr_mask_s *match;
			     /**< the current matched mask */
	float message_ttl;	  /**< a time (in seconds) passed to the broker as message lifetime.*/
	char *outlet;	      /**< post|json|url - default post. choice of output format.*/
	int pid;	   /**< what is the current process identifier.*/
	char *pidfile;	       /**< the name of the state file containing the pid.*/
	int prefetch;		/**< how many messages to request from a broker at once.*/
	char *progname;		/**< the name of the program (component) being run.*/
	struct sr_path_s *paths;
			     /**< the list of configurations or files given on the command line.*/
	int pipe;	     /**< pipe mode, read file names from standard input*/
	char *post_baseDir;	     /**< the local directory at the root of the url tree.*/
	char *post_baseUrl;	     /**< the url that corresponds to the base directory.*/
	struct sr_broker_s *post_broker;
				   /**< the broker to post to.*/
	char *post_exchange;	     /**< the exchange to post to on the post broker.*/
	int post_exchange_split;	   /**< the count of  a team of similar exchanges.*/
	char *post_exchangeSuffix;	    /**< appended to an exchange name.*/
	int post_rate_limit;	 /**< limit maximum number of posts per second */
	char *queuename;	 /**< the name of the queue for a consumer.*/
	char *randid;	      /**< a random id, typically used in queue name generation.*/
	int realpathPost;		/**< flag to indicate whether realpath should be applied before posting.*/
	int realpathFilter;	       /**< flag to say use the realpath for matching, but publish the original.*/
	int recursive;		 /**< always set to on now, walk entire tree (FIXME, remove option?)*/
	float sanity_log_dead;	       /**< how many seconds old should a log be before the component is presumed dead.*/
	int shim_defer_posting_to_exit;		  /**< flag to have the shim library only post on process exit.*/
	float shim_post_minterval;	   /**< interval in seconds, the most often one will post the same file.*/
	int shim_skip_parent_open_files;	   /**< flag, do not post files which are still open in ppid.*/
	float sleep;	     /**< number of seconds to sleep between polls/processing loops.*/
	char statehost;		  /**< flagish thing: '0','s','f' meaning no, short fqdn*/
	char *statehostval;	     /**< actual hostname resulting from statehost.*/
	int strip;	     /**< number of path elements to strip from posted path  */
	char sumalgo;	       /**< checksum algorithm to use.*/
	char sumalgoz;		/**< if algo is z what is the real checksum algorithm to apply.*/
	char *source;	      /**< indicates the cluster of origin of a post.*/
	char *to;	  /**< indicates destination cluster(s) for a post.*/
	struct sr_topic_s *topics;
			      /**< list of sub-topics to subscribe to.*/
	char topicPrefix[AMQP_MAX_SS];		 /**< the topic prefix to subscribe to.*/
	char post_topicPrefix[AMQP_MAX_SS];   /**< the topic prefix to post to.*/
	struct sr_header_s *user_headers;
				    /**< list of arbitrary user headers for extensions and upward compatibility.*/
        int  v2compatRenameDoublePost;
	char *vip;	  /**< virtual ip address ... only act, if host has this address.*/
	int xattr_cc;		/**<boolean flag to determine whether or not xattr checksum caching should be used.*/
};

/**
 * sr_local_fqdn() - return fully qualified domain name
 * Return: static hostname character string.
 */
char *sr_local_fqdn();

/**
 * sr_isMatchingPattern() - return pointer to matched pattern, if there is one, NULL otherwise.
 * \param sr_cfg: the configuration with the masks to match against.
 * \param chaine: the character string to be matched
 *
 *  return pointer to matched pattern, if there is one, NULL otherwise.
 *  if called multiple times, it returns a cached response from the previous call.
 *
 * Return: The mask entry that matched, if any. (not a copy, do not play with it.)
 */

struct sr_mask_s *sr_isMatchingPattern(struct sr_config_s *sr_cfg, const char *chaine);

/**
 * sr_config_find_one() - find the name configuration file name 
 * \param sr_cfg:       The configuration to be updated with the configuration found.
 * \param original_one: The name provided by the user.
 *
 * Return pointer to the matching mask if there is one, NULL otherwise.
 * The pointer to char will hold the absolute path of the config file corresponding to original_one
 *
 * Return: pointer to a static char buffer with a path name to the corresponding configuration file.
 */
char *sr_config_find_one(struct sr_config_s *sr_cfg, const char *original_one);

 /** 
  * sr_config_parse_option() - update sr_cfg with an option setting, and it's arguments.
  * \param sr_cfg the configuration to modify
  * \param option the option to parse
  * \param argument a potential argument for the option.
  * \param arg2 another potential argument for the option.
  * \param master  Flag to say whether this is the named configuration 
  *           file (master==1) or an included one (master==0)
  *
  * update sr_cfg with the option setting (and it's argument) given
  *
  * Return: the number of arguments consumed:  0, 1, or 2.
  *
  */

int sr_config_parse_option(struct sr_config_s *sr_cfg, char *option,
			   char *argument, char *arg2, int master);

/**
 * sr_add_path() - interpret switch (no leading -) arguments (either setting action, or path entry)
 * \param sr_cfg: the input configuration (to be modified)
 * \param option: the optio to be parsed (and included in the sr_cfg)
 *
 * After having parsed all the configuration switches (starting with a dash), at the end of the command
 * line there should be an action and possibly some path names (in post case, the paths are the files to be posted)
 * This routine determines whether the option is an action or a path, and updates sr_cfg appropriately.
 *
 * Return: modification of sr_cfg with paths added, as well as action set.
 */

void sr_add_path(struct sr_config_s *sr_cfg, const char *path);

/**
 * sr_add_topic() - add to the list of topics in an sr_cfg
 * \param sr_cfg: The configuration to be modified with the additional topic.
 * \param sub:    The subtopic to be appended to the list.
 * 
 * Add a topic to the list of bindings, based on the current topic prefix
 * Add the given topic to the list of known ones for a sr_cfg.
 *
 * Return: the sr_cfg with the added (sub)topics.
 */

void sr_add_topic(struct sr_config_s *sr_cfg, const char *sub);

/**
 * sr_broker_uri - given an sr_broker_s, return a url string.
 * \param b: - the broker structure to build the string from.
 *
 * Return: a static buffer containing the URL corresponding to the broker.
 */
char *sr_broker_uri(struct sr_broker_s *b);

void sr_config_free(struct sr_config_s *sr_cfg);

/**
 * sr_config_init()  - Initialize an sr_config structure (setting defaults)
 * \param sr_cfg: The configuration to be modified with the additional topic.
 * \param progname: Sets where in the configuration file tree to look for defaults, as well
 *            as where the .cache files will be placed ( .(config|cache)/SR_APPNAME/<progname>/<config>/ )
 *            config name is guessed later during read, and the cache directories are made
 *            when the config is finalized.
 *
 * Return: void (side effect: an initialized sr_cfg.)
 */
void sr_config_init(struct sr_config_s *sr_cfg, const char *progname);

/** 
 * sr_config_read() - read an sr configuration file, initialize the struct sr_config_s 
 * \param sr_cfg: The configuration to be modified with the additional topic.
 * \param filename: the name of the configuration file to read.
 * \param abort:  flag, do we abort if there is a problem with the file?
 * \param master: Is this a master configuration, or just an included file?
 *
 * if *abort* is non-zero, then rather than returning a status, the routine 
 * causes the program to exit.
 *
 * if *master* is set, then the file being read is a potential master configuration, that
 * is a named configuration file that will correspond to a running process.
 * if *master* is 0, then the file being read is only an include file.
 *
 * Return: 1 on success, 0 on failure.
 */
int sr_config_read(struct sr_config_s *sr_cfg, char *filename, int abort, int master);

/**
 * sr_config_finalize() - consolidate settings to prepare for use.
 * \param sr_cfg: The configuration to be finalized
 * \param is_consumer: flag to indicate whether component will be consuming (cpump.)
 * 
 * after all options and files have been read, initialize 
 * remaining values in an sr_config structure (setting defaults)
 * prior to use.
 * if is_consumer, then a queue will be needed, so perform queue guessing logic.
 *
 *  Return: 1 on success, 0 on failure.
  */
int sr_config_finalize(struct sr_config_s *sr_cfg, const int is_consumer);

/**
 * sr_config_activate()  - turn into a really running instance (that can modify state files). 
 * \param sr_cfg: The configuration to be activated
 *
 * Writes the pid to a save file, sets handler for exit.
 * SIDE EFFECT: sets a signal handler for SIGTERM (to cleanly close cache on exit.)
 *
 * Return: 0  on success , failure otherwise.
 */
int sr_config_deactivate(struct sr_config_s *sr_cfg);
int sr_config_activate(struct sr_config_s *sr_cfg);

/**
 * sr_config_startstop()  - process common actions: start|stop|status 
 * \param sr_cfg: The configuration to be run/stopped/queried.
 *
 *  start a new runinng instance, or stop an existing one.
 *  with status, just check for existence.
 *  killing existing instance, etc...
 *
 *  Return: 0 - operation is complete, should exit.  
 *         <0 - operation errored, should exit. 
 *         >0 - operation succeeded, should continue.
 *
 *  the action == 'status' then 
 *    return config_is_running?0:-1
 *
 */
int sr_config_startstop(struct sr_config_s *sr_cfg);

/**
 * sr_config_add()  - perform add action.
 * \param sr_cfg: The configuration to be added.
 *
 * find a configuration in the examples and copy it to the running configuration directory.
 *
 * Return: void.
 */
void sr_config_add(struct sr_config_s *sr_cfg);

/**
 * sr_config_disable()  - disable an active configuration.
 * \param sr_cfg: The configuration to be run/stopped/queried.
 *
 * Rename a .conf file to .off so it will not be started.
 *
 * Return: void.
 */
void sr_config_disable(struct sr_config_s *sr_cfg);

/**
 * sr_config_edit()  - launch a text editor of the configuration file.
 * \param sr_cfg: The configuration to be run/stopped/queried.
 *
 * Return: void.
 */
void sr_config_edit(struct sr_config_s *sr_cfg);

/**
 * sr_config_enable()  - make a disable configuration available again.
 * \param sr_cfg: The configuration to be run/stopped/queried.
 *
 * Rename a .off file to .conf so it will be started.
 *
 * Return: void.
 */
void sr_config_enable(struct sr_config_s *sr_cfg);

/**
 * sr_config_log()  - launch a tail -f type process on the log.
 * \param sr_cfg: The configuration to be run/stopped/queried.
 *
 * Return: void.
 */
void sr_config_log(struct sr_config_s *sr_cfg);

/**
 * sr_config_remove()  - remove a configuration.
 * \param sr_cfg: The configuration to be run/stopped/queried.
 *
 * remove a .conf file from the available directory.
 *
 * Return: void.
 */
void sr_config_remove(struct sr_config_s *sr_cfg);

/**
 * sr_config_list() - list the available configurations for the given progname
 * \param sr_cfg: The configuration giving the progname for configs to be listed.
 *
 * Return: print out list of existing configurations.
 */
void sr_config_list(struct sr_config_s *sr_cfg);

#endif
