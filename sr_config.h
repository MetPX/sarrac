
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
 * struct sr_path_t - Non option arguments (paths, either of config files, or files to be posted.)
 * @path: the path itself.
 * @next: link to the next item in the singly linked list.
 */

struct sr_path_t {
   char path[PATH_MAX];
   struct sr_path_t *next;
};

/* FIXME: pas 2019 I find these struct comments completely useless.
 *        it is bloody obviously a struct, and that it has a single element followed
 *        by a next member, means it is a singly linked list. 
 *        the description restates the name of the struct... there is no additional information.
 */

/**
 * struct sr_topic_t - topic arguments.
 * @topic: the topic itself.
 * @next: link to the next item in the singly linked list.
 */

struct sr_topic_t {
  char topic[AMQP_MAX_SS]; 
  struct sr_topic_t *next;
};

/**
 * struct sr_header_t -  store headers: a list of key-value string pairs.
 * @key: the key string
 * @value: the value string
 * @next: link to the next item in the singly linked list.
 */

struct sr_header_t {
  char *key;
  char *value;
  struct sr_header_t *next;
};

/**
 * struct sr_mask_t -  store a list of accept/reject file filter masks: 
 * @clause: the original regexp string
 * @directory: the directory in effect when the clause is applied
 * @regexp: the compiled representation of the clause.
 * @accepting: boolean:  reject(0) / accept(1)  the direction to apply the clause
 * @next: link to the next item in the singly linked list.
 */

struct sr_mask_t {
  char* clause;
  char* directory;
  regex_t regexp;
  int   accepting;
  struct sr_mask_t *next;
};

/**
 * struct sr_broker_t -  store a list of brokers
 * @ssl: whether the connection includes encryption (TLS at this point)
 * @user: user name to authenticate to the broker
 * @password: password to authenticate to the broker.
 * @hostname: broker host name.
 * @port: broker port number ( 1-65535 )
 * @exchange: name of the exchange to publish to on the broker.
 * @exchange_split: number of exchanges to split publishes among.
 * @last_delivery_tag: some AMQP thing... no idea.
 * @socket: part of an established connection to a broker
 * @conn:  part of an established connection to a broker
 * @started: boolean whether the connection has been established or not.
 * @next: link to the next item in the singly linked list.
 */

struct sr_broker_t {
  int ssl;                     
  char *user;
  char *password;
  char *hostname;
  int   port;
  char *exchange;
  int   exchange_split;
  uint64_t last_delivery_tag;
  amqp_socket_t *socket;
  amqp_connection_state_t conn;
  int started;
  struct sr_broker_t *next; 
};

/**
 * struct sr_config_t - the master config struct hold an entire one.
 * @accept_unmatched: if no masks match, reject(0), or accept(1) the file.
 * @action:  the action to perform: start, stop, status, add, remove, foreground, enable, disable, etc...
 * @blocksize: the size of blocks 0 (guess), 1 ( send entire file in one block ),  else a literal blocksize
 *             used for partitioning of large files.
 * @broker: the rabbitmq AMQP broker to connect to.
 * @cache: the expiry age, in seconds of entries in the recent files cache.
 * @cachep: the recent files cache.
 * @cache_basis: 'file' | 'path' | 'none' -> modifies which cache entries are comparable.
 * @chmod_log:  permission mode bits to use for the log files.
 * @configname: the configuration being run (name of the main configuration file.)
 * @debug:  turn on debug output.
 * @delete: flag to mark that files downloaded should be deleted (unimplemented)
 * @directory: the current directory setting (used when building masks)
 * @durable: flag to pass to broker to set corresponding Queue property
 * @events:  set of events to produce/monitor (create/delete, etc...)
 * @exchange: the exchange to subscribe to.
 * @exchange_suffix:  something to append to the exchange.
 * @expire:   a time (in seconds) passed to the broker as queue lifetime.
 * @follow_symlinks:  flag to indicate whether one should visit the destination of symlinks.
 * @force_polling:  flag to switch watch algorithms , either brute polling or Inotify
 * @heartbeat:   interval, in seconds between periodic processing events.
 * @help:        flag to trigger printing help message.
 * @instance:    the instance number of the current process within a component's configuration.
 * @last_matched: the value of the last matched mask. 
 * @list:         method to generate initial input list:  file or queue
 * @log:          Use a log file, rather than standard files.
 * @logfn:        Use this log file, rather than standard files.
 * @logrotate:    number of days to keep log files around.
 * @logseverity:  severity of messages to log (regardless of where.)
 * @masks:        the list of masks to compare file names to.
 * @match:        
 * @message_ttl:  a time (in seconds) passed to the broker as message lifetime.
 * @outlet:       post|json|url - default post. choice of output format.
 * @pid:          what is the current process identifier.
 * @pidfile:      the name of the state file containing the pid.
 * @prefetch:     how many messages to request from a broker at once.
 * @progname:     the name of the program (component) being run.
 * @paths:        the list of configurations or files given on the command line.
 * @pipe:         pipe mode, read file names from standard input
 * @post_base_dir: the local directory at the root of the url tree.
 * @post_base_url: the url that corresponds to the base directory.
 * @post_broker:   the broker to post to.
 * @post_exchange: the exchange to post to on the post broker.
 * @post_exchange_split:  the count of  a team of similar exchanges.
 * @post_exchange_suffix:  appended to an exchange name.
 * @queuename:    the name of the queue for a consumer.
 * @randid:       a random id, typically used in queue name generation.
 * @realpath:     flag to indicate whether realpath should be applied before posting.
 * @realpath_filter: flag to say use the realpath for matching, but publish the original.
 * @recursive:  always set to on now, walk entire tree (FIXME, remove option?)
 * @sanity_log_dead: how many seconds old should a log be before the component is presumed dead.
 * @shim_defer_posting_to_exit: flag to have the shim library only post on process exit.
 * @shim_post_minterval:  interval in seconds, the most often one will post the same file.
 * @shim_skip_parent_open_files: flag, do not post files which are still open in ppid.
 * @sleep:    number of seconds to sleep between polls/processing loops.
 * @statehost:  flagish thing: '0','s','f' meaning no, short fqdn
 * @statehostval:  actual hostname resulting from statehost.
 * @sumalgo:  checksum algorithm to use.
 * @sumalgoz: if algo is z what is the real checksum algorithm to apply.
 * @source:  indicates the cluster of origin of a post.
 * @to:      indicates destination cluster(s) for a post.
 * @topics:  list of sub-topics to subscribe to.
 * @topic_prefix: the topic prefix to either subscribe or post to.
 * @user_headers: list of arbitrary user headers for extensions and upward compatibility.
 *
 * Contains the entire configuration for a component.
 */

struct sr_config_t {
  int                 accept_unmatched;
  char*               action;
  long unsigned       blocksize; // if partitioned, how big are they?
  struct sr_broker_t *broker;
  float               cache;
  struct sr_cache_t  *cachep;
  char               *cache_basis;
  mode_t              chmod_log;
  char               *configname;
  int                 debug;
  int                 delete;
  char               *directory;
  int                 durable;
  sr_event_t          events;
  char                *exchange;
  char                *exchange_suffix;
  float               expire;
  int                 follow_symlinks;
  int                 force_polling;
  float               heartbeat;
  int                 help;           // print usage and exit if set.
  int                 instance;
  char               *last_matched;  //have run isMatching.
  char               *list;          //method to generate initial input list:  file or queue
  int                 log;           // use a log file, rather than standard files.
  char               *logfn;           // use a log file, rather than standard files.
  float               logrotate;       // number of days to keep log files around.
  int                 logseverity;      // severity of messages to log (regardless of where.)
  struct sr_mask_t   *masks;
  struct sr_mask_t   *match;
  float              message_ttl;
  char               *outlet;
  int                 pid;
  char               *pidfile;
  int                 prefetch;
  char               *progname;
  struct sr_path_t   *paths;
  int                 pipe;  // pipe mode, read file names from standard input
  char               *post_base_dir;
  char               *post_base_url;
  struct sr_broker_t *post_broker;
  char               *post_exchange;
  int                 post_exchange_split;
  char               *post_exchange_suffix;
  char               *queuename;
  char               *randid;
  int                 realpath;
  int                 realpath_filter;
  int                 recursive;
  float               sanity_log_dead;
  int                 shim_defer_posting_to_exit;
  float               shim_post_minterval;
  int                 shim_skip_parent_open_files;
  float               sleep;
  char                statehost;  // '0','s','f' meaning no, short fqdn
  char               *statehostval;  // actual hostname resulting from statehost.
  char                sumalgo; // checksum algorithm to use.
  char                sumalgoz; // if algo is z what is downstream...
  char               *source;
  char               *to;
  struct sr_topic_t  *topics;
  char                topic_prefix[AMQP_MAX_SS];
  struct sr_header_t *user_headers;
  
};


/**
 * local_fqdn() - return fully qualified domain name
 * Return: static hostname character string.
 */
char *local_fqdn();

/**
 * isMatchingPattern() - return pointer to matched pattern, if there is one, NULL otherwise.
 * @sr_cfg: the configuration with the masks to match against.
 * @chaine: the character string to be matched
 *
 *  return pointer to matched pattern, if there is one, NULL otherwise.
 *  if called multiple times, it returns a cached response from the previous call.
 *
 * Return: The mask entry that matched, if any. (not a copy, do not play with it.)
 */

struct sr_mask_t *isMatchingPattern( struct sr_config_t *sr_cfg, const char* chaine );

/**
 * sr_config_find_one() - find the name configuration file name 
 * @sr_cfg:       The configuration to be updated with the configuration found.
 * @original_one: The name provided by the user.
 *
 * Return pointer to the matching mask if there is one, NULL otherwise.
 * The pointer to char will hold the absolute path of the config file corresponding to original_one
 *
 * Return: pointer to a static char buffer with a path name to the corresponding configuration file.
 */
char* sr_config_find_one( struct sr_config_t *sr_cfg, const char *original_one );



 /** 
  * sr_config_parse_option() - update sr_cfg with an option setting, and it's arguments.
  * @sr_cfg: the configuration to modify
  * @option: the option to parse
  * @argument: a potential argument for the option.
  * @arg2: another potential argument for the option.
  * @master:  Flag to say whether this is the named configuration 
  *           file (master==1) or an included one (master==0)
  *
  * update sr_cfg with the option setting (and it's argument) given
  *
  * Return: the number of arguments consumed:  0, 1, or 2.
  *
  */

int sr_config_parse_option( struct sr_config_t *sr_cfg, char *option, char* argument, char* arg2, int master );


/**
 * sr_add_path() - interpret switch (no leading -) arguments (either setting action, or path entry)
 * @sr_cfg: the input configuration (to be modified)
 * @option: the optio to be parsed (and included in the sr_cfg)
 *
 * After having parsed all the configuration switches (starting with a dash), at the end of the command
 * line there should be an action and possibly some path names (in post case, the paths are the files to be posted)
 * This routine determines whether the option is an action or a path, and updates sr_cfg appropriately.
 *
 * Return: modification of sr_cfg with paths added, as well as action set.
 */

void sr_add_path( struct sr_config_t *sr_cfg, const char* path );


/**
 * sr_add_topic() - add to the list of topics in an sr_cfg
 * @sr_cfg: The configuration to be modified with the additional topic.
 * @sub:    The subtopic to be appended to the list.
 * 
 * Add a topic to the list of bindings, based on the current topic prefix
 * Add the given topic to the list of known ones for a sr_cfg.
 *
 * Return: the sr_cfg with the added (sub)topics.
 */

void sr_add_topic( struct sr_config_t *sr_cfg, const char* sub );


/**
 * sr_broker_uri - given an sr_broker_t, return a url string.
 * @b: - the broker structure to build the string from.
 *
 * Return: a static buffer containing the URL corresponding to the broker.
 */
char *sr_broker_uri( struct sr_broker_t *b );



void sr_config_free( struct sr_config_t *sr_cfg );

/**
 * sr_config_init()  - Initialize an sr_config structure (setting defaults)
 * @sr_cfg: The configuration to be modified with the additional topic.
 * @progname: Sets where in the configuration file tree to look for defaults, as well
 *            as where the .cache files will be placed ( .(config|cache)/sarra/<progname>/<config>/ )
 *            config name is guessed later during read, and the cache directories are made
 *            when the config is finalized.
 *
 * Return: void (side effect: an initialized sr_cfg.)
 */
void sr_config_init( struct sr_config_t *sr_cfg, const char *progname); 


/** 
 * sr_config_read() - read an sr configuration file, initialize the struct sr_config_t 
 * @sr_cfg: The configuration to be modified with the additional topic.
 * @filename: the name of the configuration file to read.
 * @abort:  flag, do we abort if there is a problem with the file?
 * @master: Is this a master configuration, or just an included file?
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
int sr_config_read( struct sr_config_t *sr_cfg, char *filename, int abort, int master );


/**
 * sr_config_finalize() - consolidate settings to prepare for use.
 * @sr_cfg: The configuration to be finalized
 * @is_consumer: flag to indicate whether component will be consuming (cpump.)
 * 
 * after all options and files have been read, initialize 
 * remaining values in an sr_config structure (setting defaults)
 * prior to use.
 * if is_consumer, then a queue will be needed, so perform queue guessing logic.
 *
 *  Return: 1 on success, 0 on failure.
  */
int sr_config_finalize( struct sr_config_t *sr_cfg, const int is_consumer );

/**
 * sr_config_activate()  - turn into a really running instance (that can modify state files). 
 * @sr_cfg: The configuration to be activated
 *
 * Writes the pid to a save file, sets handler for exit.
 * SIDE EFFECT: sets a signal handler for SIGTERM (to cleanly close cache on exit.)
 *
 * Return: 0  on success , failure otherwise.
 */
int sr_config_activate( struct sr_config_t *sr_cfg );


/**
 * sr_config_startstop()  - process common actions: start|stop|status 
 * @sr_cfg: The configuration to be run/stopped/queried.
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
int sr_config_startstop( struct sr_config_t *sr_cfg);

/**
 * sr_config_add()  - perform add action.
 * @sr_cfg: The configuration to be added.
 *
 * find a configuration in the examples and copy it to the running configuration directory.
 *
 * Return: void.
 */
void sr_config_add( struct sr_config_t *sr_cfg );

/**
 * sr_config_disable()  - disable an active configuration.
 * @sr_cfg: The configuration to be run/stopped/queried.
 *
 * Rename a .conf file to .off so it will not be started.
 *
 * Return: void.
 */
void sr_config_disable( struct sr_config_t *sr_cfg );

/**
 * sr_config_edit()  - launch a text editor of the configuration file.
 * @sr_cfg: The configuration to be run/stopped/queried.
 *
 * Return: void.
 */
void sr_config_edit( struct sr_config_t *sr_cfg );

/**
 * sr_config_enable()  - make a disable configuration available again.
 * @sr_cfg: The configuration to be run/stopped/queried.
 *
 * Rename a .off file to .conf so it will be started.
 *
 * Return: void.
 */
void sr_config_enable( struct sr_config_t *sr_cfg );

/**
 * sr_config_log()  - launch a tail -f type process on the log.
 * @sr_cfg: The configuration to be run/stopped/queried.
 *
 * Return: void.
 */
void sr_config_log( struct sr_config_t *sr_cfg );

/**
 * sr_config_remove()  - remove a configuration.
 * @sr_cfg: The configuration to be run/stopped/queried.
 *
 * remove a .conf file from the available directory.
 *
 * Return: void.
 */
void sr_config_remove( struct sr_config_t *sr_cfg );


/**
 * sr_config_list() - list the available configurations for the given progname
 * @sr_cfg: The configuration giving the progname for configs to be listed.
 *
 * Return: print out list of existing configurations.
 */
void sr_config_list( struct sr_config_t *sr_cfg );

#endif
