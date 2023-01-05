
/*
 * This file is part of MetPX-Sarrac.
 * The Sarrac suite is Free and is proudly provided by the Government of Canada
 * Copyright (C) Her Majesty The Queen in Right of Canada, Environment Canada, 2017-2019
 *
 * Original Author: Peter.Silva@canada.ca
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

// for sr_local_fqdn()
#include <sys/socket.h>

#include <netdb.h>

//for opendir/readdir
#include <dirent.h>

// for kill
#include <signal.h>

#include <errno.h>

#include <time.h>

#include <dlfcn.h>

#include "sr_credentials.h"

#include "sr_config.h"

#include "sr_version.h"

/**
 * sr_add_path() - interpret switch (no leading -) arguments (either setting action, or path entry)
 * @arg1: sr_cfg - the input configuration (to be modified)
 * @arg2: option - the optio to be parsed (and included in the sr_cfg)
 *
 * After having parsed all the configuration switches (starting with a dash), at the end of the command
 * line there should be an action and possibly some path names (in post case, the paths are the files to be posted)
 * This routine determines whether the option is an action or a path, and updates sr_cfg appropriately.
 *
 * Return: modification of sr_cfg with paths added, as well as action set.
 */
void sr_add_path(struct sr_config_s *sr_cfg, const char *option)
{
	struct sr_path_s *p;
	struct sr_path_s *n;

        if (option == NULL) return;

	if (!strcmp(option, "add")
	    || !strcmp(option, "cleanup")
	    || !strcmp(option, "declare")
	    || !strcmp(option, "disable")
	    || !strcmp(option, "edit")
	    || !strcmp(option, "enable")
	    || !strcmp(option, "foreground")
	    || !strcmp(option, "help")
	    || !strcmp(option, "list")
	    || !strcmp(option, "log")
	    || !strcmp(option, "status")
	    || !strcmp(option, "stop")
	    || !strcmp(option, "reload")
	    || !strcmp(option, "remove")
	    || !strcmp(option, "restart")
	    || !strcmp(option, "sanity")
	    || !strcmp(option, "setup")
	    || !strcmp(option, "start")
	    ) {
		if (sr_cfg->action)
			free(sr_cfg->action);
		sr_cfg->action = strdup(option);
		return;
	}
	p = (struct sr_path_s *)malloc(sizeof(struct sr_path_s));
	if (p == NULL) {
		sr_log_msg(LOG_ERROR, "malloc of path failed!\n");
		return;
	}
	p->next = NULL;

	if (sr_cfg->realpathPost) {
		realpath(option, p->path);
	} else
		strcpy(p->path, option);

	if (!sr_cfg->paths) {
		sr_cfg->paths = p;
	} else {
		n = sr_cfg->paths;
		while (n->next)
			n = n->next;
		n->next = p;
	}
}

/**
 * sr_add_topic() - add to the list of topics in an sr_cfg
 * @sr_cfg: The configuration to be modified with the additional topic.
 * @sub:    The subtopic to be appended to the list.
 * 
 * Add the given topic to the list of known ones for a sr_cfg.
 *
 * Return: the sr_cfg with the added (sub)topics.
 */

void sr_add_topic(struct sr_config_s *sr_cfg, const char *sub)
{
	struct sr_topic_s *t;
	struct sr_topic_s *n;

	t = (struct sr_topic_s *)malloc(sizeof(struct sr_topic_s));
	if (t == NULL) {
		sr_log_msg(LOG_ERROR, "malloc of topic failed!\n");
		return;
	}
	t->next = NULL;
	strcpy(t->topic, sr_cfg->topicPrefix);
	strcat(t->topic, ".");
	strcat(t->topic, sub);

	if (!sr_cfg->topics) {
		sr_cfg->topics = t;
	} else {
		n = sr_cfg->topics;
		while (n->next)
			n = n->next;
		n->next = t;
	}
}

#ifdef FORCE_LIBC_REGEX

typedef int (*regcomp_fn) (regex_t * pregg, const char *regex, int clfags);
static regcomp_fn regcomp_fn_ptr = NULL;

typedef int (*regexec_fn) (const regex_t * preg, const char *string,
			   size_t nmatch, regmatch_t pmatch[], int eflags);

static regexec_fn regexec_fn_ptr = NULL;

#endif

struct sr_mask_s *sr_isMatchingPattern(struct sr_config_s *sr_cfg, const char *chaine)
{
	struct sr_mask_s *entry;

	if (sr_cfg->last_matched && !strcmp(sr_cfg->last_matched, chaine))
		return (sr_cfg->match);

	if (sr_cfg->last_matched)
		free(sr_cfg->last_matched);
	sr_cfg->last_matched = strdup(chaine);

	entry = sr_cfg->masks;
	while (entry) {
		// if ( (sr_cfg) && sr_cfg->debug )
		//     sr_log_msg( LOG_DEBUG,  "sr_isMatchingPattern, testing mask: %s %-30s next=%p\n", 
		//          (entry->accepting)?"accept":"reject", entry->clause, (entry->next) );

#ifdef FORCE_LIBC_REGEX
		if (!regexec_fn_ptr(&(entry->regexp), chaine, (size_t) 0, NULL, 0)) {
#else
		if (!regexec(&(entry->regexp), chaine, (size_t) 0, NULL, 0)) {
#endif
			break;	// matched
		}
		entry = entry->next;
	}
	if ((sr_cfg) && sr_cfg->debug) {
		if (entry)
			sr_log_msg(LOG_DEBUG,
				"sr_isMatchingPattern: %s matched mask: %s %s\n",
				chaine, (entry->accepting) ? "accept" : "reject", entry->clause);
		else
			sr_log_msg(LOG_DEBUG,
				"sr_isMatchingPattern: %s did not match any masks\n", chaine);
	}
	sr_cfg->match = entry;
	return (entry);
}

static void add_mask(struct sr_config_s *sr_cfg, char *directory, char *option, int accept)
{
	struct sr_mask_s *new_entry;
	struct sr_mask_s *next_entry;
	int status;
	void *handle;

	//if ( (sr_cfg) && sr_cfg->debug )
	//    fprintf( stderr, "adding mask: %s %s\n", accept?"accept":"reject", option );

	new_entry = (struct sr_mask_s *)malloc(sizeof(struct sr_mask_s));
	new_entry->next = NULL;
	new_entry->directory = (directory ? strdup(directory) : NULL);
	new_entry->accepting = accept;
	new_entry->clause = strdup(option);

#ifdef FORCE_LIBC_REGEX
	if (!regcomp_fn_ptr) {
		handle = dlopen(FORCE_LIBC_REGEX, RTLD_LAZY);

		regcomp_fn_ptr = dlsym(handle, "regcomp");
		regexec_fn_ptr = dlsym(handle, "regexec");
		if (!regcomp_fn_ptr) {
			sr_log_msg(LOG_CRITICAL,
				"cannot find regcomp library function: regex %s ignored\n", option);
			return;
		}
	}
	status = regcomp_fn_ptr(&(new_entry->regexp), option, REG_EXTENDED | REG_NOSUB);
#else
	status = regcomp(&(new_entry->regexp), option, REG_EXTENDED | REG_NOSUB);
#endif

	if (status) {
		sr_log_msg(LOG_ERROR, "invalid regular expression: %s. Ignored\n", option);
		return;
	}
	// append new entry to existing masks.
	if (sr_cfg->masks == NULL) {
		sr_cfg->masks = new_entry;
	} else {
		next_entry = sr_cfg->masks;
		while (next_entry->next != NULL) {
			next_entry = next_entry->next;
		}
		next_entry->next = new_entry;
	}
}

#define NULTERM(x)  if (x != NULL) *x = '\0' ;

/**
 * sr_broker_uri - given an sr_broker_s, return a url string.
 * @arg1: b - the broker structure to build the string from.
 *
 * Returns: a static buffer containing the URL corresponding to the broker.
 */

char *sr_broker_uri(struct sr_broker_s *b)
{
	static char buf[PATH_MAX];
	buf[0] = '\0';
	if (!b) {
		strcpy(buf, "NULL");
		return (buf);
	}

	sprintf(buf, "amqp%s://%s@%s:%d/%s%s",
		b->ssl ? "s" : "", b->user, b->hostname, b->port,
		b->exchange ? "#" : "", b->exchange ? b->exchange : "");
/*
   strcat( buf, "amqp" );
   if (b->ssl) strcat( buf, "s" );
   strcat( buf, "://" );
   strcat( buf, b->user );
   strcat( buf, b->user );
 */

	return (buf);
}

/**
 * broker_uri_parse() - given a URL string, return an sr_broker_s struct.
 * @arg1: src - the url string to parse.
 *
 * interpret a broker url (e.g. amqp://hoho@localhost ) and to allocate
 * and initialize an sr_brokert_t struct.
 *
 * Return: an initialized allocated sr_broker_s struct.
 */

static struct sr_broker_s *broker_uri_parse(char *src)
{
	/* copy src string to buf, adding nuls to separate path elements. 
	   so each string is nul-treminated.
	 */

	struct sr_broker_s *b;
	char buf[PATH_MAX];
	char *c, *d, *save;

	if (!src) return (NULL);

	b = (struct sr_broker_s *)malloc(sizeof(struct sr_broker_s));
	strcpy(buf, src);

	b->ssl = (buf[4] == 's');
	save = buf + 7 + (b->ssl);
	d = strchr(save, '@');
	if (!d) {
	        b->user = strdup("anonymous");
       		b->password = strdup("anonymous");
	        c=save;
	} else {
 	    	// save points at user string, null terminated.
	    	*d = '\0';
    		c = d + 1;		// continuation point.
	    	d = strchr(save, ':');
	    	if (d) {
	    		*d = '\0';
	    		d++;
	    		b->password = strdup(d);
    		} else
	    		b->password = NULL;
	    	b->user = strdup(save);
	}

	// c points at hostname
	save = c;
	d = strchr(save, ':');
	if (d) {		// port specified.
		*d = '\0';
		d++;
		b->port = atoi(d);
	} else if (b->ssl) {
		b->port = 5671;
	} else
		b->port = 5672;

	if (!d)
		d = strchr(save, '/');
	if (d)
		*d = '\0';

	b->hostname = strdup(save);

	b->conn = NULL;
	b->exchange = NULL;
	b->next = NULL;
	b->socket = NULL;
	b->started = 1;
	b->last_delivery_tag = 0;

	//fprintf( stderr, "FIXME: broker ssl=%d, host: +%s+ , port: %d, user: +%s+ password: _%s_\n", 
	//   b->ssl, b->hostname, b->port, b->user, b->password );
	return (b);
}

/**
 * broker_free() - free all allocated elements of an sr_broker struct, and the struct itself.
 * @arg1: b - the broker struct to de-allocate.
 *
 * Return: void
 */
static void broker_free(struct sr_broker_s *b)
{
	if (!b)
		return;
	if (b->hostname)
		free(b->hostname);
	if (b->user)
		free(b->user);
	if (b->password)
		free(b->password);
	if (b->exchange)
		free(b->exchange);
	free(b);
}

struct sr_header_s *sr_headers_copy(struct sr_header_s *o)
/* return a linked list of headers that is a deep copy
   of the original.
 */
{
	struct sr_header_s *n = NULL, *c = NULL, *i = NULL;
	for (c = o; c; c = c->next) {
		i = (struct sr_header_s *)malloc(sizeof(struct sr_header_s));
		i->key = strdup(o->key);
		i->value = strdup(o->value);
		i->next = n;
		n = i;
	}
	return (n);
}

void sr_headers_free(struct sr_header_s *o)
/* empty out a list of headers.
 */
{
	struct sr_header_s *c = NULL, *i = NULL;

	c = o;
	while (c) {
		free(c->key);
		free(c->value);
		i = c;
		c = c->next;
		free(i);
	}
	return;
}

int sr_add_decl(struct sr_config_s *cfg, char *what, char *s)
  /*
     interpret a declare option.

     return value: number of arguments consumed.
     0 if invalid.
   */
{
	char *eq, *s2;

	if (!strcmp(what, "env") || !strcmp(what, "var")) {
		s2 = strdup(s);
		eq = strchr(s2, '=');
		if (!eq) {
			sr_log_msg(LOG_ERROR, "for: declare env name=value, = missing: %s\n", s);
			free(s2);
			return (3);
		}

		*eq = '\0';
		setenv(s2, (eq + 1), 1);
		*eq = '=';
		free(s2);

		return (3);
	} else if (!strcmp(what, "source")) {
		sr_log_msg(LOG_DEBUG, "declare source %s ignored\n", s);
	} else if (!strcmp(what, "subscriber")) {
		sr_log_msg(LOG_DEBUG, "declare subscriber %s ignored\n", s);
	}
	return (2);

}

int sr_add_header(struct sr_config_s *cfg, char *s)
  /*
     Add a (user defined) header to the list of existing ones. 
     see StrinIsTrue for explanation of bitmask return values.
   */
{
	char *eq;
	struct sr_header_s *new_header;

	eq = strchr(s, '=');
	if (!eq) {
		return (0);
	}
	new_header = (struct sr_header_s *)malloc(sizeof(struct sr_header_s));

	if (!new_header) {
		return (1);
	}
	*eq = '\0';
	new_header->key = strdup(s);
	*eq = '=';
	new_header->value = strdup(eq + 1);
	new_header->next = cfg->user_headers;
	cfg->user_headers = new_header;
	return (3);
}

static int StringIsTrue(const char *s)
 /*
    return bitmask:  0-1 string value,  argument is a value 0-1
    0- 00 - unlikely to occur, there is no value, and returning false.
    1- 01 - value is false and argument provide ( -option no )
    2- 10 - value is true and argument omitted  ( -option    )
    3- 11 - value is true and argument provided ( -option yes ) 
  */
{

	if ((s == NULL) || (*s == '-'))
		return (2);

	if (!strcasecmp(s, "true") || !strcasecmp(s, "on") || !strcasecmp(s, "yes"))
		return (3);

	if (!strcasecmp(s, "false") || !strcasecmp(s, "off") || !strcasecmp(s, "no"))
		return (1);

	return (0);
}

static long int chunksize_from_str(char *s)
{
	char u;			// unit char spec.
	long unsigned int value;
	long unsigned int power;

	u = s[strlen(s) - 1];
	if ((u == 'b') || (u == 'B'))
		u = s[strlen(s) - 2];

	value = atoll(s);
	power = 0;
	switch (u) {
	case 'k':
	case 'K':
		power = 10;
		break;
	case 'g':
	case 'G':
		power = 30;
		break;
	case 't':
	case 'T':
		power = 40;
		break;
	}
	return (value << power);

}

#define TOKMAX (1024)

char *sr_local_fqdn()
/* 
   return the fully qualified hostname of the current machine
   mostly just a copy/paste from: 
      https://stackoverflow.com/questions/504810/how-do-i-find-the-current-machines-full-hostname-in-c-hostname-and-domain-info
 */
{

	struct addrinfo hints, *info, *p;
	int gai_result;

	char *found = NULL;
	static char hostname[1024];
	hostname[1023] = '\0';
	gethostname(hostname, 1023);

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;	/*either IPV4 or IPV6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_CANONNAME;

	if ((gai_result = getaddrinfo(hostname, NULL, &hints, &info)) != 0) {
		sr_log_msg(LOG_CRITICAL,
			"cannot get hostname.  Getaddrinfo returned: %s\n",
			gai_strerror(gai_result));
		return (NULL);
	}

	for (p = info; p != NULL; p = p->ai_next) {
		found = p->ai_canonname;
	}

	if (found)
		strcpy(hostname, found);

	freeaddrinfo(info);
	return (hostname);
}

static float seconds_from_duration_str(char *s)
{
	int last;
	int factor = 1;

	if (!s)
		return (0.0);

	last = strlen(s) - 1;
	switch (s[last]) {
	case 'm':
	case 'M':
		factor *= 60;
		break;
	case 'h':
	case 'H':
		factor *= 60 * 60;
		break;
	case 'd':
	case 'D':
		factor *= 24 * 60 * 60;
		break;
	case 'w':
	case 'W':
		factor *= 7 * 24 * 60 * 60;
		break;
	case 's':
	default:
		break;
	}
	return ((float)(atof(s) * factor));
}

static char *subarg(struct sr_config_s *sr_cfg, char *arg)
/* 
   do variable substitution in arguments to options.  There are some pre-defined ones, 
   if not found, punt to getenv.

   note, arg does get modified ( *e='\0' to terminate variable names, then returned to '}' after )
   should leave identical to during entry.
 */
{
	static char subargbuf[TOKMAX];
	char *c, *d, *var, *val, *e;

	if (!arg)
		return (NULL);
	c = arg;
	d = subargbuf;
	while (*c != '\0') {
		if (*c != '$') {
			*d = *c;
			d++;
			c++;
			continue;
		}
		c++;
		if (*c != '{') {
			*d = '$';
			d++;
			continue;
		}
		c++;
		var = c;
		e = var;
		while ((*e != '\0') && (*e != '}')) {
			e++;
		}
		if (*e == '\0') {
			sr_log_msg(LOG_WARNING,
				"malformed argument: %s. returning unmodified.\n", arg);
			return (arg);
		}
		*e = '\0';
		*d = '\0';	// ready for catenation.
		if (!strcmp(var, "HOSTNAME")) {
			val = sr_local_fqdn();

		} else if (!strcmp(var, "PROGRAM")) {
			val = sr_cfg->progname;

		} else if (!strcmp(var, "CONFIG")) {
			val = sr_cfg->configname;

		} else if (!strcmp(var, "BROKER_USER")) {
			val = sr_cfg->broker->user;

		} else if (!strcmp(var, "RANDID")) {
			val = sr_cfg->randid;

		} else {
			val = getenv(var);
			if (!val) {
				sr_log_msg(LOG_ERROR, "Environment variable not set: %s\n", var);
				*e = '}';
				return (NULL);
			}
		}
		strcat(d, val);
		d += strlen(val);
		*e = '}';
		c = e + 1;
	}
	*d = '\0';
	//sr_log_msg(LOG_DEBUG, "argument after substitutions: %s\n", subargbuf);
	return (subargbuf);

}

static char token_line[TOKMAX];

// OPTIS - Option Is ... the option string matches x.

int sr_config_parse_option(struct sr_config_s *sr_cfg, char *option, char *arg,
			   char *arg2, int master)
/*
   
   returns 
      value > 0 : number of arguments to advance
      value 0   : end of options.
      return <0 : error.
 */
{

	char *brokerstr, *argument, *argument2, *spare;
	int val;
	int retval;
	//char p[PATH_MAX];

	if (strcspn(option, " \t\n#") == 0)
		return (0);

	argument = subarg(sr_cfg, arg);
	if (argument)
		argument = strdup(argument);

	if (arg2) {
		argument2 = strdup(subarg(sr_cfg, arg2));
	} else {
		argument2 = NULL;
	}
	//if (sr_cfg->debug)
	//   sr_log_msg( LOG_DEBUG, "option: %s,  argument: %s \n", option, argument );
	retval = 1;

	if (!strcmp(option, "accept") || !strcmp(option, "get")) {
		add_mask(sr_cfg, sr_cfg->directory, argument, 1);
		retval = 2;

	} else if (!strcmp(option, "accept_unmatch")
		   || !strcmp(option, "accept_unmatched")
		   || !strcmp(option, "au")) {
		val = StringIsTrue(argument);
		sr_cfg->accept_unmatched = val & 2;
		retval = (1 + (val & 1));

	} else if (!strcmp(option, "action") || !strcmp(option, "a")) {
		if (sr_cfg->action)
			free(sr_cfg->action);
		sr_cfg->action = argument;
		argument = NULL;
		retval = (2);

	} else if (!strcmp(option, "blocksize") || !strcmp(option, "parts")) {
		if (!argument) {
			sr_log_msg(LOG_ERROR, "parts (partition strategy) argument missing\n");
			retval = 1;
		} else {
			sr_cfg->blocksize = chunksize_from_str(argument);
			retval = 2;
		}

	} else if (!strcmp(option, "broker") || !strcmp(option, "b")) {
		if (sr_cfg->broker) {
			broker_free(sr_cfg->broker);
			sr_cfg->broker = NULL;
		}
		brokerstr = sr_credentials_fetch(argument);
		if (brokerstr == NULL) {
			sr_cfg->broker = broker_uri_parse(argument);
			if (!sr_cfg->broker)
			    sr_log_msg(LOG_ERROR, "unknown/invalid broker: %s.\n", argument);
				retval = -2;
		} else {
			sr_cfg->broker = broker_uri_parse(brokerstr);
		}
		free(brokerstr);
		retval = 2;

	} else if (!strcmp(option, "cache") || !strcmp(option, "caching")
	       || !strcmp(option, "no_duplicates")
		   || !strcmp(option, "noduplicates") || !strcmp(option, "nd")
		   || !strcmp(option, "suppress_duplicates")
		   || !strcmp(option, "sd")
		   || !strcmp(option, "nodupe_ttl")){
		if isalpha
			(*argument) {
			val = StringIsTrue(argument);
			sr_cfg->cache = (float)((val & 2) ? 900 : 0);
			retval = (1 + (val & 1));
		} else {
			sr_cfg->cache = seconds_from_duration_str(argument);
			retval = 2;
		}
	} else if (!strcmp(option, "suppress_duplicates_basis")
		   || !strcmp(option, "sdb") || !strcmp(option, "cache_basis")
		   || !strcmp(option, "nodupe_basis")
		   || !strcmp(option, "cb")) {
		if (!strcmp(argument, "data") || !strcmp(argument, "name")
		    || !strcmp(argument, "path")) {
			sr_cfg->cache_basis = argument;
            argument=NULL;
		} else {
			sr_log_msg(LOG_ERROR,
				"unknown basis for duplicate suppression: %s (...using default: %s)\n",
				argument, sr_cfg->cache_basis);
		}
		retval = (2);

	} else if (!strcmp(option, "chmod_log") || !strcmp(option, "permLog")) {
		sscanf(argument, "%04o", &(sr_cfg->chmod_log));
		retval = 2;

	} else if (!strcmp(option, "config") || !strcmp(option, "include")
		   || !strcmp(option, "c")) {
                if (argument) {
			val = sr_config_read(sr_cfg, argument, 1, master);
			if (val < 0)
				retval = -1;
			else
				retval = 2;
                } else {
			sr_log_msg(LOG_ERROR, "config option requires a file name argument, none given\n");
                        retval=-1;
                }

	} else if (!strcmp(option, "debug")) {
		val = StringIsTrue(argument);
		sr_cfg->debug = val & 2;
		sr_cfg->loglevel = LOG_DEBUG;
		sr_set_loglevel(LOG_DEBUG);
		retval = (1 + (val & 1));

	} else if (!strcmp(option, "declare")) {
		retval = sr_add_decl(sr_cfg, argument, argument2);

	} else if (!strcmp(option, "declare_exchange")
                || !strcmp(option,"de")||!strcmp(option,"dx")
                || !strcmp(option,"exchangeDeclare")||!strcmp(option,"ed")
                ) {
		val = StringIsTrue(argument);
		sr_cfg->exchangeDeclare = val & 2;
		retval = (1 + (val & 1));

	} else if (!strcmp(option, "declare_queue")||!strcmp(option,"dq")
	          ||!strcmp(option, "queueDeclare")||!strcmp(option,"qd")) {
		val = StringIsTrue(argument);
		sr_cfg->queueDeclare = val & 2;
		retval = (1 + (val & 1));

	} else if (!strcmp(option, "delete")) {
		val = StringIsTrue(argument);
		sr_cfg->delete = val & 2;
		retval = (1 + (val & 1));

	} else if (!strcmp(option, "directory")) {
		if (sr_cfg->directory)
			free(sr_cfg->directory);
		sr_cfg->directory = argument;
		argument = NULL;
		retval = 2;

	} else if (!strcmp(option, "post_document_root")
		   || !strcmp(option, "pdr") || !strcmp(option, "document_root")
		   || !strcmp(option, "documentRoot")
		   || !strcmp(option, "post_documentRoot")
		   || !strcmp(option, "dr")) {
		sr_log_msg(LOG_WARNING,
			"please replace (deprecated) [post_]document_root with post_baseDir: %s.\n",
			argument);
		if (sr_cfg->post_baseDir)
			free(sr_cfg->post_baseDir);
		sr_cfg->post_baseDir = argument;
		argument = NULL;

	} else if (!strcmp(option, "post_base_dir") || !strcmp(option, "pbd")
	       ||  !strcmp(option, "post_baseDir") ||  !strcmp(option, "post_basedir") ) {
		if (sr_cfg->post_baseDir)
			free(sr_cfg->post_baseDir);
		sr_cfg->post_baseDir = argument;
		argument = NULL;
		retval = 2;

    } else if (!strcmp(option, "post_topic_prefix") || !strcmp(option, "ptp" )
           || !strcmp(option, "post_topicPrefix" )) {
        strcpy( sr_cfg->post_topicPrefix, argument );
        retval = 2;

	} else if (!strcmp(option, "durable")) {
		val = StringIsTrue(argument);
		sr_cfg->durable = val & 2;
		retval = (1 + (val & 1));

	} else if (!strcmp(option, "events") || !strcmp(option, "e") || !strcmp(option, "fileEvents")) {
                spare=strdup(argument);
		sr_cfg->events = sr_parse_events(argument);
                if ( sr_cfg->events & SR_EVENT_ERROR ) {
			sr_log_msg(LOG_ERROR, "Unrecognized event in: %s.\n", spare );
                }
                free(spare);
                spare=NULL;
		retval = (2);

	} else if (!strcmp(option, "exchange") || !strcmp(option, "ex")) {
		if (sr_cfg->exchange)
			free(sr_cfg->exchange);
		sr_cfg->exchange = argument;
		argument = NULL;
		retval = (2);

	} else if (!strcmp(option, "exchange_suffix") || !strcmp(option, "exs")
		   || !strcmp(option,"exchangeSuffix") || !strcmp(option, "xs")) {
		if (sr_cfg->exchangeSuffix)
			free(sr_cfg->exchangeSuffix);
		sr_cfg->exchangeSuffix = argument;
		argument = NULL;
		retval = (2);

	} else if (!strcmp(option, "expire") || !strcmp(option, "expiry")) {
		if isalpha
			(*argument) {
			val = StringIsTrue(argument);
			sr_cfg->expire = (float)((val & 2) ? 3 * 60 : 0);
			retval = (1 + (val & 1));
		} else {
			sr_cfg->expire = seconds_from_duration_str(argument);
			retval = (2);
		}
	} else if (!strcmp(option, "follow_symlinks") || !strcmp(option, "fs")
		   || !strcmp(option, "follow")) {
		val = StringIsTrue(argument);
		sr_cfg->follow_symlinks = val & 2;
		retval = (1 + (val & 1));

	} else if (!strcmp(option, "force_polling")) {
		val = StringIsTrue(argument);
		sr_cfg->force_polling = val & 2;
		retval = (1 + (val & 1));

	} else if (!strcmp(option, "heartbeat") || !strcmp(option, "hb") || !strcmp(option, "housekeeping") ) {
		sr_cfg->heartbeat = seconds_from_duration_str(argument);
		retval = (2);

	} else if (!strcmp(option, "help") || !strcmp(option, "h")) {
		sr_cfg->help = 1;
		retval = (1);

	} else if (!strcmp(option, "header")) {
		val = sr_add_header(sr_cfg, argument);
		retval = (1 + (val & 1));

	} else if (!strcmp(option, "logrotate") || !strcmp(option, "lr")
	           || !strcmp(option, "logRotateCount")
		   || !strcmp(option, "logdays") || !strcmp(option, "ld")) {

		sr_cfg->logrotate = atoi(argument);
		retval = (2);

	} else if (!strcmp(option, "logrotate_interval")
		   || !strcmp(option, "lri") || !strcmp(option, "logRotateInterval")) {
		sr_cfg->logrotate_interval = (int)seconds_from_duration_str(argument);
		retval = (2);

	} else if (!strcmp(option, "loglevel") || !strcmp(option, "logLevel")) {
		if (!strcasecmp(argument, "info")) {
			sr_cfg->loglevel = LOG_INFO;
		} else if (!strcasecmp(argument, "warning")
			   || !strcasecmp(argument, "warn")) {
			sr_cfg->loglevel = LOG_WARNING;
		} else if (!strcasecmp(argument, "error")) {
			sr_cfg->loglevel = LOG_ERROR;
		} else if (!strcasecmp(argument, "critical")) {
			sr_cfg->loglevel = LOG_CRITICAL;
		} else if (!strcasecmp(argument, "debug")) {
			sr_cfg->loglevel = LOG_DEBUG;
		} else if (!strcasecmp(argument, "none")) {
			sr_cfg->loglevel = 0;
		} else {
			sr_cfg->loglevel = atoi(argument);
		}
		sr_set_loglevel(sr_cfg->loglevel);
		retval = (2);

	} else if (!strcmp(option, "log")) {
		val = StringIsTrue(argument);
		sr_cfg->log = val & 2;
		retval = (1 + (val & 1));

	} else if (!strcmp(option, "log_reject") || !strcmp(option, "logReject") ) {
		val = StringIsTrue(argument);
		sr_cfg->log_reject = val & 2;
		retval = (1 + (val & 1));

	} else if (!strcmp(option, "message-ttl") || !strcmp(option, "msgttl")
		   || !strcmp(option, "mttl")) {
		if isalpha
			(*argument) {
			val = StringIsTrue(argument);
			sr_cfg->message_ttl = (float)((val & 2) ? 30 * 60 : 0);
			retval = (1 + (val & 1));
		} else {
			sr_cfg->message_ttl = seconds_from_duration_str(argument);
			retval = (2);
		}
	} else if (!strcmp(option, "outlet")) {
		sr_cfg->outlet = argument;
		argument = NULL;
		retval = (2);

	} else if (!strcmp(option, "queue") || !strcmp(option, "q")) {
		sr_cfg->queuename = argument;
		argument = NULL;
		retval = (2);

	} else if (!strcmp(option, "reject")) {
		add_mask(sr_cfg, sr_cfg->directory, argument, 0);
		retval = (2);

	} else if (!strcmp(option, "path") || !strcmp(option, "p")) {
		sr_add_path(sr_cfg, argument);
		retval = (2);

	} else if (!strcmp(option, "pipe")) {
		val = StringIsTrue(argument);
		sr_cfg->pipe = val & 2;
		retval = (1 + (val & 1));

	} else if (!strcmp(option, "post_broker") || !strcmp(option, "pb")) {
		if (sr_cfg->post_broker) {
			broker_free(sr_cfg->post_broker);
			sr_cfg->post_broker=NULL;
		}
		brokerstr = sr_credentials_fetch(argument);
		if (brokerstr == NULL) {
			sr_log_msg(LOG_NOTICE,
				"no stored credential for post_broker: %s.\n", argument);
			sr_cfg->post_broker = broker_uri_parse(argument);
		} else {
			sr_cfg->post_broker = broker_uri_parse(brokerstr);
		}
		free(brokerstr);
		retval = (2);

	} else if (!strcmp(option, "post_exchange") || !strcmp(option, "px")) {
		if (sr_cfg->post_exchange)
			free(sr_cfg->post_exchange);
		sr_cfg->post_exchange = argument;
		argument = NULL;
		retval = (2);

	} else if (!strcmp(option, "post_exchange_split")
		   || !strcmp(option, "pxs")
		   || !strcmp(option, "post_exchangeSplit")) {
		sr_cfg->post_exchange_split = atoi(argument);
		retval = (2);

	} else if (!strcmp(option, "post_exchangeSuffix") || !strcmp(option, "post_exchangeSuffix") ) {
		sr_cfg->post_exchangeSuffix = argument;
		argument = NULL;
		retval = (2);

	} else if ( !strcmp(option, "post_rate_limit") || !strcmp(option, "pxs")
           || !strcmp(option, "message_rate_max") || !strcmp(option, "mrx")
           || !strcmp(option, "messageRateMax")) {
		sr_cfg->post_rate_limit = atoi(argument);
		retval = (2);

	} else if (!strcmp(option, "prefetch")) {
		sr_cfg->prefetch = atoi(argument);
		retval = (2);

	} else if (!strcmp(option, "realpath") || !strcmp(option, "realpath_post")
	          || !strcmp(option, "realpathPost") ) {
		val = StringIsTrue(argument);
		sr_cfg->realpathPost = val & 2;
		retval = (1 + (val & 1));

	} else if (!strcmp(option, "realpath_filter")||!strcmp(option, "realpathFilter")) {
		val = StringIsTrue(argument);
		sr_cfg->realpathFilter = val & 2;
		retval = (1 + (val & 1));

		/*
		   } else if ( !strcmp( option, "recursive" ) ) {
		   val = StringIsTrue(argument);
		   sr_cfg->recursive = val&2;
		   return(1+(val&1));
		 */
	} else if (!strcmp(option, "sanity_log_dead")) {
		sr_cfg->sanity_log_dead = seconds_from_duration_str(argument);
		retval = (2);

	} else if (!strcmp(option, "shim_defer_posting_to_exit")) {
		val = StringIsTrue(argument);
		sr_cfg->shim_defer_posting_to_exit = val & 2;
		retval = (1 + (val & 1));

	} else if (!strcmp(option, "shim_post_minterval")) {
		sr_cfg->shim_post_minterval = seconds_from_duration_str(argument);
		retval = (2);

	} else if (!strcmp(option, "shim_post_once")) {
		val = StringIsTrue(argument);
		sr_cfg->shim_post_minterval = (val & 2) ? (3600 * 24 * 7) : 0.0;
		retval = (1 + (val & 1));

	} else if (!strcmp(option, "shim_skip_parent_open_files")) {
		val = StringIsTrue(argument);
		sr_cfg->shim_skip_parent_open_files = val & 2;
		retval = (1 + (val & 1));

	} else if (!strcmp(option, "sleep")) {
		sr_cfg->sleep = seconds_from_duration_str(argument);
		retval = (2);

	} else if (!strcmp(option, "source")) {
		if (sr_cfg->source)
			free(sr_cfg->source);
		sr_cfg->source = argument;
		argument = NULL;
		retval = (2);

	} else if (!strcmp(option, "subtopic") || !strcmp(option, "sub")) {
		sr_add_topic(sr_cfg, argument);
		retval = (2);

	} else if (!strcmp(option, "statehost") || !strcmp(option, "sh")) {

		val = StringIsTrue(argument);
		sr_cfg->statehost = val & 2;
/*
		sr_cfg->statehost = 's';
		if (!strcasecmp(argument, "short")) {
			sr_cfg->statehost = 's';
			retval = (2);
		} else if (!strcasecmp(argument, "fqdn")) {
			sr_cfg->statehost = 'f';
			retval = (2);
		} else {
			val = StringIsTrue(argument);
			val = val & 2;
			if (!val) {
				sr_cfg->statehost = 's';
			};
			retval = (1 + (val & 1));
		}
 */
	} else if (!strcmp(option, "strip")) {
		sr_cfg->strip = atoi(argument);
		// Check if arg was a number, if not: REGEX
		if (sr_cfg->strip == 0 && argument[0] != '0') {
			// REGEX processing...
		}
		retval = (2);

	} else if (!strcmp(option, "sum") || !strcmp(option, "integrity")) {
		sr_cfg->sumalgo = argument[0];
		if (sr_cfg->sumalgo == 'z')
			sr_cfg->sumalgoz = argument[2];
		retval = (2);

	} else if (!strcmp(option, "to")) {
		if (sr_cfg->to)
			free(sr_cfg->to);
		sr_cfg->to = argument;
		argument = NULL;
		retval = (2);

	} else if (!strcmp(option, "topic_prefix") || !strcmp(option, "tp")
	       || !strcmp(option, "topicPrefix")) {
		strcpy(sr_cfg->topicPrefix, argument);
		retval = (2);

	} else if (!strcmp(option, "url") || !strcmp(option, "u")) {
		sr_log_msg(LOG_WARNING,
			"please replace (deprecated) url with post_baseUrl: %s.\n", argument);
		if (sr_cfg->post_baseUrl)
			free(sr_cfg->post_baseUrl);
		sr_cfg->post_baseUrl = argument;
		argument = NULL;
		retval = (2);
	} else if (!strcmp(option, "post_base_url") || !strcmp(option, "pbu")
	       || !strcmp(option, "post_baseUrl")  || !strcmp(option, "post_baseurl")) {
		if (sr_cfg->post_baseUrl)
			free(sr_cfg->post_baseUrl);
		sr_cfg->post_baseUrl = argument;
		argument = NULL;
		retval = (2);

	} else if (!strcmp(option, "v2compatRenameDoublePost")) {
		val = StringIsTrue(argument);
		sr_cfg->v2compatRenameDoublePost = val & 2;
		retval = (1 + (val & 1));
	} else if (!strcmp(option, "vip")) {
		if (sr_cfg->vip)
			free(sr_cfg->vip);
		sr_cfg->vip = argument;
		argument = NULL;
		retval = (2);

	} else if (!strcmp(option, "xattr_disable")
		   || !strcmp(option, "xattr_disabled")
		   || !strcmp(option, "xd")) {
		if (argument && (*argument != '-')) {
			sr_cfg->xattr_cc = !(2 & StringIsTrue(argument));
			retval = (2);
		} else {
			/* do nothing, by default, xattr_cc is disabled */
			retval = (1);
		}
	} else {
		sr_log_msg(LOG_NOTICE, "%s option not implemented, ignored.\n", option);
	}

	if (argument)
		free(argument);
	if (argument2)
		free(argument2);
	return (retval);
}

void sr_config_free(struct sr_config_s *sr_cfg)
{
	struct sr_mask_s *e;

	if (sr_cfg->action)
		free(sr_cfg->action);
	sr_cfg->action=NULL;
	if (sr_cfg->configname)
		free(sr_cfg->configname);
	sr_cfg->configname=NULL;
	if (sr_cfg->directory)
		free(sr_cfg->directory);
	sr_cfg->directory=NULL;
	if (sr_cfg->post_baseDir)
		free(sr_cfg->post_baseDir);
	sr_cfg->post_baseDir=NULL;
	if (sr_cfg->exchange)
		free(sr_cfg->exchange);
	sr_cfg->exchange=NULL;
	if (sr_cfg->exchangeSuffix)
		free(sr_cfg->exchangeSuffix);
	sr_cfg->exchangeSuffix=NULL;
	if (sr_cfg->last_matched)
		free(sr_cfg->last_matched);
	sr_cfg->last_matched=NULL;
	if (sr_cfg->queuename)
		free(sr_cfg->queuename);
	sr_cfg->queuename=NULL;
	if (sr_cfg->outlet)
		free(sr_cfg->outlet);
	sr_cfg->outlet=NULL;
	if (sr_cfg->pidfile)
		free(sr_cfg->pidfile);
	sr_cfg->pidfile=NULL;
	if (sr_cfg->post_exchange)
		free(sr_cfg->post_exchange);
	sr_cfg->post_exchange=NULL;
	if (sr_cfg->post_exchangeSuffix)
		free(sr_cfg->post_exchangeSuffix);
	sr_cfg->post_exchangeSuffix=NULL;
	if (sr_cfg->progname)
		free(sr_cfg->progname);
	sr_cfg->progname=NULL;
	if (sr_cfg->randid)
		free(sr_cfg->randid);
	sr_cfg->randid=NULL;
	if (sr_cfg->source)
		free(sr_cfg->source);
	sr_cfg->source=NULL;
	if (sr_cfg->to)
		free(sr_cfg->to);
	sr_cfg->to=NULL;
	if (sr_cfg->post_baseUrl)
		free(sr_cfg->post_baseUrl);
	sr_cfg->post_baseUrl=NULL;

	if (sr_cfg->broker)
		broker_free(sr_cfg->broker);
	sr_cfg->broker = NULL;
	if (sr_cfg->post_broker)
		broker_free(sr_cfg->post_broker);
	sr_cfg->post_broker = NULL;
	if (sr_cfg->vip)
		free(sr_cfg->vip);
        sr_cfg->vip=NULL;
	while (sr_cfg->masks) {
		e = sr_cfg->masks;
		sr_cfg->masks = e->next;
		regfree(&(e->regexp));
		free(e->directory);
		free(e->clause);
		free(e);
	}
	while (sr_cfg->user_headers) {
		struct sr_header_s *tmph;
		tmph = sr_cfg->user_headers;
		free(tmph->key);
		free(tmph->value);
		sr_cfg->user_headers = tmph->next;
		free(tmph);
	}

    while ( sr_cfg->topics ) {
		struct sr_topic_s *tmpt;
		tmpt = sr_cfg->topics;
		sr_cfg->topics = sr_cfg->topics->next;
		free(tmpt);
    }
	struct sr_path_s *p = sr_cfg->paths;
	while (p) {
		struct sr_path_s *tmpp;
		tmpp = p;
		p = p->next;
		free(tmpp);
	}

	sr_credentials_cleanup();
	sr_log_cleanup();
	free(sr_cfg->logfn);
	sr_cfg->logfn=NULL;

	sr_cache_close(sr_cfg->cachep);
	sr_cfg->cachep = NULL;
	if (sr_cfg->cache_basis)
		free(sr_cfg->cache_basis);
	sr_cfg->cache_basis=NULL;

}

void sr_config_init(struct sr_config_s *sr_cfg, const char *progname)
{
	char *c;
	char p[256];

	sr_credentials_init();
	sr_cfg->action = strdup("foreground");
	sr_cfg->accept_unmatched = 1;
        if ( getenv("SR_DEV_APPNAME" ) ) 
        {
             strcpy( sr_cfg->appname, getenv("SR_DEV_APPNAME") );
        } else {
             strcpy( sr_cfg->appname, SR_APPNAME );
        } 
        if ( !getenv("OPENSSL_CONF" ) ) {
	     setenv("OPENSSL_CONF", "/etc/ssl/", 1);
        }
	sr_cfg->blocksize = 1;
	sr_cfg->broker = NULL;
	sr_cfg->cache = 0;
	sr_cfg->cachep = NULL;
	sr_cfg->cache_basis = strdup("path");
	sr_cfg->chmod_log = 0600;
	sr_cfg->configname = NULL;
	sr_cfg->debug = 0;
        sr_cfg->exchangeDeclare = 1;
        sr_cfg->queueDeclare = 1;
	sr_cfg->delete = 0;
	sr_cfg->directory = NULL;
	sr_cfg->post_baseDir = NULL;
	sr_cfg->durable = 1;
	sr_cfg->events = (SR_EVENT_CREATE | SR_EVENT_MODIFY | SR_EVENT_DELETE | SR_EVENT_LINK);
	sr_cfg->expire = 3 * 60;
	sr_cfg->exchange = NULL;
	sr_cfg->exchangeSuffix = NULL;
	sr_cfg->follow_symlinks = 0;
	sr_cfg->force_polling = 0;
	sr_cfg->instance = 1;
	sr_cfg->last_matched = NULL;
	sr_cfg->log = 0;
	sr_cfg->log_reject = 0;
	sr_cfg->logfn = NULL;
	sr_cfg->logrotate = 5;
	sr_cfg->logrotate_interval = 24 * 60 * 60;
	sr_cfg->loglevel = LOG_INFO;
	sr_cfg->masks = NULL;
	sr_cfg->match = NULL;
	sr_cfg->message_ttl = 0.0;
	sr_cfg->outlet = strdup("json");
	sr_cfg->paths = NULL;
	sr_cfg->pid = -1;
	sr_cfg->pidfile = NULL;
	sr_cfg->pipe = 0;
	sr_cfg->post_broker = NULL;
	sr_cfg->post_exchange = NULL;
	sr_cfg->post_exchange_split = 0;
	sr_cfg->post_rate_limit = 0;
	sr_cfg->post_exchangeSuffix = NULL;
	sr_cfg->prefetch = 25;

	if (progname) {		/* skip the sr_ prefix */
		c = strchr(progname, '_');
		if (c)
			sr_cfg->progname = strdup(c + 1);
		else
			sr_cfg->progname = strdup(progname);
	} else {
		sr_cfg->progname = NULL;
	}

	sr_cfg->queuename = NULL;
	srand(time(0));
	sr_cfg->randid = malloc((RANDID_LEN + 1) * sizeof(char));
	for (c = sr_cfg->randid; c < (sr_cfg->randid + RANDID_LEN); ++c)
		sprintf(c, "%x", rand() % 16);

	sr_cfg->realpathPost = 0;
	sr_cfg->realpathFilter = 1;
	sr_cfg->recursive = 1;
	sr_cfg->sanity_log_dead = 0.0;
	sr_cfg->shim_defer_posting_to_exit = 0;
	sr_cfg->shim_post_minterval = 5.0;
	sr_cfg->shim_skip_parent_open_files = 1;
	sr_cfg->sleep = 0.0;
	sr_cfg->heartbeat = 300.0;
	sr_cfg->help = 0;
	sr_cfg->source = NULL;
	sr_cfg->statehost = 0;
	sr_cfg->strip = 0;
	sr_cfg->sumalgo = 's';
	sr_cfg->sumalgoz = 's';
	sr_cfg->to = NULL;
	sr_cfg->user_headers = NULL;
	strcpy(sr_cfg->topicPrefix, "v02.post");
	strcpy(sr_cfg->post_topicPrefix, "v02.post");
	sr_cfg->topics = NULL;
	sr_cfg->post_baseUrl = NULL;

	sr_cfg->v2compatRenameDoublePost = 0;
	sr_cfg->vip = NULL;
	sr_cfg->xattr_cc = 0;

	sprintf(p, "%s/.config", getenv("HOME"));
	if (access(p, R_OK) == -1) {
		mkdir(p, 0700);
	}
	sprintf(p, "%s/.config/%s", getenv("HOME"), sr_cfg->appname );
	if (access(p, R_OK) == -1 ) {
		mkdir(p, 0700);
	}

	if (!strcmp(progname, "shim")) {
		sprintf(p, "%s/.config/%s/%s", getenv("HOME"), sr_cfg->appname, "post");
	} else {
		sprintf(p, "%s/.config/%s/%s", getenv("HOME"), sr_cfg->appname, progname);
	}
	if (access(p, R_OK) == -1) {
		mkdir(p, 0700);
	}
	sprintf(p, "%s/.config/%s/default.conf", getenv("HOME"), sr_cfg->appname );
	sr_config_read(sr_cfg, p, 0, 0);

}

int sr_config_read(struct sr_config_s *sr_cfg, char *filename, int abort, int master)
/* 
  search for the given configuration 
  return 1 if it was found and read int, 0 otherwise.

  if abort is set, then if a problem is found panic and exit.
 
  if master is set, then try to set configuration name.

 */
{
	static int config_depth = 0;
	FILE *f;
	char *option;
	char *argument, *argument2;
	char *c, *d;
	char sufbuf[10];
	int plen;
	char p[PATH_MAX];
	int ret;

	/* set config name */
	if (master && !config_depth) {
		strcpy(p, filename);
		c = strrchr(p, '/');
		if (c)
			c++;
		else
			c = p;

		d = strrchr(c, '.');
		if (d)
			*d = '\0';
		sr_cfg->configname = strdup(c);
		config_depth++;
	}
	/* append .conf if not already there.
	 * FIXME MG  or not ending with .inc
	 *           would be better to know that we are in "include" mode...
	 *           and accept any filename under the config dir !!!
	 */
	plen = strlen(filename);
        strcpy(sufbuf,"");
	if (strcmp(&(filename[plen - 5]), ".conf")) {
		if (strcmp(&(filename[plen - 4]), ".inc")) {
			strcpy(sufbuf, ".conf");
		} 
	}

	/* linux config location */
	if (*filename != '/') {
		sprintf(p, "%s/.config/%s/%s/%s%s", getenv("HOME"), sr_cfg->appname, 
			strcmp(sr_cfg->progname, "shim") ? sr_cfg->progname : "cpost", filename, sufbuf);
		if (access(p, F_OK)) {
		    sprintf(p, "%s/.config/%s/%s/%s%s", getenv("HOME"), sr_cfg->appname, 
			strcmp(sr_cfg->progname, "shim") ? sr_cfg->progname : "post", filename, sufbuf);
                }
	} else {
		strcpy(p, filename);
	}
	// absolute paths in the normal places...

	f = fopen(p, "r");
	if (f == NULL)		// drop the suffix
	{
		sr_log_msg(LOG_DEBUG, "sr_config_read 1 failed to open: %s\n", p);
		plen = strlen(p);
		p[plen - 5] = '\0';
		plen -= 5;
		f = fopen(p, "r");
	}
	if (f == NULL) {
		sr_log_msg(LOG_DEBUG, "sr_config_read 2 failed to open: %s\n", p);

		if (*filename != '/') {	/* relative path, with or without suffix */
			strcpy(p, filename);
			sr_log_msg(LOG_DEBUG, "sr_config_read trying to open: %s\n", p);
			f = fopen(p, "r");
		}
		if (f == NULL) {
			sr_log_msg(LOG_DEBUG, "sr_config_read 3 failed to open: %s\n", p);
			if (strcmp(&(p[plen - 5]), ".conf")) {
				strcat(p, ".conf");
				sr_log_msg(LOG_DEBUG, "sr_config_read trying to open: %s\n", p);
				f = fopen(p, "r");
			}
		}
	}

	if (f == NULL) {
		if (abort) {
			sr_log_msg(LOG_CRITICAL,
				"error: failed to find configuration: %s\n", filename);
			exit(0);
		}
		return (1);
	}

	while (fgets(token_line, TOKMAX, f) != NULL) {
		//printf( "line: %s", token_line );

		ret = strspn(token_line, " \t\n");
		if ((ret == strlen(token_line)) || (token_line[ret] == '#')) {
			continue;	// blank or comment line.
		}
		option = strtok(token_line, " \t\n");
		argument = strtok(NULL, " \t\n");
		argument2 = strtok(NULL, " \t\n");

		ret = sr_config_parse_option(sr_cfg, option, argument, argument2, master);
		if (ret < 0)
			return (0);

	};
	fclose(f);

	return (1);
}

int sr_config_finalize(struct sr_config_s *sr_cfg, const int is_consumer)
/*
 Do all processing that can only happen once the entire set of settings has been read.
 Infer defaults, etc...

 return 0 if the configuration is not valid.

 */
{
	char *d;
	char *val;
	char p[PATH_MAX];
	char q[AMQP_MAX_SS];
	FILE *f;
	int ret;
	struct stat sb;
	struct timespec tseed;

	if (!sr_cfg->configname)
		sr_cfg->configname = strdup("NONE");

	if (!sr_cfg->progname)
		sr_cfg->progname = strdup("NONE");

	// seeding random generator from clock nano sec
	// sr_context_init_config is ran later and so
	// the random generator is not ready when generating a queue name
	// therefore, we have to seed/initialize random process Here

	clock_gettime(CLOCK_REALTIME, &tseed);
	srandom(tseed.tv_nsec);

	// subdir for statehost

	d = NULL;
	val = NULL;
	if (sr_cfg->statehost) {
		val = sr_local_fqdn();
		d = strchr(val, '.');
		if (d) *d = '\0';
	}
	if (val)
		sr_cfg->statehostval = strdup(val);

	// if the state directory is missing, build it.
	if (val) {
		sprintf(p, "%s/.cache/%s/%s/%s/%s", getenv("HOME"), sr_cfg->appname, val,
			sr_cfg->progname, sr_cfg->configname);
	} else {
		sprintf(p, "%s/.cache/%s/%s/%s", getenv("HOME"), sr_cfg->appname,
			sr_cfg->progname, sr_cfg->configname);
	}
	ret = stat(p, &sb);
	if (ret) {
		sprintf(p, "%s/.cache", getenv("HOME"));
		mkdir(p, 0700);
		strcat(p, "/");
		strcat(p, sr_cfg->appname);
		mkdir(p, 0700);
		if (val) {
			strcat(p, "/");
			strcat(p, val);
			mkdir(p, 0700);
		}
		strcat(p, "/");
		strcat(p, sr_cfg->progname);
		mkdir(p, 0700);
		strcat(p, "/");
		strcat(p, sr_cfg->configname);
		mkdir(p, 0700);
	}
	// if the log directory is missing, build it.
	if (val) {
		sprintf(p, "%s/.cache/%s/%s/log", getenv("HOME"), sr_cfg->appname, val);
	} else {
		sprintf(p, "%s/.cache/%s/log", getenv("HOME"), sr_cfg->appname );
	}
	ret = stat(p, &sb);
	if (ret) {
		sprintf(p, "%s/.cache/%s", getenv("HOME"), sr_cfg->appname );
		if (val) {
			strcat(p, "/");
			strcat(p, val);
			mkdir(p, 0700);
		}
		strcat(p, "/log");
		mkdir(p, 0700);
	}
	// logfn
	if (val) {
		sprintf(p, "%s/.cache/%s/%s/log/%s_%s_%02d.log",
			getenv("HOME"), sr_cfg->appname, val, sr_cfg->progname,
			sr_cfg->configname, sr_cfg->instance);
	} else {
		sprintf(p, "%s/.cache/%s/log/%s_%s_%02d.log",
			getenv("HOME"), sr_cfg->appname, sr_cfg->progname, sr_cfg->configname, sr_cfg->instance);
	}

	sr_cfg->logfn = strdup(p);

	if (strcmp(sr_cfg->action, "foreground"))
		sr_cfg->log = 1;

	if (sr_cfg->log) {
		sr_log_setup(sr_cfg->logfn, sr_cfg->chmod_log,
			  sr_cfg->debug ? LOG_DEBUG : (sr_cfg->loglevel),
			  sr_cfg->logrotate, sr_cfg->logrotate_interval);
	}
	// pidfn statehost
	if (val) {
		sprintf(p, "%s/.cache/%s/%s/%s/%s/i%03d.pid", getenv("HOME"), sr_cfg->appname, 
			val, sr_cfg->progname, sr_cfg->configname, sr_cfg->instance);
	}
	// pidfn default
	else {
		sprintf(p, "%s/.cache/%s/%s/%s/i%03d.pid", getenv("HOME"), sr_cfg->appname, 
			sr_cfg->progname, sr_cfg->configname, sr_cfg->instance);
	}

	sr_cfg->pidfile = strdup(p);
	f = fopen(p, "r");
	if (f)			// read the pid from the file.
	{
		fgets(p, PATH_MAX, f);
		sr_cfg->pid = atoi(p);
		fclose(f);
	}
	// cachefn statehost
	if (val) {
		sprintf(p, "%s/.cache/%s/%s/%s/%s/recent_files_%03d.cache",
			getenv("HOME"), sr_cfg->appname, val, sr_cfg->progname,
			sr_cfg->configname, sr_cfg->instance);
	}
	// cachefn default
	else {
		// FIXME: open and read cache file if present. seek to end.
		sprintf(p, "%s/.cache/%s/%s/%s/recent_files_%03d.cache",
			getenv("HOME"), sr_cfg->appname, sr_cfg->progname, sr_cfg->configname, sr_cfg->instance);
	}

	if (sr_cfg->sanity_log_dead == 0.0)
		sr_cfg->sanity_log_dead = (float)(1.5 * sr_cfg->heartbeat);
	if (sr_cfg->sanity_log_dead < 450)
		sr_cfg->sanity_log_dead = 450.0;

	if (sr_cfg->cache > 0) {
		sr_cfg->cachep = sr_cache_open(p);
	} else {
		if (!access(p, F_OK))
			unlink(p);
	}

	// Since we check how old the log is, we ust not write to the log during startup in sanity mode.
	if (strcmp(sr_cfg->action, "sanity")) {
		sr_log_msg(LOG_DEBUG,
			"sr_%s %s settings: action=%s hostname=%s config_name=%s log_level=%d follow_symlinks=%s realpathPost=%s\n",
			sr_cfg->progname, __sarra_version__, sr_cfg->action, sr_local_fqdn(), 
			sr_cfg->configname, sr_cfg->loglevel,
			sr_cfg->follow_symlinks ? "yes" : "no", sr_cfg->realpathPost ? "yes" : "no");
		sr_log_msg(LOG_DEBUG,
			"\tsleep=%g expire=%g heartbeat=%g sanity_log_dead=%g cache=%g statehost=%s v2compatRenameDoublePost=%s\n",
			sr_cfg->sleep, sr_cfg->expire, sr_cfg->heartbeat, sr_cfg->sanity_log_dead, sr_cfg->cache, 
                        sr_cfg->statehost ? "yes" : "no", sr_cfg->v2compatRenameDoublePost ? "yes": "no" );
		sr_log_msg(LOG_DEBUG, "\tcache_file=%s accept_unmatch=%s post_rate_limit=%d\n",
			sr_cfg->cachep ? p : "off", sr_cfg->accept_unmatched ? "on" : "off", sr_cfg->post_rate_limit );
		sr_log_msg(LOG_DEBUG,
			"\tevents=%04x directory=%s queuename=%s force_polling=%s sum=%c statehost=%c\n",
			sr_cfg->events, sr_cfg->directory, sr_cfg->queuename,
			sr_cfg->force_polling ? "on" : "off", sr_cfg->sumalgo, sr_cfg->statehost);
		sr_log_msg(LOG_DEBUG,
			"\tmessage_ttl=%g post_exchange=%s post_exchange_split=%d post_exchangeSuffix=%s\n",
			sr_cfg->message_ttl, sr_cfg->post_exchange,
			sr_cfg->post_exchange_split, sr_cfg->post_exchangeSuffix);
		sr_log_msg(LOG_DEBUG,
			"\tsource=%s to=%s post_baseUrl=%s topicPrefix=%s post_topicPrefix=%s, pid=%d\n",
			sr_cfg->source, sr_cfg->to, sr_cfg->post_baseUrl,
			sr_cfg->topicPrefix, sr_cfg->post_topicPrefix, sr_cfg->pid);
		sr_log_msg(LOG_DEBUG, "man sr_post(1) for more information\n");
	}
	// FIXME: Missing: topics, user_headers, 
	if (!strcmp(sr_cfg->progname, "post")
	    || !strcmp(sr_cfg->progname, "cpost")
	    || !strcmp(sr_cfg->progname, "shim")) {
		if (!(sr_cfg->post_broker) && (sr_cfg->broker)) {
			sr_log_msg(LOG_WARNING, "please replace broker with post_broker\n");
			sr_cfg->post_broker = sr_cfg->broker;
			sr_cfg->broker = NULL;
		}

		if (!(sr_cfg->post_broker)) {
			sr_log_msg(LOG_ERROR, "no post_broker given\n");
			return (0);
		}
	}

	if (sr_cfg->post_broker) {
		free(sr_cfg->outlet);
		sr_cfg->outlet = strdup("post");

		if (!(sr_cfg->post_exchange)) {
			if (sr_cfg->exchange) {
				sr_cfg->post_broker->exchange = strdup(sr_cfg->exchange);
			} else {
				if (sr_cfg->post_exchangeSuffix)
					sprintf(q, "xs_%s_%s",
						sr_cfg->post_broker->user,
						sr_cfg->post_exchangeSuffix);
				else
					sprintf(q, "xs_%s", sr_cfg->post_broker->user);
				sr_cfg->post_broker->exchange = strdup(q);
			}
		} else {
			sr_cfg->post_broker->exchange = strdup(sr_cfg->post_exchange);
		}
		sr_cfg->post_broker->exchange_split = sr_cfg->post_exchange_split;

		if (sr_cfg->source == NULL) {
			sr_cfg->source = strdup(sr_cfg->post_broker->user);
		}

		if (sr_cfg->to == NULL) {
			sr_cfg->to = strdup(sr_cfg->post_broker->hostname);
		}
	}

	if (!is_consumer)
		return (1);
	else if (!(sr_cfg->broker)) {
		sr_log_msg(LOG_ERROR, "no broker given\n");
		return (0);
	}

	if (sr_cfg->exchange) {
		sr_cfg->broker->exchange = strdup(sr_cfg->exchange);
	} else {
		if (sr_cfg->exchangeSuffix) {
			sprintf(q, "xs_%s_%s", sr_cfg->broker->user, sr_cfg->exchangeSuffix);
			sr_cfg->broker->exchange = strdup(q);
		} else
			sr_cfg->broker->exchange = strdup("xpublic");
	}

	// Assess sr_cfg->queuename validity: if a queue was already created, use it!
	if (!sr_cfg->queuename
	    && !(sr_cfg->progname && sr_cfg->configname && sr_cfg->broker
		 && sr_cfg->broker->user)) {
		sr_log_msg(LOG_ERROR, "incomplete configuration, cannot guess queue\n");
		return (0);
	}
	sprintf(p, "%s/.cache/%s/%s/%s/%s.%s.%s.qname", getenv("HOME"), sr_cfg->appname,
		sr_cfg->progname, sr_cfg->configname, sr_cfg->progname,
		sr_cfg->configname, sr_cfg->broker->user);
	f = fopen(p, "r");
	if (f)			// read the queue name from the file.
	{
		fgets(q, AMQP_MAX_SS, f);
		sr_cfg->queuename = strdup(q);
		fclose(f);
	} else {
		// If unset in config, set queuename now
		if (!sr_cfg->queuename) {
			sprintf(q, "q_%s_%s.%s.%ld.%ld",
				sr_cfg->broker->user, sr_cfg->progname,
				sr_cfg->configname, random(), random());
			sr_cfg->queuename = strdup(q);
		}
		f = fopen(p, "w");	// save the queue name for next time.
		if (f) {
			sr_log_msg(LOG_DEBUG, "writing %s to %s\n", sr_cfg->queuename, p);
			fputs(sr_cfg->queuename, f);
			fclose(f);
		}
	}
	if (!strcmp(sr_cfg->action, "cleanup")) {
		unlink(p);
	}

	return (1);
}

static struct sr_config_s *thecfg = NULL;

static void stop_handler(int sig)
{
	sr_log_msg(LOG_DEBUG, "shutting down: signal %d received\n", sig);

	if (thecfg && thecfg->cachep) {
		sr_cache_close(thecfg->cachep);
		thecfg->cachep = NULL;
	}
	sr_config_free(thecfg);

	// propagate handler for further processing, likely trigger exit.
	signal(sig, SIG_DFL);
	raise(sig);
}

int sr_config_deactivate(struct sr_config_s *sr_cfg)
{
  int ret=0;
  
  if (sr_cfg && sr_cfg->pidfile) 
      ret = unlink(sr_cfg->pidfile);
  return(ret); 
}

int sr_config_activate(struct sr_config_s *sr_cfg)
/* 
   now a really running instance.

   return 0 on success, < 0 on error.
     
   SIDE EFFECT: sets a signal handler for SIGTERM (to clanly close cache on exit.)

 */
{
	FILE *f;

	sr_cfg->pid = getpid();
	f = fopen(sr_cfg->pidfile, "w");
	if (f)			// read the pid from the file.
	{
		fprintf(f, "%d\n", sr_cfg->pid);
		fclose(f);
	} else
		return (-1);

	if (sr_cfg->cache > 0) {
		thecfg = sr_cfg;
		if (signal(SIGTERM, stop_handler) == SIG_ERR)
			sr_log_msg(LOG_ERROR, "unable to set SIGTERM handler\n");
		else
			sr_log_msg(LOG_DEBUG, "set SIGINT handler to cleanup cache on exit.\n");
		if (signal(SIGINT, stop_handler) == SIG_ERR)
			sr_log_msg(LOG_ERROR, "unable to set SIGINT handler\n");
		else
			sr_log_msg(LOG_DEBUG, "set SIGINT handler to cleanup cache on exit.\n");
	}
	return (0);
}

int sr_config_startstop(struct sr_config_s *sr_cfg)
/*
   process common actions: start|stop|status 

   killing existing instance, etc...

   return code:

   0 - operation is complete, should exit.
  <0 - operation errored, should exit. 
  >0 - operation succeeded, should continue.

   the action == 'status' then 
      return config_is_running?0:-1

 */
{
	struct timespec tsleep;
	int ret;
	struct stat sb;

	// "default" cannot run.
	if (!strcmp(sr_cfg->configname, "default"))
		return (0);

	// Check if already running. (conflict in use of state files.)
	if (sr_cfg->pid > 0)	// there should be one running already.
	{
		ret = kill(sr_cfg->pid, 0);
		if (!ret) {	// is running.
			if (!strcmp(sr_cfg->action, "status")) {
				fprintf(stderr,
					"configuration %s is running with pid %d. log: %s\n",
					sr_cfg->configname, sr_cfg->pid, sr_cfg->logfn);
				return (0);
			}
			if (!strcmp(sr_cfg->action, "sanity")) {
				if (stat(sr_cfg->logfn, &sb)) {
					fprintf(stderr,
						"sanity check: cannot stat log file %s. Something is wrong.\n",
						sr_cfg->logfn);
				} else {
					clock_gettime(CLOCK_REALTIME, &tsleep);
					if ((tsleep.tv_sec - sb.st_mtime) <=
					    sr_cfg->sanity_log_dead) {
						fprintf(stderr,
							"sanity check: configuration %s is running with pid %d. log: %s is %ld seconds old\n",
							sr_cfg->configname,
							sr_cfg->pid,
							sr_cfg->logfn,
							(tsleep.tv_sec - sb.st_mtime));
						return (0);
					}
					fprintf(stderr,
						"sanity check: log file %s untouched in %ld seconds (too long.)\n",
						sr_cfg->logfn, (tsleep.tv_sec - sb.st_mtime));
				}
			}
			if (!strcmp(sr_cfg->action, "cleanup")
			    || !strcmp(sr_cfg->action, "remove")) {
				fprintf(stderr,
					"configuration %s is running with pid %d. log: %s\n",
					sr_cfg->configname, sr_cfg->pid, sr_cfg->logfn);
				fprintf(stderr, "cannot perform %s\n", sr_cfg->action);
				return (-1);
			}
			// pid is running and have permission to signal, this is a problem for start & foreground.
			if (!strcmp(sr_cfg->action, "start")
			    || (!strcmp(sr_cfg->action, "foreground"))) {
				sr_log_msg(LOG_ERROR,
					"configuration %s already running using pid %d.\n",
					sr_cfg->configname, sr_cfg->pid);
				return (-1);
			}
			// but otherwise it's normal, so kill the running one. 

			sr_log_msg(LOG_DEBUG, "killing running instance pid=%d\n", sr_cfg->pid);

			//  just kill it a little at first...
			kill(sr_cfg->pid, SIGTERM);

			// give it time to clean itself up.
			tsleep.tv_sec = 2L;
			tsleep.tv_nsec = 0L;
			nanosleep(&tsleep, NULL);

			ret = kill(sr_cfg->pid, 0);
			if (!ret) {	// pid still running, and have permission to signal, so it didn't die... 
				sr_log_msg(LOG_DEBUG,
					"After 2 seconds, instance pid=%d did not respond to SIGTERM, sending SIGKILL\n",
					sr_cfg->pid);
				kill(sr_cfg->pid, SIGKILL);
				nanosleep(&tsleep, NULL);
				ret = kill(sr_cfg->pid, 0);
				if (!ret) {
					sr_log_msg(LOG_CRITICAL,
						"SIGKILL on pid=%d didn't work either. System not usable, Giving up!\n",
						sr_cfg->pid);
					return (-1);
				}
			} else {
				sr_log_msg(LOG_INFO, "old instance stopped (pid: %d)\n", sr_cfg->pid);
			}
		} else		// not permitted to send signals, either access, or it ain't there.
		{
			if (errno != ESRCH) {
				sr_log_msg(LOG_INFO,
					"running instance (pid %d) found, but is not stoppable.\n",
					sr_cfg->pid);
				return (-1);

			} else {	// just not running.

				sr_log_msg(LOG_DEBUG,
					"instance for config %s (pid %d) is not running.\n",
					sr_cfg->configname, sr_cfg->pid);

				if (!strcmp(sr_cfg->action, "stop")) {
					fprintf(stderr,
						"already stopped config %s (pid %d): deleting pidfile.\n",
						sr_cfg->configname, sr_cfg->pid);
					unlink(sr_cfg->pidfile);
					return (-1);
				}
			}
		}
		if (!strcmp(sr_cfg->action, "stop")) {
			unlink(sr_cfg->pidfile);
			sr_log_msg(LOG_INFO, "stopped.\n");
			fprintf(stderr,
				"running instance for config %s (pid %d) stopped.\n",
				sr_cfg->configname, sr_cfg->pid);
			return (0);
		}
		if (!strcmp(sr_cfg->action, "restart"))
			return (1);
	} else {
		/* At this point, config is not running which is good for actions cleanup/remove... */
		if (!strcmp(sr_cfg->action, "cleanup")
		    || !strcmp(sr_cfg->action, "remove"))
			return (1);

		/* for other actions inform not running */
		fprintf(stderr, "config %s is stopped.\n", sr_cfg->configname);

		/*  MG FIXME if we are not running... if action is stop return 0 */
		if ((!strcmp(sr_cfg->action, "stop")
		     || !strcmp(sr_cfg->action, "sanity")))
			return (0);
	}

	/*  MG FIXME whatever was the state... if action is status return 0 */
	if (!strcmp(sr_cfg->action, "status"))
		return (0);

	return (1);		// Success! ready to continue!

}

static void cp(const char *s, const char *d)
{
	FILE *sfd = NULL;
	FILE *dfd = NULL;
	char buf[1024];

	sr_log_msg(LOG_DEBUG, "copying %s to %s.\n", s, d);
	if (!(sfd = fopen(s, "r"))) {
		sr_log_msg(LOG_ERROR, "opening config to read %s failed.\n", s);
		return;
	}

	if (!(dfd = fopen(d, "w+"))) {
		sr_log_msg(LOG_ERROR, "opening config to write %s failed.\n", d);
		return;
	}

	while (NULL != fgets(buf, 1024, sfd)) {
		fputs(buf, dfd);
	}
	fclose(sfd);
	fclose(dfd);

}

char *sr_config_find_one(struct sr_config_s *sr_cfg, const char *original_one)
{
	static char oldp[512];
	char one[256];
	int len_one;

	//fprintf( stderr, " find_one, original_one: %s\n", original_one );
	if (original_one) {

		strcpy(one, original_one);
		len_one = strlen(original_one) - 5;
		if (!strcmp(&(one[len_one]), ".conf"))
			one[len_one] = '\0';
		else {
			len_one++;
			if (!strcmp(&(one[len_one]), ".inc"))
				one[len_one] = '\0';
		}
		//fprintf( stderr, " find_one, one: %s\n", one );
		if (!strcmp(one, "default")) {
			sprintf(oldp, "%s/.config/%s/default.conf", getenv("HOME"), sr_cfg->appname );
			return (oldp);
		}
		if (!strcmp(one, "admin")) {
			sprintf(oldp, "%s/.config/%s/admin.conf", getenv("HOME"), sr_cfg->appname );
			return (oldp);
		}
		if (!strcmp(one, "credentials")) {
			sprintf(oldp, "%s/.config/%s/credentials.conf", getenv("HOME"), sr_cfg->appname );
			return (oldp);
		}

		sprintf(oldp, "%s/.config/%s/%s/%s.inc", getenv("HOME"), sr_cfg->appname, sr_cfg->progname, one);
		if (!access(oldp, R_OK))
			return (oldp);
		else {
			//fprintf(stderr, "not %s\n", oldp );

			sprintf(oldp, "%s/.config/%s/%s/%s.conf",
				getenv("HOME"), sr_cfg->appname, sr_cfg->progname, one);

			if (!access(oldp, R_OK))
				return (oldp);
			else {
				//fprintf(stderr, "not %s\n", oldp );
				sprintf(oldp, "%s/.config/%s/%s/%s",
					getenv("HOME"), sr_cfg->appname, sr_cfg->progname, one);
				if (!access(oldp, R_OK))
					return (oldp);
				else {
					//fprintf(stderr, "not %s\n", oldp );
					sprintf(oldp,
						"%s/.config/%s/%s/%s.conf.off",
						getenv("HOME"), sr_cfg->appname, sr_cfg->progname, one);
					if (!access(oldp, R_OK))
						return (oldp);
					else {
						sr_log_msg(LOG_ERROR, "config %s not found.\n", one);
						//fprintf(stderr, "not %s\n", oldp );
					}
				}
			}

		}
	}
	return (NULL);
}

int sr_config_add_one(struct sr_config_s *sr_cfg, const char *original_one)
{
	char oldp[512];
	char newp[256];
	char one[256];
	int len_one;

	if (original_one) {

		if (!access(original_one, R_OK)) {
			sprintf(newp, "%s/.config/%s/%s/%s", getenv("HOME"), sr_cfg->appname,
				sr_cfg->progname, original_one);
			cp(original_one, newp);
			return (0);
		}
		if (!getenv("SR_CONFIG_EXAMPLES")) {
			sr_log_msg(LOG_ERROR,
				"Cannot add configurations because SR_CONFIG_EXAMPLES is not set.\n");
			return (1);
		}

		sprintf(oldp, "%s", getenv("SR_CONFIG_EXAMPLES"));
		if (access(oldp, F_OK | R_OK)) {
			sr_log_msg(LOG_ERROR,
				"Cannot access SR_CONFIG_EXAMPLES directory %s.\n", oldp);
			return (1);
		}

		sprintf(oldp, "%s/%s/%s", getenv("SR_CONFIG_EXAMPLES"),
			sr_cfg->progname, original_one);
		if (!access(oldp, R_OK)) {
			sprintf(newp, "%s/.config/%s/%s/%s", getenv("HOME"), sr_cfg->appname,
				sr_cfg->progname, original_one);
			cp(oldp, newp);
			return (0);
		}

		strcpy(one, original_one);
		len_one = strlen(original_one);
		if (strcmp(&(one[len_one - 5]), ".conf")) {
			strcat(one, ".conf");
			if (!sr_config_add_one(sr_cfg, one))
				return (0);
			one[len_one - 1] = '\0';
		} else {
			return (1);
		}

		if (strcmp(&(one[len_one - 4]), ".inc")) {
			strcat(one, ".inc");
			if (!sr_config_add_one(sr_cfg, one))
				return (0);
			one[len_one - 1] = '\0';
		} else {
			return (1);
		}

		if (strcmp(&(one[len_one - 5]), ".off")) {
			strcat(one, ".off");
			if (!sr_config_add_one(sr_cfg, one))
				return (0);
			one[len_one - 1] = '\0';
		} else {
			return (1);
		}
/*
          strcmp( &(one[strlen(one)-4]), ".inc" ) && 
          strcmp( &(one[strlen(one)-4]), ".off" ) )
     {
          
     } else
     {
         len_one++; 
         if ( !strcmp(&(one[len_one]), ".inc") ) one[len_one]='\0';
         if ( !strcmp(&(one[len_one]), ".off") ) one[len_one]='\0';
     }
     // assert: one now contains the name, without suffix.

     sprintf( oldp, "%s.inc", one ) ;
     sprintf( newp, "%s/.config/%s/%s/%s.inc", getenv("HOME"), sr_cfg->appname, sr_cfg->progname, one ) ;

     if ( !access( oldp, R_OK ) ) cp( oldp, newp );
     else 
     {
        sprintf( oldp, "%s.conf", one ) ;
        sprintf( newp, "%s/.config/%s/%s/%s.conf", getenv("HOME"), sr_cfg->appname,
            sr_cfg->progname, one ) ;

        if ( !access( oldp, R_OK ) ) cp( oldp, newp );
        else
        {
            sprintf( oldp, "%s", one ) ;
            if ( !access( oldp, R_OK ) ) cp( oldp, newp );
            else sr_log_msg(LOG_ERROR, "config %s not found.\n", one  );
        }

     }
  */
	}
	return (1);
}

void sr_config_add(struct sr_config_s *sr_cfg)
{
	if (sr_cfg->configname)
		sr_config_add_one(sr_cfg, sr_cfg->configname);
	for (struct sr_path_s * path = sr_cfg->paths; path; path = path->next)
		sr_config_add_one(sr_cfg, path->path);
}

void sr_config_edit(struct sr_config_s *sr_cfg)
{
	char *one;
	char *editor;

	one = sr_config_find_one(sr_cfg, sr_cfg->paths->path);

	editor = getenv("EDITOR");
	if (!editor)
		editor = "/usr/bin/vi";

	execlp(editor, editor, one, NULL);
}

void sr_config_log(struct sr_config_s *sr_cfg)
{
	char p[256];

	if (sr_cfg->statehost == '0') {
		sprintf(p, "%s/.cache/%s/log/%s_%s_%04d.log",
			getenv("HOME"), sr_cfg->appname, sr_cfg->progname, sr_cfg->configname, sr_cfg->instance);
	} else {
		sprintf(p, "%s/.cache/%s/%s/log/%s_%s_%04d.log",
			getenv("HOME"), sr_cfg->appname, sr_cfg->statehostval, sr_cfg->progname,
			sr_cfg->configname, sr_cfg->instance);
	}

	execlp("/usr/bin/tail", "tail", "-f", p, NULL);
}

void sr_config_remove(struct sr_config_s *sr_cfg)
{
	char *one;

	if (sr_cfg->configname) {
		one = sr_config_find_one(sr_cfg, sr_cfg->configname);
		if (one)
			unlink(one);
	}
	for (struct sr_path_s * path = sr_cfg->paths; path; path = path->next) {
		one = sr_config_find_one(sr_cfg, path->path);
		if (one)
			unlink(one);
	}
}

void sr_config_disable(struct sr_config_s *sr_cfg)
{
	char *one;
	char newp[256];

	one = sr_config_find_one(sr_cfg, sr_cfg->configname);
	if (one) {
		if (!strcmp(&(one[strlen(one) - 4]), ".off")) {
			sr_log_msg(LOG_WARNING, "config %s already disabled.\n", one);
		} else {
			sprintf(newp, "%s.off", one);
			rename(one, newp);
		}
	}
	for (struct sr_path_s * path = sr_cfg->paths; path; path = path->next) {
		one = sr_config_find_one(sr_cfg, path->path);
		if (one) {
			if (!strcmp(&(one[strlen(one) - 4]), ".off")) {
				sr_log_msg(LOG_WARNING, "config %s already disabled.\n", one);
			} else {
				sprintf(newp, "%s.off", one);
				rename(one, newp);
			}
		}
	}
}

void sr_config_enable(struct sr_config_s *sr_cfg)
{
	char *one;
	char newp[256];

	one = sr_config_find_one(sr_cfg, sr_cfg->configname);
	fprintf(stderr, "enable, one=%s\n", one);
	if (one) {
		strcpy(newp, one);
		if (!strcmp(&(newp[strlen(newp) - 4]), ".off")) {
			newp[strlen(newp) - 4] = '\0';
			rename(one, newp);
		}
	}
	for (struct sr_path_s * path = sr_cfg->paths; path; path = path->next) {
		one = sr_config_find_one(sr_cfg, path->path);
		fprintf(stderr, "disable, one=%s\n", one);
		if (one) {
			strcpy(newp, one);
			if (!strcmp(&(newp[strlen(newp) - 4]), ".off")) {
				newp[strlen(newp) - 4] = '\0';
				rename(one, newp);
			}
		}
	}
}

void sr_config_list(struct sr_config_s *sr_cfg)
{
	char p[1024];
	DIR *cld;
	FILE *f;
	struct dirent *d;
	char *s;
	int l;
	int enabled;
	int pidstat;
	pid_t pid;

	if (getenv("SR_CONFIG_EXAMPLES")) {
		sprintf(p, "%s/%s", getenv("SR_CONFIG_EXAMPLES"), sr_cfg->progname);

		fprintf(stdout, "sr_%s %s ", sr_cfg->progname, __sarra_version__);
		fprintf(stdout, "Example configurations ( %s )\n\n", p);
		cld = opendir(p);
		if (!cld)
			return;
		l = 1;
		while ((d = readdir(cld))) {
			if (d->d_name[0] == '.')
				continue;
			l = strlen(d->d_name);
			if (d->d_name[l - 1] == '~')
				continue;
			fprintf(stdout, "%20s ", d->d_name);
			if (l % 4 == 0) {
				fprintf(stdout, "\n");
				l = 1;
			} else
				l++;
		}
		if (l % 4 != 1)
			fprintf(stdout, "\n");
	} else {
		fprintf(stdout, "SR_CONFIG_EXAMPLES, not set, no samples available\n");
	}
	sprintf(p, "%s/.config/%s/%s", getenv("HOME"), sr_cfg->appname, sr_cfg->progname);

	fprintf(stdout, "\nConfigurations for sr_%s ( %s ):\n", sr_cfg->progname, p);
	cld = opendir(p);

	if (!cld)
		return;

	while ((d = readdir(cld))) {
		if (d->d_name[0] == '.')
			continue;

		l = strlen(d->d_name);
		if (d->d_name[l - 1] == '~')
			continue;
		l -= 5;
		if (l > 0) {
			s = &(d->d_name[l]);
			if (strcmp(s, ".conf")) {
				s++;
				if (!strcmp(s, ".inc")) {
					enabled = 0;
					s += 4;
					fprintf(stdout, "\t%-20s (include)\n", d->d_name);
					continue;
				} else {
					if (strcmp(s, ".off"))
						continue;
					enabled = 0;
					s -= 5;
				}
			} else {
				enabled = 1;
			}
			*s = '\0';
		}

		sprintf(p, "%s/.cache/%s/%s/%s/i001.pid", getenv("HOME"),
			sr_cfg->appname, sr_cfg->progname, d->d_name);
		f = fopen(p, "r");
		if (f)		// read the pid from the file.
		{
			fgets(p, 1024, f);
			pid = atoi(p);
			fclose(f);
			pidstat = kill(pid, 0);
		} else {
			pidstat = 99;
		}

		fprintf(stdout, "\t%-20s (%s,%s)\n", d->d_name,
			pidstat ? "stopped" : "running", enabled ? "enabled" : "disabled");
	}
	closedir(cld);
	fprintf(stdout, "\n");
}
