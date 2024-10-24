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

  spits out ´unimplemented option´ where appropriate...
 */
#include <linux/limits.h>
#include <errno.h>

#define EBUFLEN (127)
static char *es;
static char error_buf[EBUFLEN + 1];

#include <sys/types.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <string.h>

/*
   https://troydhanson.github.io/uthash/userguide.html

 */

#include "uthash.h"

#include "sr_version.h"

#define IDLE_MESSAGE_INTERVAL (60)

/* 
  for each directory opened, store it's dev+inode pair.
  if you encounter another directory witht the same numbers, there is a loop.
  The FD is the file descriptor returned by an inotify_init.

 */

struct hash_entry {
	char *fn;		// key & payload
	UT_hash_handle hh;
};

#include "sr_post.h"

static int inotify_event_mask;	// translation of sr_events to inotify events.

struct dir_stack {
	char *path;		// path of directory.
	int wd;			// fd returned by inotify_init.
	dev_t dev;		// info from stat buf of directory.
	ino_t ino;
	int visited;
	struct dir_stack *next;	// pointer towards the top of the stack.
};

/* FIXME: crappy algorithm single linked stack, no optimizations at all.
   FIXME: once a directory is added, deletion is not handled 
          (case: directory exists, while code runs, directory is deleted, then
           the inode is re-used for a file or another directory. if it turns
           out to be a directory, then it will be in the stack, but not watched.

   would be straightforward to:
       - use an uthash for the stack, rather than a stack a hash list on id.
       - have each dir_stak entry have a hash_entry for the files modified within that directory,
         rather than one big one in check4events.  would bring the size of  'n' way down for various algos.
         also use relative paths, that way, rather than absolute ones used in current hash.

 */

static struct dir_stack *dir_stack_top = NULL;	/* insertion point (end of line.) */
static int dir_stack_size = 0;

/* 
   at the beginning of each poll, need to walk the tree again.
   so reset *visited* to 0 for entire stack.  These get set to true
   at the next iteration.
 */
void dir_stack_reset()
{
	for (struct dir_stack * s = dir_stack_top; s; s = s->next)
		s->visited = 0;

}

int dir_stack_push(struct sr_log_context_s *logctx, char *fn, int wd, dev_t dev, ino_t ino)
 /* add the given directory to the list of ones that are being scanned.

    Return value:  1 if this is a new directory and it has been added.
    0 if the directory is a duplicate, and was not added.
  */
{
	struct dir_stack *t, *i, *present;

	present = NULL;
	if (dir_stack_top) {
		i = dir_stack_top;
		while (!present && i) {
			if ((i->dev == dev) && (i->ino == ino))
				present = i;
			i = i->next;
		}
	}
	if (!present) {
		t = (struct dir_stack *)(malloc(sizeof(struct dir_stack)));
		if (!t) {
			es = strerror_r(errno, error_buf, EBUFLEN);
			sr_log_msg(logctx,LOG_ERROR,
				   "ERROR: failed to malloc adding to dir_stack for%s: %s\n", fn,
				   es);
			return (0);
		}

		dir_stack_size++;
		t->path = strdup(fn);
		t->wd = wd;
		t->dev = dev;
		t->ino = ino;
		t->visited = 1;
		t->next = dir_stack_top;
		dir_stack_top = t;
		return (1);
	} else {
		if (present->visited) {
			return (0);
		}
		present->visited++;
		return (1);
	}
}

/*
 * remove dir_stack entry with path corresponding to fn, if there is one
 * FIXME refactor dir_stack into generic sll
 */
void dir_stack_rm(char *fn)
{
	struct dir_stack *i = NULL;
	struct dir_stack *j = NULL;

	i = dir_stack_top;
	if (!i)
		return;

	if (!strcmp(i->path, fn)) {
		j = i;
		dir_stack_top = i->next;
		goto dir_stack_rm_exit;
	}

	while (i->next && strcmp(i->next->path, fn))
		i = i->next;
	if (i) {
		j = i->next;
		if (i->next)
			i->next = i->next->next;
	}

 dir_stack_rm_exit:
	if (j) {
		free(j->path);
		free(j);
	}
}

void dir_stack_free()
{
	struct dir_stack *s;

	while ((s = dir_stack_top)) {
		dir_stack_top = s->next;
		free(s->path);
		free(s);
	}
}

char evstr[80];

char *inotify_event_2string(uint32_t mask)
{
	if (mask & IN_CREATE)
		strcpy(evstr, "create");
	else if (mask & IN_MODIFY)
		strcpy(evstr, "modify");
	else if (mask & IN_MOVED_FROM)
		strcpy(evstr, "rename");
	else if (mask & IN_MOVED_TO)
		strcpy(evstr, "rename");
	else if (mask & IN_DELETE)
		strcpy(evstr, "delete");
	else if (mask & IN_IGNORED)
		strcpy(evstr, "ignored");
	else
		sprintf(evstr, "dunno: %04x!", mask);
	if (mask & IN_ISDIR)
		strcat(evstr, ",directory");
	return (evstr);
}

// see man 7 inotify for size of struct inotify_event
#define INOTIFY_EVENT_MAX  (sizeof(struct inotify_event) + NAME_MAX + 1)

static int inot_fd = 0;

static int first_call = 1;
//struct timespec latest_min_mtim;

int ts_newer(struct timespec a, struct timespec b)
   /*  return true is a is newer than b.
    */
{
	if (a.tv_sec > b.tv_sec)
		return (1);
	if (a.tv_sec < b.tv_sec)
		return (0);
	if (a.tv_nsec > b.tv_nsec)
		return (1);
	return (0);
}

void do1file(struct sr_context *sr_c, char *fn)
{
	char *s;
	DIR *dir;
	int w;
	struct dirent *e;
	struct stat sb;
	struct sr_mask_s *mask;
	char ep[PATH_MAXNUL];
	char fnreal[PATH_MAXNUL];
	char tmpname[PATH_MAXNUL];

	// attempted mollification of valgrind: nope!
	// memset(&sb,0,sizeof(struct stat));
	// try 2:
	//sb.st_mtim.tv_sec=0;
	//sb.st_mtim.tv_nsec=0;

	//if (sr_c->cfg->debug)
	//    sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "do1file starting on: %s\n", fn );
	/* apply the accept/reject clauses */

	// FIXME BUG: pattern to match is supposed to be complete URL, not just path...

	if (sr_c->cfg->realpathFilter) {

		if (lstat(fn, &sb) < 0) {
			strcpy(tmpname, fn);
			s = rindex(tmpname, '/');
			if (s) {
				*s = '\0';
				s++;
			}
			realpath(tmpname, fnreal);	// apply to directory, not final path entry.
			if (s) {
				strcat(fnreal, "/");
				strcat(fnreal, s);
			}
		} else {
			realpath(fn, fnreal);
		}
		mask = sr_isMatchingPattern(sr_c->cfg, fnreal);
	} else {
		mask = sr_isMatchingPattern(sr_c->cfg, fn);
	}

	if ((mask && !(mask->accepting))
	    || (!mask && !(sr_c->cfg->acceptUnmatched))) {
		if (sr_c->cfg->logReject)
			sr_log_msg(sr_c->cfg->logctx,LOG_INFO, "rejecting pattern: %s\n", fn);
		return;
	}

	if (lstat(fn, &sb) < 0) {
		sr_post(sr_c, fn, NULL);	/* post file remove */
		return;
	}

	if (S_ISLNK(sb.st_mode)) {	// process a symbolic link.
		if (sr_c->cfg->debug)
			sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG,
				   "debug: %s is a symbolic link. (follow=%s) posting\n",
				   fn, (sr_c->cfg->follow_symlinks) ? "on" : "off");

		//if (ts_newer( sb.st_mtim, latest_min_mtim ))
		sr_post(sr_c, fn, &sb);	// post the link itself.

		/* FIXME:  INOT  - necessary? I think symlinks can be skipped?
		 */

		if (!(sr_c->cfg->follow_symlinks))
			return;

		if (stat(fn, &sb) < 0) {	// repeat the stat, but for the destination.
			es = strerror_r(errno, error_buf, EBUFLEN);
			sr_log_msg(sr_c->cfg->logctx,LOG_ERROR, "failed to stat %s: %s\n", fn, es);
			return;
		}
		//if (ts_newer( latest_min_mtim, sb.st_mtim ) ) return; // only the link was new.

	} else if (S_ISDIR(sb.st_mode))	// process a directory.
	{
		sr_post(sr_c, fn, &sb);	/* post mkdir */

		if (sr_c->cfg->debug)
			sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG,
				   "info: opening directory: %s, first_call=%s, recursive=%s, follow_symlinks=%s\n",
				   fn, first_call ? "on" : "off",
				   (sr_c->cfg->recursive) ? "on" : "off",
				   (sr_c->cfg->follow_symlinks) ? "on" : "off");

		if (!first_call && !(sr_c->cfg->recursive))
			return;

		first_call = 0;

		// FIXME:  INOT 

		if (!sr_c->cfg->force_polling) {
			w = inotify_add_watch(inot_fd, fn, inotify_event_mask);
			if (w < 0) {
				es = strerror_r(errno, error_buf, EBUFLEN);
				sr_log_msg(sr_c->cfg->logctx,LOG_ERROR, "failed to add_watch for %s: %s\n", fn, es);
				return;
			}
		} else
			w = 0;

		if (!dir_stack_push(sr_c->cfg->logctx, fn, w, sb.st_dev, sb.st_ino)) {
			if (sr_c->cfg->logReject)
				sr_log_msg(sr_c->cfg->logctx,LOG_INFO, "rejecting loop: %s\n", fn);
			return;
		}		//else 
		//sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "pushed on stack: %s\n", fn );

		dir = opendir(fn);
		if (!dir) {
			es = strerror_r(errno, error_buf, EBUFLEN);
			sr_log_msg(sr_c->cfg->logctx,LOG_ERROR, "failed to open directory %s: %s\n", fn, es);
			return;
		}

		while ((e = readdir(dir))) {
			if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
				continue;

			strcpy(ep, fn);
			strcat(ep, "/");
			strcat(ep, e->d_name);
			do1file(sr_c, ep);
		}
		closedir(dir);

		if (sr_c->cfg->debug)
			sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "info: closing directory: %s\n", fn);

	} else {
		//if (ts_newer( sb.st_mtim, latest_min_mtim )) 
		sr_post(sr_c, fn, &sb);	// process a file
	}

}

struct rename_list {
	char *ofn;
	char *nfn;
	uint32_t cookie;
	struct rename_list *next;
};

int dir_stack_check4events(struct sr_context *sr_c)
 /* at the end of each sleeping interval, read the queue of outstanding events
    and process them.

    return the number of events processed.
  */
{
	char buff[PATH_MAX * 4];
	char fn[PATH_MAX];
	char *p;
	struct inotify_event *e;
	struct dir_stack *d;
	int ret;
	int event_count = 0;

	/* A normal rename is two events IN_MOVED_FROM, and IN_MOVED_TO.
	 * if the source is outside the paths being monitored, we only get IN_MOVED_TO.
	 * if the destination is outside, we only get IN_MOVED_FROM.
	 *
	 * an *rename_single_event* is one where we only receive one event.
	 * Since we don't have anything outside the tree, this turns into a normal 
	 * post of a file, or a removal.
	 */
	int rename_single_event=0;
	struct rename_list *old_names = NULL, *on = NULL, *prevon = NULL;

	struct hash_entry *new_entry, *entries_done, *tmpe = NULL;

	/* fixme: MISSING: process pending list
	   - go sequentially through the pending list,
	   removing things if they succeed.
	 */
	entries_done = NULL;

	/* normal event processing. */

	/* FIXME: MISSING: initialize done_list? */

	while ((ret = read(inot_fd, buff, sizeof buff)) > 0) {
		for (p = buff; p < (buff + ret); p += sizeof(struct inotify_event) + e->len) {
			e = (struct inotify_event *)p;
			event_count += 1;

			for (d = dir_stack_top; d && (e->wd != d->wd); d = d->next) ;
			if (!d) {
				sr_log_msg(sr_c->cfg->logctx,LOG_ERROR, "cannot find path for event %s\n", e->name);
				continue;
			}
			sprintf(fn, "%s/%s", d->path, e->name);

			sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG,
				   "bytes read: %d, sz ev: %ld, event: %04x %s: len=%d, fn=%s\n",
				   ret, (long)(sizeof(struct inotify_event) + e->len),
				   e->mask, inotify_event_2string(e->mask), e->len, fn);

			if ((e->mask & IN_IGNORED)) {
				sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "ignoring IGNORE event\n");
				continue;
			}
			/*
			 * directory removal processing
			 * ... code requires serious refactoring, but this quick fix should do for now
			 */
			if (e->mask & IN_ISDIR) {
				if (e->mask & IN_DELETE) {
					sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG,
						   "detected directory removal, removing from internal data structures");
					dir_stack_rm(fn);
					continue;
				} else if (e->mask & (IN_CREATE | IN_ATTRIB)) {
					do1file(sr_c, fn);
				}
			} else if ((e->mask & IN_CREATE) && !(sr_c->cfg->events & SR_EVENT_CREATE)) {
				continue;	// should skip non-dir create events.
			}

			/* rename processing
			   rename arrives as two events, old name MOVE_FROM, new name MOVE_TO.
			   need to group them together by cookie to call sr_post_rename.
			 */
			if (((e->mask & IN_MOVED_FROM) == IN_MOVED_FROM)
			    || ((e->mask & IN_MOVED_TO) == IN_MOVED_TO)) {
				sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "rename, %sname=%s\n",
					   ((e->mask & IN_MOVED_TO) ==
					    IN_MOVED_TO) ? "new" : "old", fn);
				rename_single_event=1;
				if (old_names) {
					prevon = NULL;
					for (on = old_names;
					     (on && (on->cookie != e->cookie)); on = on->next)
						prevon = on;
					if (on) {
						if (on->ofn) {
				                        rename_single_event=0;
							sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG,
								   "ok invoking rename ofn=%s %s\n",
								   on->ofn, fn);
							sr_post_rename(sr_c, on->ofn, fn);
							free(on->ofn);
						} else {
							sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG,
								   "ok invoking rename %s nfn=%s\n",
								   fn, on->nfn);
				                        rename_single_event=0;
							sr_post_rename(sr_c, fn, on->nfn);
							free(on->nfn);
						}
						if (prevon)
							prevon->next = on->next;
						else
							old_names = on->next;
						free(on);
						on = NULL;
						continue;
					}
				}
				on = (struct rename_list *)
				    malloc(sizeof(struct rename_list));
				on->cookie = e->cookie;
				on->ofn = NULL;
				on->nfn = NULL;
				if ((e->mask & IN_MOVED_TO) == IN_MOVED_TO)
					on->nfn = strdup(fn);
				else
					on->ofn = strdup(fn);
				on->next = old_names;
				old_names = on;
			}

			/* FIXME: missing: check for repeats. if post succeeds, remove from list.
			   if post fails, move to *pending* list.

			   done_list and pending_list options: 
			   1. build a linked list of fn-strings, search... O(n^2)... blch, but small n?
			   2. build a linked list of hashes of the strings (faster per string.)
			   store the list in order, so faster search.
			   best to do 1 first, and then optimize later if necessary.                     
			 */

			HASH_FIND_STR(entries_done, fn, tmpe);

			sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG,
				   "looking in entries_done, for %s, result=%p\n", fn, tmpe);

			if (!tmpe) {
				new_entry = (struct hash_entry *)
				    malloc(sizeof(struct hash_entry));
				new_entry->fn = strdup(fn);
				HASH_ADD_KEYPTR(hh, entries_done, new_entry->fn,
						strlen(new_entry->fn), new_entry);
				sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG,
					   "e->mask=%04x from:  %04x  to: %04x \n",
					   e->mask, IN_MOVED_FROM, IN_MOVED_TO);
				if (rename_single_event || !(e->mask & (IN_ATTRIB | IN_MOVED_FROM | IN_MOVED_TO))) {
					if (!(e->mask & IN_ATTRIB)
					    || (sr_c->cfg->events & SR_EVENT_ATTRIB)) {
						sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "do one file: %s\n", fn);
						do1file(sr_c, fn);
					}
				}
			} else {
				sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "entries_done hit! ignoring:%s\n", fn);
			}
		}
	}

	/* empty out done list */
	HASH_ITER(hh, entries_done, tmpe, new_entry) {
		free(tmpe->fn);
		HASH_DEL(entries_done, tmpe);
		free(tmpe);
	}
	return(event_count);
}

int sr_cpost_cleanup(struct sr_context *sr_c, struct sr_config_s *sr_cfg, int dolog)
{
	DIR *dir;
	int ret;
	char cache_dir[PATH_MAX];
	char cache_fil[PATH_MAX];
	struct stat sb;
	struct dirent *e;

	// if running, warn no cleanup
	if (sr_cfg->pid > 0) {
		ret = kill(sr_cfg->pid, 0);
		if (!ret) {	// is running.
			fprintf(stderr,
				"cannot cleanup : sr3_cpost configuration %s is running\n",
				sr_cfg->configname);
			return (1);
		}
	}

	sprintf(cache_dir, "%s/.cache/" SR_APPNAME "/%s/%s", getenv("HOME"),
		sr_c->cfg->progname, sr_c->cfg->configname);

	if (!sr_post_cleanup(sr_c)) {
		sr_log_msg(sr_c->cfg->logctx,LOG_WARNING, "failed to delete exchange: %s\n", sr_cfg->exchange);
	} else {
		sr_log_msg(sr_c->cfg->logctx,LOG_INFO, "exchange: %s deleted\n", sr_cfg->exchange);
	}
	sr_context_close(sr_c);
	sr_config_free(sr_cfg);

	dir = opendir(cache_dir);

	if (dir) {

		while ((e = readdir(dir))) {
			if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
				continue;

			strcpy(cache_fil, cache_dir);
			strcat(cache_fil, "/");
			strcat(cache_fil, e->d_name);

			if (lstat(cache_fil, &sb) < 0)
				continue;

			if (S_ISDIR(sb.st_mode)) {
				fprintf(stderr,
					"cannot cleanup : sr3_cpost configuration %s directory\n",
					e->d_name);
			}

			ret = remove(cache_fil);
		}

		closedir(dir);

		ret = rmdir(cache_dir);
	}

	/* I don't think we should delete logs.
	   Michel also mentioned, this doesn't delete old logs, so would need elaboration anyways.
	   if (dolog)
	   {
	   ret = remove(sr_cfg->logfn);
	   }
	 */

	return (0);
}

void usage()
{
	fprintf(stderr, "usage: sr3_cpost %s <options> <paths>\n\n", __sarra_version__);
	fprintf(stderr, "\taccept/reject <regex> - to filter files to post.\n");
	fprintf(stderr, "\taccept_unmatch <boolean> - if not matched, accept? (default: true).\n");
	fprintf(stderr, "\taction [start|stop|setup|cleanup|foreground] default: foreground\n");
	fprintf(stderr, "\t\tstart - start a daemon running (will detach) and write to log.\n");
	fprintf(stderr, "\t\thelp - view this usage.\n");
	fprintf(stderr, "\t\tshow - display the effective configuration.\n");
	fprintf(stderr, "\t\tstop - stop a running daemon.\n");
	fprintf(stderr, "\t\tlist - list configurations available.\n");
	fprintf(stderr,
		"\t\tdeclare - declare broker resources (to be ready for subscribers to bind to.)\n");
	fprintf(stderr, "\t\tsetup - bind queues to resources, declaring if needed.)\n");
	fprintf(stderr, "\t\tcleanup - delete any declared broker resources.\n");
	fprintf(stderr,
		"\t\tforeground - run as a foreground process logging to stderr (ideal for debugging.)\n");
	fprintf(stderr,
		"\tbroker amqps://<user>@host - required - to lookup in ~/.config/" SR_APPNAME
		"/credentials. MANDATORY\n");
	fprintf(stderr, "\tchmod_log <mode> - permissions to set on log files (default: 0600)\n");
	fprintf(stderr, "\tconfig|c <name> - Configuration file (to store options) MANDATORY\n");
	fprintf(stderr, "\tdebug <on|off> - more verbose output. (default: off) \n");
	fprintf(stderr,
		"\tdelete <on|off> - Assume Directories empty themselves. (default: off) \n");
	fprintf(stderr,
		"\tdocument_root|dr <path> - part of tree to subtract from advertised URL's.\n");
	fprintf(stderr,
		"\tdurable <boolean> - AMQP parameter, exchange declared persist across broker restarts (default: true)\n");
	fprintf(stderr,
		"\tevents <list> - types of file events to post (default: create,modify,link,delete )\n");
	fprintf(stderr,
		"\t\tcreate - file creation (generally empty files are not interesting.)\n");
	fprintf(stderr, "\t\tmodify - when files being written are closed (most interesting.)\n");
	fprintf(stderr, "\t\tdelete - when files removed. \n");
	fprintf(stderr, "\t\tattrib - when files chown, chmoded, or touched. \n");
	fprintf(stderr,
		"\t\tlink - when files are linked or symbolically linked removed (converted to symlink). \n");
	fprintf(stderr,
		"\texchange <exchange> - required - name of exchange to publish to (default: xs_<brokerusername>.)\n");
	fprintf(stderr,
		"\tfollow_symlinks <boolean> - traverse_symlinks and post the other side (default: off)\n");
	fprintf(stderr,
		"\tforce_polling <boolean> - walk the tree every time, instead of INOTIFY (default: off)\n");
	fprintf(stderr,
		"\t\tPolling is slower and much more resource intensive than default method, use only when needed.\n");
	fprintf(stderr,
		"\t\tExample: when using distributed cluster files systems with multiple writing nodes, like GPFS & lustre (or run on all nodes.)\n");
	fprintf(stderr,
		"\theader <key>=<value> - post an arbitrary key=value attribute with file. OPTIONAL\n");
	fprintf(stderr, "\thousekeeping <on|off|integer> - clean cache interval.\n");
	fprintf(stderr,
		"\tloglevel <integer> - print >= n:\n\t\t1-DEBUG, 2-info, 3-Warn, 4-ERROR, 5-CRITICAL.\n");
	fprintf(stderr,
		"\tblocksize <integer> - partition strategy (size of chunks): (default: 1) \n");
	fprintf(stderr, "\t\t1- always send files in one chunk, \n");
	fprintf(stderr, "\t\t0-guess chunk size\n");
	fprintf(stderr,
		"\t\t>1 explicit chunk size  (can use (M/K/G[B] suffixes: eg. 50M -> 50 megabytes (base 2) ).\n");
	fprintf(stderr,
		"\tpath <path> - a file/directory to post. (also on end of command line.) MANDATORY\n");
	fprintf(stderr,
		"\tpipe <boolean> - accept file names to post from stdin (default: off).\n");
	fprintf(stderr,
		"\tpost_baseUrl <url>[,<url>]... - retrieval base url in the posted files.\n");
	fprintf(stderr,
		"\t\t(a comma separated list of urls will result in alternation among multiple file postings.)\n");
	fprintf(stderr, "\trealpath <boolean> - resolve paths before posting (default: off)\n");
	fprintf(stderr, "\tsum <algo> - how to set fingerprint for posts: (default: s)\n");
	fprintf(stderr, "\t\td-MD5 sum of entire file.\n");
	fprintf(stderr, "\t\tn-MD5 sum of file name.\n");
	fprintf(stderr, "\t\ts-SHA512 sum of entire file.\n");
	fprintf(stderr, "\t\tN-SHA512 sum of file name.\n");
	fprintf(stderr,
		"\tsleep <integer> - watch paths every *sleep* seconds (rather than once) (default: 0 (== off)).\n");
	fprintf(stderr, "\tsuppress_duplicates|sd|cache|caching <on|off|integer> (default: off)\n");
	fprintf(stderr,
		"\t\tsuppress duplicate announcements < *cache* seconds apart.  \"on\" means 15 minute caching (on=900).\n");
	fprintf(stderr, "\tpost_topicPrefix <string> - AMQP topic prefix (default: v03 )\n");
	fprintf(stderr,
		"\tto <destination> - clusters pump network should forward to (default: broker).\n");
	fprintf(stderr,
		"\t<paths> - list of files and/or directories to post (same as *path* option.)\n\n");
	fprintf(stderr,
		"This is a limited C implementation of sr_post(1), see man page for details\n\n");
	fprintf(stderr,
		"does not support plugins. main difference: specifying sleep makes it act like sr_watch\n\n");
	exit(1);
}

int main(int argc, char **argv)
{
	struct sr_context *sr_c;
	struct sr_config_s sr_cfg;
	char inbuff[PATH_MAXNUL];
	int consume, i, pass;
	int ret;
	char *one;

	struct timespec tsleep;
	float elapsed;
	int fs_event_count = 0;
	int seconds_since_fs_event;
	struct timespec now,last_fs_event; 

	clock_gettime(CLOCK_REALTIME_COARSE, &last_fs_event);
	clock_gettime(CLOCK_REALTIME_COARSE, &now);

	sr_config_init(&sr_cfg, "cpost");

	i = 1;
	while (i < argc) {
		if ((strlen(argv[i]) > 1) && (argv[i][0] == '-'))
			consume = sr_config_parse_option(&sr_cfg, &(argv[i][(argv[i][1] == '-') ? 2 : 1]),	/* skip second hyphen if necessary */
							 (argc > i) ? argv[i + 1] : NULL,
							 (argc > i + 2) ? argv[i + 2] : NULL, 1);
		else
			break;
		if (consume < 0)
			return (1);

		if (!consume)
			break;
		i += consume;
	}

	for (; i < argc; i++) {
		if (!strcmp(sr_cfg.action, "foreground")
		    || !strcmp(sr_cfg.action, "enable")
		    || !strcmp(sr_cfg.action, "disable")
		    || !strcmp(sr_cfg.action, "add")
		    || !strcmp(sr_cfg.action, "remove")
		    || !strcmp(sr_cfg.action, "edit")
		    || !strcmp(sr_cfg.action, "show")
		    )
			sr_add_path(&sr_cfg, argv[i]);
		else
			sr_config_read(&sr_cfg, argv[i], 1, 1);
	}

	if (!strcmp(sr_cfg.action, "add")) {
		sr_config_add(&sr_cfg);
		exit(0);
	}

	if (!strcmp(sr_cfg.action, "enable")) {
		sr_config_enable(&sr_cfg);
		exit(0);
	}

	if (!strcmp(sr_cfg.action, "help") || sr_cfg.help)
		usage();

	if (!strcmp(sr_cfg.action, "remove")) {

		one = sr_config_find_one(&sr_cfg, sr_cfg.paths->path);
		if (one && !strcmp(&(one[strlen(one) - 5]), ".conf")) {
			sr_config_read(&sr_cfg, one, 1, 1);
		} else {
			sr_config_remove(&sr_cfg);
			exit(0);
		}
	}

	if (!strcmp(sr_cfg.action, "disable")) {
		sr_config_disable(&sr_cfg);
		exit(0);
	}

	if (!strcmp(sr_cfg.action, "edit")) {
		sr_config_edit(&sr_cfg);
		exit(0);
	}

	if (!strcmp(sr_cfg.action, "list")) {
		sr_config_list(&sr_cfg);
		exit(0);
	}

	if (!sr_config_finalize(&sr_cfg, 0)) {
		sr_log_msg(sr_cfg.logctx,LOG_ERROR, "something missing, failed to finalize config\n");
		sr_config_free(&sr_cfg);
		return (1);
	}

	if (!strcmp(sr_cfg.action, "log")) {
		sr_config_log(&sr_cfg);
		exit(0);
	}

	if (!strcmp(sr_cfg.action, "show")) {
		exit(0);
	}
	// if going to run as a daemon, Check if already running. (conflict in use of state files.)
	if (strcmp(sr_cfg.action, "foreground") || (sr_cfg.sleep > 0)) {
		ret = sr_config_startstop(&sr_cfg);

		if (ret < 1) {
			exit(abs(ret));
		}
		if (sr_cfg.sleep > 0) {
			sr_log_msg(sr_cfg.logctx,LOG_INFO,
				   "sleep > 0 means run as a daemon, watching given paths.\n");
		}

	} else {
		if (sr_cfg.nodupe_ttl > 0) {
			sr_log_msg(sr_cfg.logctx,LOG_CRITICAL,
				   "cache > 0 cannot be used unless running as a daeemon. turn off to use for rapid parallel posting.\n");
			return (4);
		}
	}

	if ((sr_cfg.sleep <= 0.0) &&
	    ((!strcmp(sr_cfg.action, "start")) || (!strcmp(sr_cfg.action, "restart")))) {
		sr_log_msg(sr_cfg.logctx,LOG_WARNING,
			   "start|restart with sleep <= 0 does nothing. exiting normally\n");
		return (0);
	}

	if (sr_cfg.paths == NULL) {
		sr_log_msg(sr_cfg.logctx,LOG_CRITICAL, "no path to post given\n");
		return (0);
        }

	sr_c = sr_context_init_config(&sr_cfg, 0);
	if (!sr_c) {
		sr_log_msg(sr_cfg.logctx,LOG_CRITICAL, "failed to read config\n");
		sr_config_free(&sr_cfg);
		return (1);
	}

	sr_c = sr_context_connect(sr_c);

	if (!sr_c) {
		sr_log_msg(sr_cfg.logctx,LOG_CRITICAL, "failed to establish sr_context\n");
		sr_config_free(&sr_cfg);
		return (1);
	}

	if (!strcmp(sr_cfg.action, "cleanup")) {
		ret = sr_cpost_cleanup(sr_c, &sr_cfg, 0);
		return (0);
	}

	if (!strcmp(sr_cfg.action, "remove")) {
		ret = sr_cpost_cleanup(sr_c, &sr_cfg, 1);
		if (ret == 0) {
			if (one)
				unlink(one);
		}
		return (0);
	}

	sr_post_init(sr_c);

	if (!sr_c->cfg->post_baseUrl) {
		sr_log_msg(sr_c->cfg->logctx,LOG_ERROR, "post_baseURL setting missing\n");
		return (0);
	}

	if (!strcmp(sr_cfg.action, "setup") 
	    || !strcmp(sr_cfg.action, "declare")) {
		sr_context_close(sr_c);
		free(sr_c);
		sr_config_free(&sr_cfg);
		exit(0);
	}

	if (strcmp(sr_cfg.action, "foreground")) {
		sr_daemonize(1,sr_cfg.logctx);
	}
	// Assert: this is a working instance, not a launcher...
	if (sr_config_activate(&sr_cfg)) {
		sr_log_msg(sr_c->cfg->logctx,LOG_WARNING,
			   "could not save pidfile %s: possible to run conflicting instances  \n",
			   sr_cfg.pidfile);
	}

	sr_log_msg(sr_c->cfg->logctx,LOG_INFO, "%s %s config: %s, pid: %d, starting\n",
		   sr_cfg.progname, __sarra_version__, sr_cfg.configname, sr_cfg.pid);

	pass = 0;
	// when using inotify, have to walk the tree to set the watches initially.
	//latest_min_mtim.tv_sec = 0;
	//latest_min_mtim.tv_nsec = 0;

	if (!sr_cfg.force_polling) {

		// IN_CREATE must be included always in order to add directories to inotfd when created.
		inotify_event_mask = IN_DONT_FOLLOW | IN_CREATE | IN_ATTRIB;

		if (sr_cfg.events & SR_EVENT_CREATE)
			inotify_event_mask |= IN_CREATE | IN_MOVED_FROM | IN_MOVED_TO;

		if (sr_cfg.events & SR_EVENT_MODIFY)
			inotify_event_mask |= IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO;

		if (sr_cfg.events & SR_EVENT_DELETE)
			inotify_event_mask |= IN_DELETE;

		inot_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
		if (inot_fd < 0) {
			es = strerror_r(errno, error_buf, EBUFLEN);
			sr_log_msg(sr_c->cfg->logctx,LOG_ERROR, "inot init failed: %s\n", es);
		}
		sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG,
			   "sr_event_mask: %04x translated to inotify_event_mask: %04x\n",
			   sr_cfg.events, inotify_event_mask);
	} else {
		sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "force_polling active, so event masks not used.\n");
	}

	while (1) {

		if (((sr_cfg.sleep > 0.0) && sr_cfg.vip) && (sr_has_vip(sr_cfg.vip,sr_cfg.logctx) < 1)) {
			sleep(5);
			continue;
		}
		if (sr_cfg.force_polling || !pass) {
			sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "starting polling loop pass: %d\n", pass);
			for (struct sr_path_s * i = sr_cfg.paths; i; i = i->next) {
				first_call = 1;
				do1file(sr_c, i->path);
			}
			dir_stack_reset();

			// FIXME: I think this breaks non Inotify walks...
			//if ( sr_cfg.force_polling && !sr_cfg.delete )
			//    latest_min_mtim = sr_time_of_last_run();

			//sr_log_msg(sr_c->cfg->logctx,LOG_ERROR, "latest_min_mtime: %d, %d\n", latest_min_mtim.tv_sec, latest_min_mtim.tv_nsec );
		} else {

			fs_event_count = dir_stack_check4events(sr_c);	// inotify. process accumulated events.

			//sr_log_msg(sr_c->cfg->logctx,LOG_INFO, "%d events received.\n", fs_event_count );
			if (fs_event_count == 0) {
	                    clock_gettime(CLOCK_REALTIME_COARSE, &now);

	                    seconds_since_fs_event = now.tv_sec - last_fs_event.tv_sec ;
			    //sr_log_msg(sr_c->cfg->logctx,LOG_INFO, "%d-%d == %d seconds since last fs_event.\n", 
			    //		    now.tv_sec, last_fs_event.tv_sec, seconds_since_fs_event );
			    if (seconds_since_fs_event > IDLE_MESSAGE_INTERVAL)  {
				sr_log_msg(sr_c->cfg->logctx,LOG_INFO, "no directory changes in last %d seconds\n", seconds_since_fs_event );
	                        clock_gettime(CLOCK_REALTIME_COARSE, &last_fs_event);
			    }
			} else {
	                   clock_gettime(CLOCK_REALTIME_COARSE, &last_fs_event);
			}
		}

		if (sr_cfg.sleep <= 0.0)
			break;	// one shot.

		elapsed = sr_context_housekeeping_check(sr_c);

		if (elapsed < sr_cfg.sleep) {
			tsleep.tv_sec = (long)(sr_cfg.sleep - elapsed);
			tsleep.tv_nsec = (long)((sr_cfg.sleep - elapsed) - tsleep.tv_sec);
			//sr_log_msg(sr_c->cfg->logctx,LOG_DEBUG, "debug: watch sleeping for %g seconds. \n", (sr_cfg.sleep-elapsed));
			nanosleep(&tsleep, NULL);
		} else
			sr_log_msg(sr_c->cfg->logctx,LOG_WARNING,
				   "INFO: watch, one pass takes longer (%g) than sleep interval (%g), not sleeping at all\n",
				   elapsed, sr_cfg.sleep);

		pass++;
	}

	if (sr_cfg.pipe) {
		if (sr_cfg.sleep > 0.0) {
			sr_log_msg(sr_c->cfg->logctx,LOG_ERROR, "sleep conflicts with pipe. pipe ignored.\n");
		} else
			while (fgets(inbuff, PATH_MAX, stdin) > 0) {
				inbuff[strlen(inbuff) - 1] = '\0';
				do1file(sr_c, inbuff);
			}
	}

	sr_context_close(sr_c);
	sr_config_deactivate(&sr_cfg);
	free(sr_c);
	sr_c = NULL;
	sr_config_free(&sr_cfg);
	dir_stack_free();
	return (0);
}
