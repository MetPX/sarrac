
/*
  for use by sr_post to avoid duplicate postings, sr_winnow to suppress duplicated, perhaps other consumers as well.

  is the use of the hash enough of a key?  dunno.
 */

#ifndef SR_CACHE_H
#define SR_CACHE_H 1

#include "sr_context.h"
#include <openssl/sha.h>
#include <time.h>
#include "uthash.h"

#define SR_CACHEKEYSZ (SHA512_DIGEST_LENGTH+1)

struct sr_cache_entry_path_s {
	char *path;
	char *partstr;
	struct timespec created;
	struct sr_cache_entry_path_s *next;
};

struct sr_cache_entry_s {
	unsigned char key[SR_CACHEKEYSZ];	// Assumed longest possible hash. first character is algorithm marker.
	struct sr_cache_entry_path_s *paths;
	UT_hash_handle hh;
};

struct sr_cache_s {
	char *fn;
	FILE *fp;
	struct sr_cache_entry_s *data;
	struct sr_log_context_s *logctx;
};

struct sr_cache_s *sr_cache_open(const char *fn, struct sr_log_context_s *logctx);
 /* 
    create an sr_cache based on the content of the named file.     
  */

void sr_cache_close(struct sr_cache_s *c);
 /* 
    close sr_cache.
    frees structure established by open, but does not set c to NULL.
  */

int sr_cache_check(struct sr_cache_s *cachep, char *cache_basis, char algo,
		   unsigned char *ekey, char *path, char *partstr);

 /* 

    insert new item with key value = ekey, and lenghth = ekeylen. if it isn't in the cache.
    return value:
    0 - present, so not added, but access time updated to now.
    1 - was not present, so added to cache.
    <0 - something bad happenned

  */

void sr_cache_clean(struct sr_cache_s *cachep, float more_than_seconds_old);
 /* 
    remove entries in the cache if their date stamps are older than the threshold.
    this is LRU, as every check updates the age in the cache.

  */

void sr_cache_free(struct sr_cache_s *cachep);
 /* 
    remove all entries in the cache  (cleanup to discard.)
  */

int sr_cache_save(struct sr_cache_s *cachep, int to_stdout);
 /* 
    write entire cache data to the given file name. (for debugging, set to stdout.)
    returns number of entries written.
  */

#endif
