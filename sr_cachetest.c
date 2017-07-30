
#include <openssl/sha.h>
#include <openssl/md5.h>

#include "sr_cache.h"

unsigned char hash[SHA512_DIGEST_LENGTH];

unsigned char *md5hash( char *str )
{
   MD5_CTX md5ctx;

   MD5_Init( &md5ctx );
   MD5_Update( &md5ctx, str, strlen(str) );
   MD5_Final( hash, &md5ctx );
   return(hash);
}

unsigned char *sha512hash( char *str )
{
   SHA512_CTX shactx;

   SHA512_Init( &shactx );
   SHA512_Update( &shactx, str, strlen(str) );
   SHA512_Final( hash, &shactx );
   return(hash);
}

int main( int argc, char *argv[] )
{
   struct sr_cache_t *cache=NULL;
   int ret;
   int population=0;

   int test_count=0;
   int success_count=0;

   hash[0]='s';
   hash[1]=',';
   hash[2]='\0';

   unlink( "sr_cache_save.test" );
   cache = sr_cache_open( "sr_cache_save.test" );
   ret = sr_cache_check( cache, 's', sha512hash( "hoho" ), "hoho", "1,1,0,0" );
   if (ret > 0) {
       fprintf( stdout, "OK. added hoho to the cache\n" );
       success_count++;
       population++;
   } else
       fprintf( stdout, "ERROR: failed to add hoho to the cache\n" );
   test_count++;

   ret = sr_cache_check( cache, 's', sha512hash( "haha" ), "haha", "1,1,0,0" );
   if (ret > 0) {
       fprintf( stdout, "OK. added haha to the cache\n" );
       success_count++;
       population++;
   } else
       fprintf( stdout, "ERROR: failed to add haha to the cache\n" );
   test_count++;

   ret = sr_cache_check( cache, 's', sha512hash( "hoho" ), "hoho", "1,1,0,0" );
   if (ret > 0) 
       fprintf( stdout, "ERROR: added hoho to the cache a second time\n" );
   else if ( ret == 0 )
   {
       fprintf( stdout, "OK refused to add hoho to the cache a second time\n" );
       success_count++;
   }
   test_count++;

   ret = sr_cache_check( cache, 's', sha512hash( "hoho" ), "haha2", "1,1,0,0" );
   if (ret > 0)  {
       fprintf( stdout, "OK: added haha to the cache with same sum as hoho\n" );
       success_count++;
       population++;
   } else if ( ret == 0 )
   {
       fprintf( stdout, "ERROR refused to add haha to the cache with same value as hoho\n" );
   }
   test_count++;

   hash[0]='d';
   hash[1]=',';
   hash[2]='\0';
   ret = sr_cache_check( cache, 'd', md5hash( "lala" ), "lolo/lala", "1,1,0,0" );
   if (ret > 0)  {
       fprintf( stdout, "OK: added lolo to the cache with same an md5 sum\n" );
       success_count++;
       population++;
   } else if ( ret == 0 )
   {
       fprintf( stdout, "ERROR refused to add haha to the cache with same value as hoho\n" );
   }
   test_count++;

   ret = sr_cache_check( cache, 'd', md5hash( "lala" ), "lolo/lala", "1,1,0,0" );
   if (ret > 0) 
       fprintf( stdout, "ERROR: added lala to the cache a second time\n" );
   else if ( ret == 0 )
   {
       fprintf( stdout, "OK refused to add lala to the cache a second time\n" );
       success_count++;
   }
   test_count++;

   ret = sr_cache_check( cache, 'd', md5hash( "lala" ), "lolo/lily", "1,1,0,0" );
   if (ret > 0)  {
       fprintf( stdout, "OK: added lily to the cache with same sum as lolo\n" );
       success_count++;
       population++;
   } else if ( ret == 0 )
   {
       fprintf( stdout, "ERROR refused to add lily to the cache with same value as lolo\n" );
   }
   test_count++;


   fprintf( stdout, "closing cache.\n" );
   sr_cache_close( cache );
   cache = NULL;

   /* 
      There are only three hashes in the table, so that HASH_COUNT should be 3.
      sha of haha, sha of hoho, then two items under md5 of lala
   */ 
   cache = sr_cache_open( "sr_cache_save.test" );
   fprintf(stdout, "after load: cache=%p count=%d\n", cache, HASH_COUNT(cache->data) );
   if (HASH_COUNT(cache->data) == 3)
   {
       fprintf( stdout, "OK restored by cache_load: same number of cache entries\n" );
       success_count++;
   } else {
       fprintf( stdout, "failed to restore by cache_load population is: %d, expected: %d\n",
               HASH_COUNT(cache->data), 3 );
   }
   test_count++;

   ret = sr_cache_save( cache, 1 );
   if ( ret == population ) 
   {
       fprintf( stdout, "OK restored by cache_load: same number of cache entry paths.\n" );
       success_count++;
   } else {
       fprintf( stdout, "failed to restore paths from cache population is: %d, expected: %d\n",
                          ret, population );
   }
   test_count++;


   if (success_count == test_count )
   {
       fprintf( stdout, "OK: %d of %d tests passed\n", success_count, test_count );
       exit(0);
   }
   fprintf( stdout, "FAILED: only %d of %d tests passed.\n", success_count, test_count );
   exit(1); 
}