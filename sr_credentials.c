
/*
 This file is part of sarracenia.
 The sarracenia suite is Free and is proudly provided by the Government of Canada
 Copyright (C) Her Majesty The Queen in Right of Canada, Environment Canada, 2008-2015

 Questions or bugs report: dps-client@ec.gc.ca
 sarracenia repository: https://github.com/MetPX/Sarrac
 Documentation: https://github.com/MetPX/sarracenia

 Code contributed by:
     Peter Silva - 2017-2019

 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

char *sr_credentials = NULL;

char *sr_credentials_fetch(char *s)
  /* search for the first credential that matches the search spec given.
   */
{
	char *start = sr_credentials;
	char *end = sr_credentials;
	char *result = NULL;
	int slen;

	if (!s)
		return (NULL);

	slen = strlen(s);

	//fprintf(stderr, "\nfetching: %s\n", s );

	while (*end != '\0') {
		//fprintf( stderr, "try:\n%s\n", start );
		int i = 0;
		int smatching = 0;

		while (start[i] == s[i]) {
			//fprintf( stderr, "start[i]=%c, s[i]=%c\n", start[i], s[i] );
			i++;
		}
		//fprintf( stderr, "out of loop 1: start[i]=%c, s[i]=%c\n", start[i], s[i] );
		if (i == slen) {
			result = (char *)malloc(i + 1);
			strncpy(result, start, i);
			result[i] = '\0';
			//fprintf( stderr, "result: %s\n", result );
			return (result);
		}

		if (((start[i] == ':') && (s[i] == '@')) || (!strchr(s, '@'))) {
			smatching = i;
			//fprintf( stderr, "skipping password..\n" );
			while (start[i] != '@')
				i++;

			// we can't compare @ when we don't have a username in the config uri
			if (!strchr(s, '@'))
				++i;

			//fprintf( stderr, "rest of url, start[i]=%c, s[smatching]=%c\n", 
			//        start[i], s[smatching] );

			while ((smatching < slen) && start[i] == s[smatching]) {
				//fprintf( stderr, "start[i]=%c, i=%d s[smatching]=%c smatching=%d\n", 
				//     start[i], i, s[smatching], smatching );
				i++;
				smatching++;
			}
			//fprintf( stderr, "out of loop 2, slen=%d, start[i]=%c, i=%d s[smatching]=%c smatching=%d\n", 
			//        slen, start[i], i, s[smatching], smatching );

			if ((smatching >= slen - 1)
			    && ((start[i] == ' ') || (start[i] == '/')
				|| (start[i] == '\t') || (start[i] == '\n'))) {
				result = (char *)malloc(i + 1);
				strncpy(result, start, i);
				result[i] = '\0';
				//fprintf( stderr, "result: %s\n", result );
				return (result);
			};
		}
		//fprintf( stderr, "nope!\n" );
		end = start + i;
		while ((*end != '\n') && (*end != '\0'))
			end++;
		start = end + 1;
	}
	return (NULL);
}

void sr_credentials_init()
{

	FILE *f;
	char cfnbuf[1024];
	struct stat sb;
	int status;

	strcpy(cfnbuf, getenv("HOME"));
	strcat(cfnbuf, "/.config/" SR_APPNAME "/credentials.conf");

	status = stat(cfnbuf, &sb);

	if (status) {
		sb.st_size = 1;
	}
	sr_credentials = (char *)malloc(sb.st_size + 1);

	//fprintf( stderr, "opening %s\n", cfnbuf );

	f = fopen(cfnbuf, "r");
	if (f != NULL) {
		fread(sr_credentials, sb.st_size, 1, f);
		sr_credentials[sb.st_size] = '\0';
		fclose(f);
	} else {
		sr_credentials[0] = '\0';
	}

}

void sr_credentials_cleanup()
{

	if (sr_credentials)
		free(sr_credentials);
}

/* 

void main() {

 sr_credentials_init();
 
 sr_credentials_fetch( "amqp://guest:guest@localhost" );
 sr_credentials_fetch( "amqp://guest@localhost" );
 sr_credentials_fetch( "amqp://tsource@localhost/" );
 
}

 */
