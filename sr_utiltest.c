
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdio.h>

#include "sr_util.h"

unsigned char myhash[SHA512_DIGEST_LENGTH + 1];

unsigned char *md5hash(char *str)
{
	EVP_MD_CTX *ctx;
	const EVP_MD *md;
	unsigned int hashlen = 0;

	ctx = EVP_MD_CTX_create();
	md = EVP_md5();
	EVP_DigestInit_ex(ctx, md, NULL);

	EVP_DigestUpdate(ctx, str, strlen(str));
	EVP_DigestFinal_ex(ctx, myhash + 1, &hashlen);
	myhash[0] = 'd';
	return (myhash);
}

unsigned char *sha512hash(char *str)
{
	EVP_MD_CTX *ctx;
	const EVP_MD *md;
	unsigned int hashlen = 0;

	ctx = EVP_MD_CTX_create();
	md = EVP_sha512();
	EVP_DigestInit_ex(ctx, md, NULL);

	EVP_DigestUpdate(ctx, str, strlen(str));
	EVP_DigestFinal_ex(ctx, myhash + 1, &hashlen);

	myhash[0] = 's';
	return (myhash);
}

int right(char *input, char *expected, char *output)
{
	printf("     input: %s\n", input);
	printf("    output: %s\n", output);
	printf("  expected: %s\n", expected);
	if (strcmp(output, expected)) {
		printf("ERROR: not \n");
		return (0);
	} else {
		printf("Good! continue...\n");
		return (1);
	}
}

int main(int argc, char *argv[])
{

	struct timespec tsnow;
	struct timespec tsrt;
	time_t t;
	char timestring[60];
	char *tscp;
	int testcnt = 0;
	int success = 0;
	int i = 0;
	char input[1024];
	char *output;
	char *roundtrip;
	char expected[1024];

	unsigned char original_hash[SHA512_DIGEST_LENGTH + 1];
	unsigned char rt_hash[SHA512_DIGEST_LENGTH + 1];

	char osumstr[SR_SUMSTRLEN];
	char rtsumstr[SR_SUMSTRLEN];

	fprintf(stderr, "SHA512_DIGEST_LENGTH=%d\n", SHA512_DIGEST_LENGTH);
	fprintf(stderr, "SR_SUMSTRLEN=%d\n", SR_SUMSTRLEN);

	memcpy(original_hash, sha512hash("hoho"), SHA512_DIGEST_LENGTH + 1);

	fprintf(stderr, "sumstr=%s", sr_hash2sumstr(sr_sumstr2hash("z,d")));

	for (i = 0; i < 9; i++) {
		for (i = 1; i < sr_get_sumhashlen(osumstr[0]); i++)
			fprintf(stderr, " %02d", i);
		fprintf(stderr, "\n");

		strcpy(osumstr, sr_hash2sumstr(original_hash));
		memcpy(rt_hash, sr_sumstr2hash(osumstr), SHA512_DIGEST_LENGTH + 1);
		strcpy(rtsumstr, sr_hash2sumstr(rt_hash));

		fprintf(stderr, "     original hash is: +%s+ length: %ld\n",
			osumstr, (long)strlen(osumstr));
		fprintf(stderr, "round-tripped hash is: +%s+ length: %ld\n",
			rtsumstr, (long)strlen(rtsumstr));

		if (!strcmp(osumstr, rtsumstr)) {
			fprintf(stderr, "OK: sum string <-> hash strings are the same.\n");
			success++;
		} else {
			fprintf(stderr,
				"FAIL: original sum strings and roundtripped ones are different\n");
		}
		testcnt++;

		if (!memcmp(original_hash, rt_hash, SHA512_DIGEST_LENGTH + 1)) {
			fprintf(stderr, "OK: original and round-tripped hashes are the same.\n");
			success++;
		} else {
			fprintf(stderr,
				"FAIL: original sum hashes and roundtripped ones are different\n");
		}
		testcnt++;

		memcpy(original_hash, sr_sumstr2hash(rtsumstr), SHA512_DIGEST_LENGTH + 1);
	}
	t = time(NULL);
	sr_log_msg(LOG_INFO, "              It is now: %s\n", ctime(&t));

	/* FIXME, repeat for MD5, for N, n, L, R  */

	clock_gettime(CLOCK_REALTIME, &tsnow);

	sr_log_msg(LOG_INFO, "        starting time is: %ld\n", tsnow.tv_sec);
	tscp = sr_time2str(&tsnow);
	memset(timestring, 0, 60);
	memcpy(timestring, tscp, strlen(tscp));
	sr_log_msg(LOG_DEBUG, "text version ot time is: %s\n", timestring);

	memcpy(&tsrt, sr_str2time(timestring), sizeof(struct timespec));
	sr_log_msg(LOG_DEBUG, " round tripped, time is: %ld\n", tsrt.tv_sec);
	sr_log_msg(LOG_DEBUG, "          difference is: %ld\n", tsrt.tv_sec - tsnow.tv_sec);
	tscp = sr_time2str(&tsrt);
	memcpy(timestring, tscp, strlen(tscp));

	sr_log_msg(LOG_DEBUG, "text version ot time is: %s\n", timestring);

	if (tsrt.tv_sec - tsnow.tv_sec) {
		sr_log_msg(LOG_ERROR,
			   "Failed to roundtrip time through conversion routines, see difference above, should be 0\n");
	} else
		success++;

	testcnt++;

	sr_log_msg(LOG_INFO, " testing sr_hex2base64 conversion\n");

	strcpy(input, "d15f684279f7d4721671a587325160a8");
	output = sr_hex2base64(input);
	strcpy(expected, "0V9oQnn31HIWcaWHMlFgqA==");

	if (right(input, expected, output))
		success++;
	testcnt++;

	roundtrip = sr_base642hex(output);
	right(output, input, roundtrip);
	if (right(output, input, roundtrip))
		success++;
	testcnt++;

	strcpy(input, "4c1e5d8ef96ee9e00f2feb38f70de21f");
	output = sr_hex2base64(input);
	strcpy(expected, "TB5djvlu6eAPL+s49w3iHw==");
	if (right(input, expected, output))
		success++;
	testcnt++;

	roundtrip = sr_base642hex(output);
	right(output, input, roundtrip);
	if (right(output, input, roundtrip))
		success++;
	testcnt++;

	strcpy(input,
	       "dcc2806747cc0046f4dcd7ac93411bde896fd089edf3420e0e5d1fe0b6b876b403dfdcf7221b6dd520298bd2de4c4e74bdd0cd76c10d69ca44ebc724dedda7b1");
	output = sr_hex2base64(input);
	strcpy(expected,
	       "3MKAZ0fMAEb03Nesk0Eb3olv0Int80IODl0f4La4drQD39z3Ihtt1SApi9LeTE50vdDNdsENacpE68\\nck3t2nsQ==");
	if (right(input, expected, output))
		success++;
	testcnt++;

	roundtrip = sr_base642hex(output);
	right(output, input, roundtrip);
	if (right(output, input, roundtrip))
		success++;
	testcnt++;

	printf("%s %d/%d tests passed\n", (success >= testcnt) ? "OK" : "FAILED", success, testcnt);
	exit(!(success >= testcnt));
}
