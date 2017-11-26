/**
 * break_time.c
 * @author Jacob Heard
 *
 * This program demonstrates a simple known plaintext attack when a key is 
 * generated using C rand().
 * 
 * The program takes the start and end times as unix timestamps and outputs 
 * any texts (and seeds) that match the known portion plaintext.
 * 
 * Internally, AES(128)-ECB is used to encrypt the data. 
 * Note that the actual vulnerability lies is in how the key is generated, 
 * not the cipher itself.
**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "aes.h"


void genKey(uint8_t *buf, int len) {
	for(int i = 0; i < len; i++) {
		buf[i] = rand() % 0x100;
	}
}

int main(int argc, char* argv[]) {
	if(argc < 4) {
		printf("Usage: %s seed time_start time_end\n", argv[0]);
		return 1;
	}
	
	// Start time, end time, original seed
	long tstart, tend, oseed;
	char *err;

	// plaintext sample
	const char *PLAINTEXT = "this message starts with \"this \"!\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	const char *SEARCHSTR = "this "; // The text to search for
	char ciphertext[64] = {0};
	char buffer[64] = {0};	
	uint8_t key[16];
	
	oseed = strtol(argv[1], &err, 10);
	if(*err != '\0') {
		printf("Error parsing start time.\n");
		return EXIT_FAILURE;
	}	
	tstart = strtol(argv[2], &err, 10);
	if(*err != '\0') {
		printf("Error parsing start time.\n");
		return EXIT_FAILURE;
	}
	tend = strtol(argv[3], &err, 10);
	if(*err != '\0' || tend < tstart) {
		printf("Error parsing end time. %d\n", tend);
		return EXIT_FAILURE;
	}

	int n = strlen(PLAINTEXT);
	int m = strlen(SEARCHSTR);
	printf("Plaintext to match: %s\n", PLAINTEXT);
	srand(oseed);
	genKey(key, 16);
	AES_ECB_encrypt(PLAINTEXT, key, ciphertext, n + n %16);
	
	long seed;
	for(seed = tstart; seed < tend; seed ++) {
		srand(seed);
		genKey(key, 16);
		AES_ECB_decrypt(ciphertext, key, buffer, n + n % 16);
		if(strncmp(buffer, SEARCHSTR, m) == 0) {
			printf("Possible match (%d): %s\n", seed, buffer);
		}
	}
	
	return EXIT_SUCCESS;
}
