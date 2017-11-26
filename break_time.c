/**
 * break_time.c
 * @author Jacob Heard
 *
 * This program demonstrates a simple known plaintext attack when a key is 
 * generated using an insecure seed.
 * 
 * For the sake of this example, assume srand() and rand() are a CSPRNG. An
 * exploit for finding a secure seed while using rand() can be found in 
 * the file break_rand.c
 *
 * Actual breakdown of program:
 * 1. srand() is called on the given seed, and a 128bit key is generated. 
 *    This key is used to encrypt some piece of plaintext. It is assumed we 
 *    (the attacker) know the first few bytes of this plaintext, but nothing 
 *    else.
 * 2. srand() is called on all seeds from time_start to time_end. After each 
 *    call, a new key is generated and the ciphertext from above is decrypted 
 *    using this key. Each ciphertext is tested against the known portion of 
 *    plaintext.
 * 3. Any matches are listed as possible plaintexts for the given ciphertext.
 *    This works well because there are only 2592000(~2^21) seconds in one 
 *    month, or 31536000 (~2^25) seconds in one year. So if the month or year 
 *    of the key generation is known, it is trivial to generate all possible 
 *    states with modern computing.
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "aes.h"


/* Generates a random 16 byte key using rand() for each byte */
void genKey(uint8_t *buf, int len) {
	for(int i = 0; i < len; i++) {
		buf[i] = rand() % 0x100;
	}
}

int main(int argc, char* argv[]) {
	if(argc < 4) {
		printf("%s takes a seed (some unix timestamp) and given a start and end time, finds the seed using a known plaintext attack.\n\n", argv[0]);
		printf("Usage: %s seed time_start time_end\n", argv[0]);
		printf("    seed        Timestamp used to encrypt a message (unix timestamp)\n");
		printf("    time_start  The start of the time period (unix timestamp)\n");
		printf("    time_end    The end of the time period (unix timestamp)\n");
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

	int n = strlen(PLAINTEXT); // Length of plaintext
	int m = strlen(SEARCHSTR); // Number of known bytes of plaintext
	printf("Plaintext to match: %s\n\n", PLAINTEXT); // Print the plaintext we are attempting to match
	srand(oseed);
	genKey(key, 16); // Generate the key for the original cipher
	AES_ECB_encrypt(PLAINTEXT, key, ciphertext, n + n %16); // Find the original ciphertext

	/* Now that all of the setup is done, this is the actual body of the 
	 * program; generate all possible keys and test each one. 
	 */
	long seed;
	for(seed = tstart; seed < tend; seed ++) {
		// Seed the PRNG
		srand(seed);
		// Generate a new key
		genKey(key, 16);
		// Decrypt the ciphertext
		AES_ECB_decrypt(ciphertext, key, buffer, n + n % 16);
		// Print any possible matches
		if(strncmp(buffer, SEARCHSTR, m) == 0) {
			printf("Possible match (%d): %s\n", seed, buffer);
		}
	}
	
	return EXIT_SUCCESS;
}
