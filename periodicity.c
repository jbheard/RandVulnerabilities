/**
 * @author Jacob Heard
 * break_rand.c
 * 
 * This program demonstrates a simple known plaintext attack on a portable implementation 
 * of the rand() algorithm. This demonstrates that even when a key is used, 
 * 
 * Idea from: https://crypto.stackexchange.com/a/52002
 * ISO/IEC 9899:1990 C standard (page 324-325): http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1124.pdf
 *
 * For this test, the seeds used are entirely insecure, assume that this is a
 * securely generated seed (has truly random entropy). An exploit for insecure
 * seeds (specifically using time()) can be found in seed_time.c
 *
 * It can be shown that although using a secure seed adds security, it is not much.
 * seed_time.c needs only 2^27 tests to check a 4 year period of keys generated using time(),
 * while periodicity.c needs at most 2^31, because all possible seeds should be tested.
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

#include "aes.h"

/* Portable definition of rand() from ISO/IEC 9899:1990 C standard */
static uint32_t next = 1;
int prand(void) { // RAND_MAX assumed to be 32767
	// The period is 2^31 due to the choice of 1103515245
    next = next * 1103515245 + 12345;
    return (uint32_t)(next/65536) % 32768;
}
void psrand(uint32_t seed) {
    next = seed;
}

/* Generates a random 16 byte key using prand() for each byte */
void genKey(uint8_t *buf, int len) {
	for(int i = 0; i < len; i++) {
		buf[i] = prand() % 0x100;
	}
}

int main(void) {
	// plaintext sample
	const char *PLAINTEXT = "this message starts with \"thi\"!\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	const char *SEARCHSTR = "thi"; // The text to search for
	int n = strlen(PLAINTEXT);
	int m = strlen(SEARCHSTR);
	char ciphertext[64] = {0};
	char buffer[64] = {0};
	uint8_t key[16];
	int ctr = 0, p = 0;
	
	srand(time(0));
	psrand(rand());
	genKey(key, 16); // Generate the key for the original cipher
	AES_ECB_encrypt(PLAINTEXT, key, ciphertext, n + n %16); // Generate ciphertext
	
	for(uint32_t seed = 0; seed < 2147483648 /* 2^31 */; seed ++) {
		// Seed the PRNG
		psrand(seed);
		// Generate a new key
		genKey(key, 16);
		// Decrypt the ciphertext
		AES_ECB_decrypt(ciphertext, key, buffer, n + n % 16);
		// Print any possible matches
		if(strncmp(buffer, SEARCHSTR, m) == 0) {
			printf("Possible match (%d): %s\n", seed, buffer);
		}
		ctr ++;
		if(ctr >= 1474836) {
			ctr = 0; 
			p ++;
			printf("~%.1f%% Completed\n", (float)p/10);
		}
	}
	
	return EXIT_SUCCESS;
}
