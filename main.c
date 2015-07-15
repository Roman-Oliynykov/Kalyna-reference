/*

main.c, printing test vectors of reference implementation of the Kalyna block cipher (DSTU 7624:2014), all block and key length variants

Authors: Ruslan Kiianchuk, Ruslan Mordvinov, Roman Oliynykov

*/

#include <stdio.h>
#include <memory.h>

#include "kalyna.h"
#include "transformations.h"

void print (int data_size, uint64_t data []);

int main(int argc, char** argv) {
   
	int i;
	kalyna_t* ctx22_e = KalynaInit(128, 128);
	kalyna_t* ctx24_e = KalynaInit(128, 256);
	kalyna_t* ctx44_e = KalynaInit(256, 256);
	kalyna_t* ctx48_e = KalynaInit(256, 512);
	kalyna_t* ctx88_e = KalynaInit(512, 512);

    uint64_t pt22_e[2] = {0x1716151413121110ULL, 0x1f1e1d1c1b1a1918ULL};
	uint64_t ct22_e[2];
    uint64_t key22_e[2] = {0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL};
    uint64_t expect22_e[2] = {0x20ac9b777d1cbf81ULL, 0x06add2b439eac9e1ULL};

    uint64_t pt24_e[2] = {0x2726252423222120ULL, 0x2f2e2d2c2b2a2928ULL};
	uint64_t ct24_e[2];
    uint64_t key24_e[4] = {0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL, 0x1716151413121110ULL, 0x1f1e1d1c1b1a1918ULL};
    uint64_t expect24_e[2] = { 0x8a150010093eec58ULL, 0x144f336f16f74811ULL};

    uint64_t pt44_e[4] = {0x2726252423222120ULL, 0x2f2e2d2c2b2a2928ULL, 0x3736353433323130ULL, 0x3f3e3d3c3b3a3938ULL};
	uint64_t ct44_e[4];
    uint64_t key44_e[4] = {0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL, 0x1716151413121110ULL, 0x1f1e1d1c1b1a1918ULL};
    uint64_t expect44_e[4] = {0x3521c90e573d6ef6ULL, 0x8c2abddc23e3daaeULL, 0x5a0d6a20ec6339a0ULL, 0x2cd97f61245c3888ULL};

    uint64_t pt48_e[4] = {0x4746454443424140ULL, 0x4f4e4d4c4b4a4948ULL, 0x5756555453525150ULL, 0x5f5e5d5c5b5a5958ULL};
	uint64_t ct48_e[4];
    uint64_t key48_e[8] = {0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL, 0x1716151413121110ULL, 0x1f1e1d1c1b1a1918ULL,
							0x2726252423222120ULL, 0x2f2e2d2c2b2a2928ULL, 0x3736353433323130ULL, 0x3f3e3d3c3b3a3938ULL};
    uint64_t expect48_e[4] = {0x7ab6b7e6e9906960ULL, 0xb76822d793d8d64bULL, 0x02e1d73c3cc8028eULL, 0xd95dfefda8742efdULL};


    uint64_t pt88_e[8] = {  0x4746454443424140ULL, 0x4f4e4d4c4b4a4948ULL, 0x5756555453525150ULL, 0x5f5e5d5c5b5a5958ULL,
									0x6766656463626160ULL, 0x6f6e6d6c6b6a6968ULL, 0x7776757473727170ULL, 0x7f7e7d7c7b7a7978ULL};
	uint64_t ct88_e[8];
    uint64_t key88_e[8] = {		0x0706050403020100ULL, 0x0f0e0d0c0b0a0908ULL, 0x1716151413121110ULL, 0x1f1e1d1c1b1a1918ULL,
									0x2726252423222120ULL, 0x2f2e2d2c2b2a2928ULL, 0x3736353433323130ULL, 0x3f3e3d3c3b3a3938ULL};
    uint64_t expect88_e[8] = {     0x6a351c811be3264aULL, 0x1a239605cad61da6ULL, 0xa1f347aa5483ba67ULL, 0xb856eb20c3ee1d3eULL,
									0x66ab5b1717f4d095ULL, 0x6cc815bb34f1d62fULL, 0xb7fe6e85266a90cbULL, 0xd9d90d947264bcc5ULL};

	uint64_t ct22_d[2] = {0x18191a1b1c1d1e1fULL, 0x1011121314151617ULL};
	uint64_t pt22_d[2];
    uint64_t key22_d[2] = {0x08090a0b0c0d0e0fULL, 0x0001020304050607ULL};
    uint64_t expect22_d[2] = {0x84c70c472bef9172ULL, 0xd7da733930c2096fULL};

	uint64_t ct24_d[2] = {0x28292a2b2c2d2e2fULL, 0x2021222324252627ULL};
	uint64_t pt24_d[2];
    uint64_t key24_d[4] = {0x18191a1b1c1d1e1fULL, 0x1011121314151617ULL, 0x08090a0b0c0d0e0fULL, 0x0001020304050607ULL};
    uint64_t expect24_d[2] = {0xe1dffdce56b46df3ULL, 0x96d9ca30705f5bb4ULL};

	uint64_t ct44_d[4] = {0x38393a3b3c3d3e3fULL, 0x3031323334353637ULL, 0x28292a2b2c2d2e2fULL, 0x2021222324252627ULL};
	uint64_t pt44_d[4];
    uint64_t key44_d[4] = {0x18191a1b1c1d1e1fULL, 0x1011121314151617ULL, 0x08090a0b0c0d0e0fULL, 0x0001020304050607ULL};
    uint64_t expect44_d[4] = {0x864e67967823c57fULL, 0xa34b8b3fb0e9c103ULL, 0xd3c33f2c597c5babULL, 0xe30fb28625d1ed61ULL};

	uint64_t ct48_d[4] = {0x58595a5b5c5d5e5fULL, 0x5051525354555657ULL, 0x48494a4b4c4d4e4fULL, 0x4041424344454647ULL};
	uint64_t pt48_d[4];
    uint64_t key48_d[8] = {0x38393a3b3c3d3e3fULL, 0x3031323334353637ULL, 0x28292a2b2c2d2e2fULL, 0x2021222324252627ULL,
						0x18191a1b1c1d1e1fULL, 0x1011121314151617ULL, 0x08090a0b0c0d0e0fULL, 0x0001020304050607ULL};
    uint64_t expect48_d[4] = {0x82d4da67277a3118ULL, 0x078d78a1b907cdbcULL, 0x97845f9e1898705eULL, 0xe06aba796d910b2dULL};

	uint64_t ct88_d[8] = {0x78797a7b7c7d7e7fULL, 0x7071727374757677ULL, 0x68696a6b6c6d6e6fULL, 0x6061626364656667ULL,
						0x58595a5b5c5d5e5fULL, 0x5051525354555657ULL, 0x48494a4b4c4d4e4fULL, 0x4041424344454647ULL};
	uint64_t pt88_d[8];
    uint64_t key88_d[8] = {0x38393a3b3c3d3e3fULL, 0x3031323334353637ULL, 0x28292a2b2c2d2e2fULL, 0x2021222324252627ULL,
						0x18191a1b1c1d1e1fULL, 0x1011121314151617ULL, 0x08090a0b0c0d0e0fULL, 0x0001020304050607ULL};
    uint64_t expect88_d[8] = {0x5252a025338480ceULL, 0x29d8a9e614d7ea1bULL, 0xbd45a8e90e1e38fdULL, 0xa346fad954450492ULL,
						0xf2b13b85dbef7f75ULL, 0x6ae6753b839dff97ULL, 0xdc1b29b5ab5741afULL, 0x22ff5aaa13bb94f0ULL };

	kalyna_t* ctx22_d = KalynaInit(128, 128);
	kalyna_t* ctx24_d = KalynaInit(128, 256);
	kalyna_t* ctx44_d = KalynaInit(256, 256);
	kalyna_t* ctx48_d = KalynaInit(256, 512);
	kalyna_t* ctx88_d = KalynaInit(512, 512);

	// kalyna 22 enc
	KalynaKeyExpand(key22_e, ctx22_e);

    printf("\n=============\n");
    printf("Kalyna (%lu, %lu)\n", ctx22_e->nb * 64, ctx22_e->nk * 64);
   
	printf("\n--- ENCIPHERING ---\n");
    printf("Key:\n");
    print(ctx22_e->nk, key22_e);

    printf("Plaintext:\n");
    print(ctx22_e->nb, pt22_e);

    KalynaEncipher(pt22_e, ctx22_e, ct22_e);
    printf("Ciphertext:\n");
    print(ctx22_e->nb, ct22_e);

	if (memcmp(ct22_e, expect22_e, sizeof(ct22_e)) != 0) printf("Failed enciphering\n");
	else printf("Success enciphering\n\n");

	KalynaDelete(ctx22_e);

	// kalyna 22 dec
	KalynaKeyExpand(key22_d, ctx22_d);

    printf("\n=============\n");
    printf("Kalyna (%lu, %lu)\n", ctx22_d->nb * 64, ctx22_d->nk * 64);
   
	printf("\n--- DECIPHERING ---\n");
    printf("Key:\n");
    print(ctx22_d->nk, key22_d);

	printf("Ciphertext:\n");
    print(ctx22_d->nb, ct22_d);

	KalynaDecipher(ct22_d, ctx22_d, pt22_d);
    printf("Plaintext:\n");
    print(ctx22_d->nb, pt22_d);

	if (memcmp(pt22_d, expect22_d, sizeof(pt22_d)) != 0) printf("Failed deciphering\n");
	else printf("Success deciphering\n\n");

	KalynaDelete(ctx22_d);
	
	// kalyna 24 enc
	KalynaKeyExpand(key24_e, ctx24_e);

    printf("\n=============\n");
    printf("Kalyna (%lu, %lu)\n", ctx24_e->nb * 64, ctx24_e->nk * 64);

    printf("\n--- ENCIPHERING ---\n");
    printf("Key:\n");
    print(ctx24_e->nk, key24_e);

    printf("Plaintext:\n");
    print(ctx24_e->nb, pt24_e);

    KalynaEncipher(pt24_e, ctx24_e, ct24_e);
    printf("Ciphertext:\n");
    print(ctx24_e->nb, ct24_e);

	if (memcmp(ct24_e, expect24_e, sizeof(ct24_e)) != 0) printf("Failed enciphering\n");
	else printf("Success enciphering\n\n");

	KalynaDelete(ctx24_e);

	// kalyna 24 dec
	KalynaKeyExpand(key24_d, ctx24_d);

    printf("\n=============\n");
    printf("Kalyna (%lu, %lu)\n", ctx24_d->nb * 64, ctx24_d->nk * 64);
   
	printf("\n--- DECIPHERING ---\n");
    printf("Key:\n");
    print(ctx24_d->nk, key24_d);

	printf("Ciphertext:\n");
    print(ctx24_d->nb, ct24_d);

	KalynaDecipher(ct24_d, ctx24_d, pt24_d);
    printf("Plaintext:\n");
    print(ctx24_d->nb, pt24_d);

	if (memcmp(pt24_d, expect24_d, sizeof(pt24_d)) != 0) printf("Failed deciphering\n");
	else printf("Success deciphering\n\n");

	KalynaDelete(ctx24_d);

	// kalyna 44 enc
	KalynaKeyExpand(key44_e, ctx44_e);

    printf("\n=============\n");
    printf("Kalyna (%lu, %lu)\n", ctx44_e->nb * 64, ctx44_e->nk * 64);

    printf("\n--- ENCIPHERING ---\n");
    printf("Key:\n");
    print(ctx44_e->nk, key44_e);

    printf("Plaintext:\n");
    print(ctx44_e->nb, pt44_e);

    KalynaEncipher(pt44_e, ctx44_e, ct44_e);
    printf("Ciphertext:\n");
    print(ctx44_e->nb, ct44_e);

	if (memcmp(ct44_e, expect44_e, sizeof(ct44_e)) != 0) printf("Failed enciphering\n");
	else printf("Success enciphering\n\n");

	KalynaDelete(ctx44_e);

	// kalyna 44 dec
	KalynaKeyExpand(key44_d, ctx44_d);

    printf("\n=============\n");
    printf("Kalyna (%lu, %lu)\n", ctx44_d->nb * 64, ctx44_d->nk * 64);
   
	printf("\n--- DECIPHERING ---\n");
    printf("Key:\n");
    print(ctx44_d->nk, key44_d);

	printf("Ciphertext:\n");
    print(ctx44_d->nb, ct44_d);

	KalynaDecipher(ct44_d, ctx44_d, pt44_d);
    printf("Plaintext:\n");
    print(ctx44_d->nb, pt44_d);

	if (memcmp(pt44_d, expect44_d, sizeof(pt44_d)) != 0) printf("Failed deciphering\n");
	else printf("Success deciphering\n\n");

	KalynaDelete(ctx44_d);

	// kalyna 48 enc
	KalynaKeyExpand(key48_e, ctx48_e);

    printf("\n=============\n");
    printf("Kalyna (%lu, %lu)\n", ctx48_e->nb * 64, ctx48_e->nk * 64);
   
    printf("\n--- ENCIPHERING ---\n");
    printf("Key:\n");
    print(ctx48_e->nk, key48_e);

    printf("Plaintext:\n");
    print(ctx48_e->nb, pt48_e);

    KalynaEncipher(pt48_e, ctx48_e, ct48_e);
    printf("Ciphertext:\n");
    print(ctx48_e->nb, ct48_e);

	if (memcmp(ct48_e, expect48_e, sizeof(ct48_e)) != 0) printf("Failed enciphering\n");
	else printf("Success enciphering\n\n");

	KalynaDelete(ctx48_e);

	// kalyna 48 dec
	KalynaKeyExpand(key48_d, ctx48_d);

    printf("\n=============\n");
    printf("Kalyna (%lu, %lu)\n", ctx48_d->nb * 64, ctx48_d->nk * 64);
   
	printf("\n--- DECIPHERING ---\n");
    printf("Key:\n");
    print(ctx48_d->nk, key48_d);

	printf("Ciphertext:\n");
    print(ctx48_d->nb, ct48_d);

	KalynaDecipher(ct48_d, ctx48_d, pt48_d);
    printf("Plaintext:\n");
    print(ctx48_d->nb, pt48_d);

	if (memcmp(pt48_d, expect48_d, sizeof(pt48_d)) != 0) printf("Failed deciphering\n");
	else printf("Success deciphering\n\n");

	KalynaDelete(ctx48_d);

	// kalyna 88 enc
	KalynaKeyExpand(key88_e, ctx88_e);

    printf("\n=============\n");
    printf("Kalyna (%lu, %lu)\n", ctx88_e->nb * 64, ctx88_e->nk * 64);

    printf("\n--- ENCIPHERING ---\n");
    printf("Key:\n");
    print(ctx88_e->nk, key88_e);

    printf("Plaintext:\n");
    print(ctx88_e->nb, pt88_e);

    KalynaEncipher(pt88_e, ctx88_e, ct88_e);
    printf("Ciphertext:\n");
    print(ctx88_e->nb, ct88_e);

	if (memcmp(ct88_e, expect88_e, sizeof(ct88_e)) != 0) printf("Failed enciphering\n");
	else printf("Success enciphering\n\n");

	KalynaDelete(ctx88_e);

	// kalyna 88 dec
	KalynaKeyExpand(key88_d, ctx88_d);

    printf("\n=============\n");
    printf("Kalyna (%lu, %lu)\n", ctx88_d->nb * 64, ctx88_d->nk * 64);
   
	printf("\n--- DECIPHERING ---\n");
    printf("Key:\n");
    print(ctx88_d->nk, key88_d);

	printf("Ciphertext:\n");
    print(ctx88_d->nb, ct88_d);

	KalynaDecipher(ct88_d, ctx88_d, pt88_d);
    printf("Plaintext:\n");
    print(ctx88_d->nb, pt88_d);

	if (memcmp(pt88_d, expect88_d, sizeof(pt88_d)) != 0) printf("Failed deciphering\n");
	else printf("Success deciphering\n\n");

	KalynaDelete(ctx88_d);

    return 0;
}


void print (int data_size, uint64_t data [])
{
	int i;
	uint8_t * tmp = (uint8_t *) data; 
	for (i = 0; i < data_size * 8; i ++)
	{
		if (! (i % 16)) printf ("    ");
		printf ("%02X", (unsigned int) tmp [i]);
		if (!((i + 1) % 16)) printf ("\n");
	};
	printf ("\n");
};
