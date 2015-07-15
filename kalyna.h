/*

Header file for the reference implementation of the Kalyna block cipher (DSTU 7624:2014), all block and key length variants

Authors: Ruslan Kiianchuk, Ruslan Mordvinov, Roman Oliynykov

*/

#ifndef KALYNA_H
#define KALYNA_H


#include <stdlib.h>
#include <string.h>


typedef unsigned char uint8_t;
typedef unsigned long long uint64_t;

/*!
 * Context to store Kalyna cipher parameters.
 */
typedef struct {
    size_t nb;  /**< Number of 64-bit words in enciphering block. */ 
    size_t nk;  /**< Number of 64-bit words in key. */
    size_t nr;  /**< Number of enciphering rounds. */
    uint64_t* state;  /**< Current cipher state. */
    uint64_t** round_keys;  /**< Round key computed from enciphering key. */
} kalyna_t;


/*!
 * Initialize Kalyna parameters and create cipher context.
 *
 * @param block_size Enciphering block bit size (128, 256 or 512 bit sizes are 
 * allowed).
 * @param block_size Enciphering key bit size. Must be equal or double the
 * block bit size.
 * @return Pointer to Kalyna context containing cipher instance
 * parameters and allocated memory for state and round keys. NULL in case of
 * error.
 */
kalyna_t* KalynaInit(size_t block_size, size_t key_size);

/*!
 * Delete Kalyna cipher context and free used memory.
 *
 * @param ctx Kalyna cipher context.
 * @return Zero in case of success.
 */
int KalynaDelete(kalyna_t* ctx);

/*!
 * Compute round keys given the enciphering key and store them in cipher
 * context `ctx`.
 *
 * @param key Kalyna enciphering key.
 * @param ctx Initialized cipher context.
 */
void KalynaKeyExpand(uint64_t* key, kalyna_t* ctx);

/*!
 * Encipher plaintext using Kalyna symmetric block cipher.
 * KalynaInit() function with appropriate block and enciphering key sizes must
 * be called beforehand to get the cipher context `ctx`. After all enciphering
 * is completed KalynaDelete() must be called to free up allocated memory.
 *
 * @param plaintext Plaintext of length Nb words for enciphering.
 * @param ctx Initialized cipher context with precomputed round keys.
 * @param ciphertext The result of enciphering.
 */
void KalynaEncipher(uint64_t* plaintext, kalyna_t* ctx, uint64_t* ciphertext);

/*!
 * Decipher ciphertext using Kalyna symmetric block cipher.
 * KalynaInit() function with appropriate block and enciphering key sizes must
 * be called beforehand to get the cipher context `ctx`. After all enciphering
 * is completed KalynaDelete() must be called to free up allocated memory.
 *
 * @param ciphertext Enciphered data of length Nb words.
 * @param ctx Initialized cipher context with precomputed round keys.
 * @param plaintext The result of deciphering.
 */
void KalynaDecipher(uint64_t* ciphertext, kalyna_t* ctx, uint64_t* plaintext);

#endif  /* KALYNA_H */

