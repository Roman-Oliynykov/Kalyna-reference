/*

Constant and basic transformations for the reference implementation of the Kalyna block cipher (DSTU 7624:2014)

Authors: Ruslan Kiianchuk, Ruslan Mordvinov, Roman Oliynykov

*/

#ifndef KALYNA_DEFS_H
#define KALYNA_DEFS_H


#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <limits.h>

#include "kalyna.h"


#if (ULLONG_MAX != 0xFFFFFFFFFFFFFFFFULL)
#error "Architecture not supported. Required type to fit 64 bits."
#endif

#define kBITS_IN_WORD 64

#if (CHAR_BIT != 8)
#error "Architecture not supported. Required type to fit 8 bits."
#endif

#define kBITS_IN_BYTE 8

#define TRUE 1
#define FALSE 0

/* Block words size. */
#define kNB_128 2
#define kNB_256 4
#define kNB_512 8

/* Key words size. */
#define kNK_128 2
#define kNK_256 4
#define kNK_512 8

/* Block bits size. */
#define kBLOCK_128 kNB_128 * kBITS_IN_WORD
#define kBLOCK_256 kNB_256 * kBITS_IN_WORD
#define kBLOCK_512 kNB_512 * kBITS_IN_WORD

/* Block bits size. */
#define kKEY_128 kNK_128 * kBITS_IN_WORD
#define kKEY_256 kNK_256 * kBITS_IN_WORD
#define kKEY_512 kNK_512 * kBITS_IN_WORD

/* Number of enciphering rounds size depending on key length. */
#define kNR_128 10
#define kNR_256 14
#define kNR_512 18

#define kREDUCTION_POLYNOMIAL 0x011d  /* x^8 + x^4 + x^3 + x^2 + 1 */

/*!
 * Index a byte array as cipher state matrix.
 */
#define INDEX(table, row, col) table[(row) + (col) * sizeof(uint64_t)]


/*!
 * Substitute each byte of the cipher state using corresponding S-Boxes.
 *
 * @param ctx Initialized cipher context with current state and round keys 
 * precomputed.
 */
void SubBytes(kalyna_t* ctx);

/*!
 * Inverse SubBytes transformation.
 *
 * @param ctx Initialized cipher context with current state and round keys 
 * precomputed.
 */
void InvSubBytes(kalyna_t* ctx);

/*!
 * Shift cipher state rows according to specification.
 *
 * @param ctx Initialized cipher context with current state and round keys 
 * precomputed.
 */
void ShiftRows(kalyna_t* ctx);

/*!
 * Inverse ShiftRows transformation.
 *
 * @param ctx Initialized cipher context with current state and round keys 
 * precomputed.
 */
void InvShiftRows(kalyna_t* ctx);

/*!
 * Multiply bytes in Finite Field GF(2^8).
 *
 * @param x Multiplicand element of GF(2^8).
 * @param y Multiplier element of GF(2^8) from MDS matrix.
 * @return Product of multiplication in GF(2^8).
 */                                                         
uint8_t MultiplyGF(uint8_t x, uint8_t y);


/*!
 * Multiply cipher state by specified MDS matrix. 
 * Used to avoid code repetition for MixColumn and Inverse MixColumn.
 *
 * @param ctx Initialized cipher context with current state and round keys 
 * precomputed.
 * @param matrix MDS 8x8 byte matrix.
 */
void MatrixMultiply(kalyna_t* ctx, uint8_t matrix[8][8]);

/*!
 * Perform MixColumn transformation to the cipher state.
 *
 * @param ctx Initialized cipher context with current state and round keys 
 * precomputed.
 */
void MixColumns(kalyna_t* ctx);

/*!
 * Inverse MixColumn transformation.
 *
 * @param ctx Initialized cipher context with current state and round keys 
 * precomputed.
 */
void InvMixColumns(kalyna_t* ctx);

/*!
 * Perform single round enciphering routine.
 *
 * @param ctx Initialized cipher context with current state and round keys 
 * precomputed.
 */
void EncipherRound(kalyna_t* ctx);

/*!
 * Perform single round deciphering routine.
 *
 * @param ctx Initialized cipher context with current state and round keys 
 * precomputed.
 */
void DecipherRound(kalyna_t* ctx);


/*!
 * Inject round key into the state using addition modulo 2^{64}.
 *
 * @param round Number of the round on which the key addition is performed in
 * order to use the correct round key.
 * @param ctx Initialized cipher context with current state and round keys 
 * precomputed.
 */
void AddRoundKey(int round, kalyna_t* ctx);

/*!
 * Extract round key from the state using subtraction modulo 2^{64}.
 *
 * @param round Number of the round on which the key subtraction is performed 
 * in order to use the correct round key.
 * @param ctx Initialized cipher context with current state and round keys 
 * precomputed.
 */
void SubRoundKey(int round, kalyna_t* ctx);

/*!
 * Perform addition of two arbitrary states modulo 2^{64}.
 * The operation is identical to simple round key addition but on arbitrary 
 * state array and addition value (instead of the actual round key). Used in
 * key expansion procedure. The result is stored in `state`.
 * 
 * @param ctx Initialized cipher context with current state and round keys 
 * precomputed.
 * @param value Is to be added to the state array modulo 2^{64}.
 */
void AddRoundKeyExpand(uint64_t* value, kalyna_t* ctx);

/*!
 * Inject round key into the state using XOR operation.
 *
 * @param round Number of the round on which the key addition is performed in
 * order to use the correct round key.
 * @param ctx Initialized cipher context with current state and round keys 
 * precomputed.
 */
void XorRoundKey(int round, kalyna_t* ctx);

/*!
 * Perform XOR of two arbitrary states.
 * The operation is identical to simple round key XORing but on arbitrary 
 * state array and addition value (instead of the actual round key). Used in
 * key expansion procedure. The result is stored in `state`.
 * XOR operation is involutive so no inverse transformation is required.
 * 
 * @param ctx Initialized cipher context with current state and round keys 
 * precomputed.
 * @param value Is to be added to the state array modulo 2^{64}.
 */
void XorRoundKeyExpand(uint64_t* value, kalyna_t* ctx);

/*!
 * Rotate words of a state.
 * The state is processed as 64-bit words array {w_{0}, w_{1}, ..., w_{nk-1}}
 * and rotation is performed so the resulting state is 
 * {w_{1}, ..., w_{nk-1}, w_{0}}.
 *
 * @param ctx Initialized cipher context with current state and round keys 
 * precomputed.
 * @param state_value A state represented by 64-bit words array of length Nk.
 * It is not the cipher state that is used during enciphering.
 */
void Rotate(size_t state_size, uint64_t* state_value);

/*!
 * Shift each word one bit to the left.
 * The shift of each word is independent of other array words.
 *
 * @param state_size Size of the state to be shifted. 
 * @param state_value State represented as 64-bit words array.  Note that this 
 * state Nk words long and differs from the cipher state used during 
 * enciphering.
 */
void ShiftLeft(size_t state_size, uint64_t* state_value);

/*!
 * Rotate the state (2 * Nb + 3) bytes to the left.
 * The state is interpreted as bytes string in little endian. Big endian
 * architectures are also correctly processed by this function.
 *
 * @param ctx Initialized cipher context with current state and round keys 
 * precomputed.
 * @param state_value A state represented by 64-bit words array of length Nk.
 * It is not the cipher state that is used during enciphering.
 */
void RotateLeft(size_t state_size, uint64_t* state_value);

/*!
 * Generate the Kt value (auxiliary key used in key expansion).
 *
 * @param ctx Initialized cipher context with current state and round keys 
 * precomputed.
 * @param key Enciphering key of size corresponding to the one stored in cipher
 * context `ctx` (specified via KalynaInit() function).
 * @param kt Array for storing generated Kt value.
 */
void KeyExpandKt(uint64_t* key, kalyna_t* ctx, uint64_t* kt);


/*!
 * Compute even round keys and store them in cipher context `ctx`.
 *
 * @param key Kalyna enciphering key of length Nk 64-bit words.
 * @param kt Kalyna auxiliary key. The size is equal to enciphering state
 * size and equals Nb 64-bit words.
 * @param ctx Initialized cipher context.
 */
void KeyExpandEven(uint64_t* key, uint64_t* kt, kalyna_t* ctx);

/*!
 * Compute odd round keys by rotating already generated even ones and
 * fill in the rest of the round keys in cipher context `ctx`.
 *
 * @param ctx Initialized cipher context.
 */
void KeyExpandOdd(kalyna_t* ctx);

/*!
 * Convert array of 64-bit words to array of bytes.
 * Each word is interpreted as byte sequence following little endian
 * convention. However a check for big endian and corresponding word reversion
 * is performed if needed.
 *
 * @param length Length of 64-bit words array.
 * @param words Pointer to 64-bit words array.
 * @return Pointer to bytes array.
 */
uint8_t* WordsToBytes(size_t length, uint64_t* words);

/*!
 * Convert array of bytes to array of 64-bit words.
 * Each word is interpreted as byte sequence following little endian
 * convention. However a check for big endian and corresponding word reversion
 * is performed if needed.
 *
 * @param length Length of bytes array.
 * @param words Pointer to bytes array.
 * @return Pointer to 64-bit words array.
 */
uint64_t* BytesToWords(size_t length, uint8_t* bytes);

/*!
 * Reverse bytes ordering that form the word.
 *
 * @param word 64-bit word that needs its bytes to be reversed (perhaps for
 * converting between little and big endian).
 * @return 64-bit word with reversed bytes.
 */
uint64_t ReverseWord(uint64_t word);

/*!
 * Check if architecture follows big endian convention.
 *
 * @return 1 if architecture is big endian, 0 if it is little endian.
 */
int IsBigEndian();

/*!
 * Print specified cipher state (or any similar array) to stdout.
 *
 * @param length Length of the words array.
 * @param state State represented as words array.
 */
void PrintState(size_t length, uint64_t* state);

#endif  /* KALYNA_DEFS_H */

