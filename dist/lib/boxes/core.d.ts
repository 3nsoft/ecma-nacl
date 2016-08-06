/**
 * Analog of crypto_core in crypto_core/salsa20/ref/core.c
 * It makes nicer, shorter code to have variables of this function sitting in
 * one array, but expanded version runs faster.
 * We inlined load_littleendian(() & store_littleendian(), and rotate()
 * functions from the original source.
 * @param out is Uint8Array, 64 bytes long, into which result is placed.
 * @param inArr is Uint8Array, 16 bytes long, of incoming bytes.
 * @param k is Uint8Array, 32 bytes long.
 * @param c is Uint8Array, 16 bytes long.
 */
export declare function salsa20(out: Uint8Array, inArr: Uint8Array, k: Uint8Array, c: Uint8Array): void;
/**
 * Analog of crypto_core in crypto_core/hsalsa20/ref2/core.c
 * It makes nicer, shorter code to have variables of this function sitting in
 * one array, but expanded version runs faster.
 * We inlined load_littleendian(() & store_littleendian(), and rotate()
 * functions from the original source.
 * @param out is Uint8Array, 32 bytes long, into which result is placed.
 * @param inArr is Uint8Array, 16 bytes long, of incoming bytes.
 * @param k is Uint8Array, 32 bytes long.
 * @param c is Uint8Array, 16 bytes long.
 */
export declare function hsalsa20(out: Uint8Array, inArr: Uint8Array, k: Uint8Array, c: Uint8Array): void;
