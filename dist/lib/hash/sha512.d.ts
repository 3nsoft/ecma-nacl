import arrays = require('../util/arrays');
/**
 * Analog of crypto_hash in crypto_hash/sha512/ref/hash.c
 * with ending part of make hash of padded arranged into its
 * own function.
 */
export declare function hash(inArr: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
export interface Hasher {
    /**
     * This absorbs bytes as they stream in, hashing even blocks.
     */
    update(m: Uint8Array): void;
    /**
     * This method tells a hasher that there are no more bytes to hash,
     * and that a final hash should be produced.
     * This also forgets all of hasher's state.
     * And if this hasher is not single-use, update can be called
     * again to produce hash for a new stream of bytes.
     */
    digest(): Uint8Array;
    /**
     * This method securely wipes internal state, and drops resources, so that
     * memory can be GC-ed.
     */
    destroy(): void;
}
export declare function makeHasher(isSingleUse?: boolean, arrFactory?: arrays.Factory): Hasher;
