export interface Factory {
    /**
     * This either creates new, or gets a spare array from the pool.
     * Newly created array is not put into pool, because it is given to someone
     * for use.
     * If someone forgets to return it, there shall be no leaking references.
     * @param len is number of elements in desired array.
     * @returns Uint8Array, with given number of elements in it.
     */
    getUint8Array(len: number): Uint8Array;
    /**
     * This either creates new, or gets a spare array from the pool.
     * Newly created array is not put into pool, because it is given to someone for use.
     * If someone forgets to return it, there shall be no leaking references.
     * @param len is number of elements in desired array.
     * @returns Uint32Array, with given number of elements in it.
     */
    getUint32Array(len: number): Uint32Array;
    /**
     * This puts given arrays into the pool (note: it does not zero elements).
     * Use this function for those arrays that shall be reused, due to having
     * common to your application size, and, correspondingly, do not use it on
     * odd size arrays.
     * This function takes any number of unsigned arrays, that need to be
     * recycled.
     * When you need to just wipe an array, or wipe a particular view of an
     * array, use wipe() method.
     */
    recycle(...arrays: any[]): void;
    /**
     * This wipes (sets to zeros) all arrays that are located in pools
     */
    wipeRecycled(): void;
    /**
     * This drops all arrays from pools, letting GC to pick them up,
     * even if reference to this factory is hanging somewhere.
     */
    clear(): void;
    /**
     * This zeros all elements of given arrays, or given array views.
     * Use this function on things that needs secure cleanup, but should not be
     * recycled due to their odd and/or huge size, as it makes pooling inefficient.
     */
    wipe(...arrays: any[]): void;
}
export declare function makeFactory(): Factory;
/**
 * This zeros all elements of given arrays, or given array views.
 * Use this function on things that needs secure cleanup, but should not be
 * recycled due to their odd and/or huge size, as it makes pooling inefficient.
 */
export declare function wipe(...arrays: any[]): void;
