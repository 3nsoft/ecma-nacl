/**
 * @param x is typed array
 * @param y is typed array, of the same length as x
 * @param n is number of element to compare, starting from each arrays head.
 * If this number is greater than length of given arrays, behaviour is undefined.
 * Therefore, users of this function must check lengths of given arrays
 * before calling this function.
 * It also implies that this function cannot be directly expose by the library.
 * @returns true when n first elements of arrays were found to correspond in each array,
 *          and false otherwise.
 *          Notice, that C's crypto_verify 16 and 32 return 0 (falsy value), for same elements,
 *          and -1 (truethy value), for different elements.
 */
export declare function verify(x: any, y: any, len: number): boolean;
/**
 * @param x is typed array
 * @param y is typed array, of the same length as x
 * @returns true when 16 first elements of arrays were found to correspond in each array,
 *          and false otherwise.
 *          Notice, that C's crypto_verify 16 and 32 return 0 (falsy value), for same elements,
 *          and -1 (truethy value), for different elements.
 */
export declare function v16(x: any, y: any): boolean;
/**
 * @param x is typed array
 * @param y is typed array, of the same length as x
 * @returns true when 32 first elements of arrays were found to correspond in each array,
 *          and false otherwise.
 *          Notice, that C's crypto_verify 16 and 32 return 0 (falsy value), for same elements,
 *          and -1 (truethy value), for different elements.
 */
export declare function v32(x: any, y: any): boolean;
