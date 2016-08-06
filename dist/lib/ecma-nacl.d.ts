/**
 * This file is an external interface of Ecma-NaCl library.
 */
export import secret_box = require('./boxes/secret_box');
export import box = require('./boxes/box');
export import nonce = require('./util/nonce');
export import signing = require('./signing/sign');
import sha512Mod = require('./hash/sha512');
export declare module hashing.sha512 {
    var hash: typeof sha512Mod.hash;
    var makeHasher: typeof sha512Mod.makeHasher;
}
import scryptMod = require('./scrypt/scrypt');
export declare var scrypt: typeof scryptMod.scrypt;
export import arrays = require('./util/arrays');
/**
 * @param x typed array
 * @param y typed array
 * @returns true, if arrays have the same length and their elements are equal;
 * and false, otherwise.
 */
export declare function compareVectors(x: any, y: any): boolean;
export interface GetRandom {
    (n: number): Uint8Array;
}
