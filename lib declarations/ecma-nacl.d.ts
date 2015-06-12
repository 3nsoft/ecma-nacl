/**
 * This file is an external interface of Ecma-NaCl library.
 */

declare module EcmaNacl {
	/**
	/** Analog of crypto_scrypt in lib/crypto/crypto_scrypt-ref.c
	 * crypto_scrypt(passwd, passwdlen, salt, saltlen, N, r, p, buf, buflen):
	 * Compute scrypt(passwd[0 .. passwdlen - 1], salt[0 .. saltlen - 1], N, r,
	 * p, buflen) and write the result into buf.  The parameters r, p, and buflen
	 * must satisfy r * p < 2^30 and buflen <= (2^32 - 1) * 32.  The parameter N
	 * must be a power of 2.
	 *
	 * Return Uint8Array with result; or throw an error.
	 */
	export function scrypt(passwd: Uint8Array, salt: Uint8Array, logN: number, r: number, p: number, dkLen: number, progressCB: (p: number) => void, arrFactory?: arrays.Factory): Uint8Array;
	/**
	 * @param x typed array
	 * @param y typed array
	 * @returns true, if arrays have the same length and their elements are equal;
	 * and false, otherwise.
	 */
	export function compareVectors(x: any, y: any): boolean;
	export interface GetRandom {
    	(n: number): Uint8Array;
	}
}

declare module EcmaNacl.arrays {
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
	export function makeFactory(): Factory;
	/**
	 * This zeros all elements of given arrays, or given array views.
	 * Use this function on things that needs secure cleanup, but should not be
	 * recycled due to their odd and/or huge size, as it makes pooling inefficient.
	 */
	export function wipe(...arrays: any[]): void;
}

declare module EcmaNacl.secret_box {
	/**
	 * @param m is Uint8Array of message bytes that need to be encrypted by secret key.
	 * @param n is Uint8Array, 24 bytes long nonce.
	 * @param k is Uint8Array, 32 bytes long secret key.
	 * @param arrFactory is typed arrays factory, used to allocated/find an array
	 * for use. It may be undefined, in which case an internally created one is used.
	 * @return Uint8Array with resulting cipher of incoming message, packaged according
	 * to NaCl's xsalsa20+poly1305 secret-box bytes layout, trimmed of initial zeros,
	 * by having a view on array, starting with non-zero part.
	 */
	export function pack(m: Uint8Array, n: Uint8Array, k: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
	/**
	 * Analog of crypto_secretbox_open in crypto_secretbox/xsalsa20poly1305/ref/box.c
	 * with an addition that given cipher should not be padded with zeros, and all
	 * padding happen automagically without copying cipher array.
	 * @param c is Uint8Array of cipher bytes that need to be opened by secret key.
	 * @param n is Uint8Array, 24 bytes long nonce.
	 * @param k is Uint8Array, 32 bytes long secret key.
	 * @param arrFactory is typed arrays factory, used to allocated/find an array
	 * for use. It may be undefined, in which case an internally created one is used.
	 * @return Uint8Array with opened message.
	 * Array is a view of buffer, which has 32 zeros preceding message bytes.
	 */
	export function open(c: Uint8Array, n: Uint8Array, k: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
	/**
	 * This is an encryptor that packs bytes according to "with-nonce" format.
	 */
	export interface Encryptor {
		/**
		 * This encrypts given bytes using internally held nonce, which is
		 * advanced for every packing operation, ensuring that every call will
		 * have a different nonce.
		 * @param m is a byte array that should be encrypted
		 * @return byte array with cipher formatted with nonce
		 */
    	pack(m: Uint8Array): Uint8Array;
		/**
		 * This method securely wipes internal key, and drops resources, so that
		 * memory can be GC-ed.
		 */
    	destroy(): void;
		/**
		 * @return an integer, by which nonce is advanced.
		 */
	    getDelta(): number;
	}
	/**
	 * This is an dencryptor that unpacks bytes from "with-nonce" format.
	 */
	export interface Decryptor {
		/**
		 * @param c is a byte array with cipher, formatted with nonce.
		 * @return decrypted bytes.
		 */
    	open(c: Uint8Array): Uint8Array;
		/**
		 * This method securely wipes internal key, and drops resources, so that
		 * memory can be GC-ed.
		 */
	    destroy(): void;
	}
	export module formatWN {
		/**
		 * @param m is Uint8Array of message bytes that need to be encrypted by secret key.
		 * @param n is Uint8Array, 24 bytes long nonce.
		 * @param k is Uint8Array, 32 bytes long secret key.
		 * @param arrFactory is typed arrays factory, used to allocated/find an array
		 * for use. It may be undefined, in which case an internally created one is used.
		 * @returns Uint8Array, where nonce is packed together with cipher.
		 * Length of the returned array is 40 bytes greater than that of a message.
		 */
    	function pack(m: Uint8Array, n: Uint8Array, k: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
		/**
		 * @param c is Uint8Array with nonce and cipher bytes that need to be opened by secret key.
		 * @param k is Uint8Array, 32 bytes long secret key.
		 * @param arrFactory is typed arrays factory, used to allocated/find an array for use.
		 * It may be undefined, in which case an internally created one is used.
		 * @return Uint8Array with opened message.
		 * Array is a view of buffer, which has 32 zeros preceding message bytes.
		 */
	    function open(c: Uint8Array, k: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
		/**
		 * @param c is Uint8Array with nonce and cipher bytes
		 * @returns Uint8Array, which is a copy of 24-byte nonce from a given array c
		 */
    	function copyNonceFrom(c: Uint8Array): Uint8Array;
		/**
		 *
		 * @param key for new encryptor.
		 * Note that key will be copied, thus, if given array shall never be used anywhere, it should
		 * be wiped after this call.
		 * @param nextNonce is nonce, which should be used for the very first packing.
		 * All further packing will be done with new nonce, as it is automatically evenly advanced.
		 * Note that nextNonce will be copied.
		 * @param delta is a number between 1 and 255 inclusive, used to advance nonce.
		 * When missing, it defaults to one.
		 * @param arrFactory is typed arrays factory, used to allocated/find an array for use.
		 * It may be undefined, in which case an internally created one is used.
		 * @return a frozen object with pack & open functions, and destroy
		 * It is NaCl's secret box for a given key, with automatically evenly advancing nonce.
		 */
	    function makeEncryptor(key: Uint8Array, nextNonce: Uint8Array, delta?: number, arrFactory?: arrays.Factory): Encryptor;
		/**
		 *
		 * @param key for new decryptor.
		 * @param arrFactory is typed arrays factory, used to allocated/find an array for use.
		 * It may be undefined, in which case an internally created one is used.
		 * Note that key will be copied, thus, if given array shall never be used anywhere,
		 * it should be wiped after this call.
		 * @return a frozen object with pack & open and destroy functions.
		 */
    	function makeDecryptor(key: Uint8Array, arrFactory?: arrays.Factory): Decryptor;
	}
	export var NONCE_LENGTH: number;
	export var KEY_LENGTH: number;
	export var POLY_LENGTH: number;
	export var JWK_ALG_NAME: string;
}

declare module EcmaNacl.box {
	/**
	 * Replacement of crypto_box_keypair in
	 * crypto_box/curve25519xsalsa20poly1305/ref/keypair.c
	 * Public key can be generated for any given secret key, which itself should be
	 * randomly generated.
	 * @param sk is Uint8Array of 32 bytes of a secret key.
	 * @param arrFactory is typed arrays factory, used to allocated/find an array
	 * for use. It may be undefined, in which case an internally created one is used.
	 * @returns Uint8Array with 32 bytes of a public key, that corresponds given
	 * secret key.
	 */
	export function generate_pubkey(sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
	/**
	 * Analog of crypto_box_beforenm in
	 * crypto_box/curve25519xsalsa20poly1305/ref/before.c
	 * @param pk is Uint8Array, 32 items long.
	 * @param sk is Uint8Array, 32 items long.
	 * @param arrFactory is typed arrays factory, used to allocated/find an array
	 * for use. It may be undefined, in which case an internally created one is used.
	 * @return Uint8Array with 32 bytes of stream key for the box, under given
	 * public and secret keys.
	 */
	export function calc_dhshared_key(pk: Uint8Array, sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
	/**
	 * Analog of crypto_box in crypto_box/curve25519xsalsa20poly1305/ref/box.c
	 * @param m is Uint8Array of message bytes that need to be encrypted by secret key.
	 * @param n is Uint8Array, 24 bytes long nonce.
	 * @param pk is Uint8Array, 32 bytes long public key of message receiving party.
	 * @param sk is Uint8Array, 32 bytes long secret key of message sending party.
	 * @param arrFactory is typed arrays factory, used to allocated/find an array
	 * for use. It may be undefined, in which case an internally created one is used.
	 * @return Uint8Array with resulting cipher of incoming message, packaged according
	 * to NaCl's xsalsa20+poly1305 secret-box bytes layout, trimmed of initial zeros.
	 */
	export function pack(m: Uint8Array, n: Uint8Array, pk: Uint8Array, sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
	/**
	 * Analog of crypto_box_open in crypto_box/curve25519xsalsa20poly1305/ref/box.c
	 * @param c is Uint8Array of cipher bytes that need to be opened.
	 * @param n is Uint8Array, 24 bytes long nonce.
	 * @param pk is Uint8Array, 32 bytes long public key of message receiving party.
	 * @param sk is Uint8Array, 32 bytes long secret key of message sending party.
	 * @param arrFactory is typed arrays factory, used to allocated/find an array
	 * for use. It may be undefined, in which case an internally created one is used.
	 * @return Uint8Array with decrypted message bytes.
	 * Array is a view of buffer, which has 32 zeros preceding message bytes.
	 * @throws Error when cipher bytes fail verification.
	 */
	export function open(c: Uint8Array, n: Uint8Array, pk: Uint8Array, sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
	export module stream {
    	var pack: typeof secret_box.pack;
	    var open: typeof secret_box.open;
	}
	export module formatWN {
		/**
		 * @param m is Uint8Array of message bytes that need to be encrypted by secret key.
		 * @param n is Uint8Array, 24 bytes long nonce.
		 * @param pk is Uint8Array, 32 bytes long public key of message receiving party.
		 * @param sk is Uint8Array, 32 bytes long secret key of message sending party.
		 * @param arrFactory is typed arrays factory, used to allocated/find an array
		 * for use. It may be undefined, in which case an internally created one is used.
		 * @returns Uint8Array, where nonce is packed together with cipher.
		 * Length of the returned array is 40 bytes greater than that of a message.
		 */
    	function pack(m: Uint8Array, n: Uint8Array, pk: Uint8Array, sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
		/**
		 * @param c is Uint8Array with nonce and cipher bytes that need to be opened by
		 * secret key.
		 * @param pk is Uint8Array, 32 bytes long public key of message receiving party.
		 * @param sk is Uint8Array, 32 bytes long secret key of message sending party.
		 * @param arrFactory is typed arrays factory, used to allocated/find an array
		 * for use. It may be undefined, in which case an internally created one is used.
		 * @return Uint8Array with decrypted message bytes.
		 * Array is a view of buffer, which has 32 zeros preceding message bytes.
		 */
	    function open(c: Uint8Array, pk: Uint8Array, sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
    	var copyNonceFrom: typeof secret_box.formatWN.copyNonceFrom;
		/**
		 * @param pk is Uint8Array, 32 bytes long public key of message receiving party.
		 * @param sk is Uint8Array, 32 bytes long secret key of message sending party.
		 * @param nextNonce is nonce, which should be used for the very first packing.
		 * All further packing will be done with new nonce, as it is automatically evenly
		 * advanced.
		 * Note that nextNonce will be copied.
		 * @param delta is a number between 1 and 255 inclusive, used to advance nonce.
		 * When missing, it defaults to two.
		 * @param arrFactory is typed arrays factory, used to allocated/find an array
		 * for use. It may be undefined, in which case an internally created one is used.
		 * @return a frozen object with pack & open functions, and destroy
		 * It is NaCl's secret box for a calculated DH-shared key, with automatically
		 * evenly advancing nonce.
		 */
	    function makeEncryptor(pk: Uint8Array, sk: Uint8Array, nextNonce: Uint8Array, delta?: number, arrFactory?: arrays.Factory): secret_box.Encryptor;
		/**
		 * @param pk is Uint8Array, 32 bytes long public key of message receiving party.
		 * @param sk is Uint8Array, 32 bytes long secret key of message sending party.
		 * @param arrFactory is typed arrays factory, used to allocated/find an array
		 * for use. It may be undefined, in which case an internally created one is used.
		 * @return a frozen object with open and destroy functions.
		 * It is NaCl's secret box for a calculated DH-shared key.
		 */
    	function makeDecryptor(pk: Uint8Array, sk: Uint8Array, arrFactory?: arrays.Factory): secret_box.Decryptor;
	}
	export var NONCE_LENGTH: number;
	export var KEY_LENGTH: number;
	export var JWK_ALG_NAME: string;
}

declare module EcmaNacl.nonce {
	/**
	 * This takes a given 24-byte nonce as three 8-byte numbers, and adds
	 * a given delta to each number.
	 * @param n is Uint8Array, 24 bytes long nonce that will be changed in-place.
	 * @param delta is a number from 1 to 255 inclusive.
	 */
	export function advance(n: Uint8Array, delta: number): void;
	/**
	 * This takes a given 24-byte nonce as three 8-byte numbers, and adds
	 * 1 to each number.
	 * @param n is Uint8Array, 24 bytes long nonce that will be changed in-place.
	 */
	export function advanceOddly(n: Uint8Array): void;
	/**
	 * This takes a given 24-byte nonce as three 8-byte numbers, and adds
	 * 2 to each number.
	 * @param n is Uint8Array, 24 bytes long nonce that will be changed in-place.
	 */
	export function advanceEvenly(n: Uint8Array): void;
	/**
	 * @param initNonce
	 * @param delta
	 * @return new nonce, calculated from an initial one by adding a delta to it.
	 */
	export function calculateNonce(initNonce: Uint8Array, delta: number, arrFactory: arrays.Factory): Uint8Array;
	/**
	 * @param n1
	 * @param n2
	 * @return delta (unsigned 32-bit integer), which, when added to the first
	 * nonce (n1), produces the second nonce (n2).
	 * Null is returned, if given nonces are not related to each other.
	 */
	export function calculateDelta(n1: Uint8Array, n2: Uint8Array): number;
}

declare module EcmaNacl.signing {
	export interface Keypair {
		/**
		 * Secret key of this pair.
		 */
    	skey: Uint8Array;
		/**
		 * Public key of this pair.
		 */
	    pkey: Uint8Array;
	}
	/**
	 * Analog of crypto_sign_keypair in crypto_sign/ed25519/ref/keypair.c
	 */
	export function generate_keypair(seed: Uint8Array, arrFactory?: arrays.Factory): Keypair;
	export function extract_pkey(sk: Uint8Array): Uint8Array;
	/**
	 * Analog of crypto_sign in crypto_sign/ed25519/ref/sign.c
	 */
	export function sign(m: Uint8Array, sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
	export function signature(m: Uint8Array, sk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
	/**
	 * Analog of crypto_sign_open in crypto_sign/ed25519/ref/open.c
	 */
	export function open(sm: Uint8Array, pk: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
	export function verify(sig: Uint8Array, m: Uint8Array, pk: Uint8Array, arrFactory?: arrays.Factory): boolean;
	export var JWK_ALG_NAME: string;
	export var PUBLIC_KEY_LENGTH: number;
	export var SECRET_KEY_LENGTH: number;
}

declare module EcmaNacl.fileXSP {
	/**
	 * This is a starting sequence of xsp file, which contains both
	 * encrypted segments and a header.
	 */
	export var FILE_START: Uint8Array;
	/**
	 * This is an offset to segments in xsp file with both segments and header.
	 */
	export var SEGMENTS_OFFSET: number;
	/**
	 * This is a starting sequence of a file with a header only.
	 */
	export var HEADER_FILE_START: Uint8Array;
	/**
	 * This is a starting sequence of a file with encrypted segments nly.
	 */
	export var SEGMENTS_FILE_START: Uint8Array;
	/**
	 * @param segsLen is a total length of encrypted segments.
	 * @return XSP file starting bytes, which are
	 * (1) 3 bytes "xsp", (2) 8 bytes with an offset, at which header starts.
	 */
	export function generateXSPFileStart(segsLen: number): Uint8Array;
	export function getXSPHeaderOffset(xspBytes: Uint8Array): number;
}

declare module EcmaNacl.fileXSP.segments {
	export interface LocationInSegment {
		/**
		 * Is a position in a decrypted content of a segment.
		 */
    	pos: number;
		/**
		 * Segment with a loaction of interest.
		 */
	    seg: {
    		/**
    		 * Index that points to the segment in the file.
    		 */
    	    ind: number;
    		/**
    		 * Segment's start in the encrypted file.
    		 */
        	start: number;
    		/**
    		 * Length of encrypted segment.
    		 */
	        len: number;
    	};
	}
	export interface SegmentsReader {
		/**
		 * @param pos is byte's position index in file content.
		 * @return corresponding location in segment with segment's info.
		 */
    	locationInSegments(pos: number): LocationInSegment;
		/**
		 * @param seg is an array with encrypted segment's bytes, starting at
		 * zeroth index. Array may be longer than a segment, but it will an error,
		 * if it is shorter.
		 * @param segInd is segment's index in file.
		 * @return decrypted content bytes of a given segment and a length of
		 * decrypted segment.
		 * Data array is a view of buffer, which has 32 zeros preceding
		 * content bytes.
		 */
    	openSeg(seg: Uint8Array, segInd: number): {
	        data: Uint8Array;
        	segLen: number;
	        last?: boolean;
    	};
		/**
		 * This wipes file key and releases used resources.
		 */
	    destroy(): void;
    	isEndlessFile(): boolean;
	}
	/**
	 * @param header is an array with header files. Array must contain only
	 * header's bytes. Arrays's length is used to decide on how to process it.
	 * @param mkeyDecr is a decryptor, based on a master key
	 * @param arrFactory (optional)
	 */
	export function makeReader(header: Uint8Array, mkeyDecr: secret_box.Decryptor, arrFactory?: arrays.Factory): SegmentsReader;
	export interface SegmentsWriter {
		/**
		 * @param pos is byte's position index in file content.
		 * @return corresponding location in segment with segment's info.
		 */
    	locationInSegments(pos: number): LocationInSegment;
	    packSeg(content: Uint8Array, segInd: number): {
    	    dataLen: number;
        	seg: Uint8Array;
	    };
		/**
		 * This wipes file key and releases used resources.
		 */
    	destroy(): void;
	    packHeader(mkeyEnc: secret_box.Encryptor): Uint8Array;
    	setContentLength(totalContentLen: number): void;
	    isHeaderModified(): boolean;
    	splice(pos: number, rem: number, ins: number): any;
	    isEndlessFile(): boolean;
	}
	export function makeNewWriter(segSizein256bs: number, randomBytes: (n: number) => Uint8Array, arrFactory?: arrays.Factory): SegmentsWriter;
	/**
	 * @param header is an array with header files. Array must contain only
	 * header's bytes. Arrays's length is used to decide on how to process it.
	 * @param mkeyDecr is a decryptor, based on a master key
	 * @param randomBytes is a function that produces cryptographically strong
	 * random numbers (bytes).
	 * @param arrFactory (optional)
	 */
	export function makeWriter(header: Uint8Array, mkeyDecr: secret_box.Decryptor, randomBytes: (n: number) => Uint8Array, arrFactory?: arrays.Factory): SegmentsWriter;
}

declare module EcmaNacl.hashing.sha512 {
	/**
	 * Analog of crypto_hash in crypto_hash/sha512/ref/hash.c
	 * with ending part of make hash of padded arranged into its
	 * own function.
	 */
	export function hash(inArr: Uint8Array, arrFactory?: arrays.Factory): Uint8Array;
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
	export function makeHasher(isSingleUse?: boolean, arrFactory?: arrays.Factory): Hasher;
}

declare module "ecma-nacl" {
    export = EcmaNacl;
}
