
/**
 * This is an encryptor that packs bytes according to "with-nonce" format.
 */
interface Encryptor {
	
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
interface Decryptor {
	
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

interface Keypair {
	
	/**
	 * Secret key of this pair.
	 */
	skey: Uint8Array;
	
	/**
	 * Public key of this pair.
	 */
	pkey: Uint8Array;
}

interface Hasher {
	
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
