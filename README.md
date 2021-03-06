# ecma-nacl: Pure JavaScript (ECMAScript) version of NaCl cryptographic library.

[NaCl](http://nacl.cr.yp.to/) is a great crypto library that is not placing a burden of crypto-math choices onto developers, providing only solid high-level functionality (box - for public-key, and secret_box - for secret key  authenticated encryption), in a let's [stop blaming users](http://cr.yp.to/talks/2012.08.08/slides.pdf) of cryptographic library (e.g. end product developers, or us) manner.
Take a look at details of NaCl's design  "[The security impact of a new cryptographic
library](http://cr.yp.to/highspeed/coolnacl-20120725.pdf)".

ecma-nacl is a re-write of NaCl in TypeScript, which is ECMAScript with compile-time types.
Library implements NaCl's box and secret box.
Signing code comes from SUPERCOP version 2014-11-24.

TypeScript re-write of [scrypt](http://www.tarsnap.com/scrypt.html) key derivation function has been added to ecma-nacl beyond NaCl.
Scrypt is a highly valuable thing for services that allow users to have passwords, while doing proper work with crypto keys, derived from those passwords.

Re-writes are based on C sources, included in this repository.
Tests are written to correspond those in C code, to make sure that output of this library is the same as that of C's version.
Scrypt's tests a taken from an [RFC draft](http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01).
Besides this, we added comparison runs between ecma-nacl, and js-nacl with js-scrypt, which is an [Emscripten](https://github.com/kripken/emscripten)-compilation of C respective libraries.

## Get ecma-nacl

### NPM Package

This library is registered on
[npmjs.org](https://npmjs.org/package/ecma-nacl). To install it, do:
```
npm install ecma-nacl
```
Package comes only with already compiled library code and typescript definitions in build/ folder. For building and testing clone github project.

### Building

Once you clone this repo, do in the folder
```
npm install
```
which will install dev-dependencies.

Building is done with npm script.
Do in the folder
```
npm run build
```
and
```
npm run test
```
runs tests.

## ecma-nacl API

### API for secret-key authenticated encryption

Add module into code as

```javascript
import * as nacl from 'ecma-nacl';
```

[Secret-key authenticated](http://nacl.cr.yp.to/secretbox.html) encryption is provided by secret_box, which implements XSalsa20+Poly1305.

When encrypting, or packing, NaCl does following things. First, it encrypts plain text bytes using XSalas20 algorithm. Secondly, it creates 16 bytes of authentication Poly1305 code, and places these infront of the cipher. Thus, regular byte layout is 16 bytes of Poly1305 code, followed by cipher with actual message, having exactly the same length as plain text message.

Decrypting, or opening goes through these steps in reverse. First, Poly1305 code is read and is compared with code, generated by reading cipher. When these do not match, it means either that key+nonce pair is incorrect, or that cipher with message has been damaged/changed. Our code will throw an exception in such a case. When verification is successful, XSalsa20 will do decryption, producing message bytes.

```javascript
// all incoming and outgoing things are Uint8Array's;
// to encrypt, or pack plain text bytes into cipher bytes, use
let cipher_bytes = nacl.secret_box.pack(plain_bytes, nonce, key);

// decryption, or opening is done by
let result_bytes = nacl.secret_box.open(cipher_bytes, nonce, key);
```

Above pack method will produce an Uint8Array with cipher, offset by 16 zero bytes in the underlying buffer. Deciphered bytes, on the other hand, are offset by 32 zero bytes. This should always be kept in mind, when transferring raw buffers to/from web-workers. In all other places, this padding is never noticed, thanks to [typed array api](https://developer.mozilla.org/en-US/docs/Web/API/Uint8Array).

Key is 32 bytes long. Nonce is 24 bytes. Nonce means number-used-once, i.e. it should be unique for every segment encrypted by the same key.

Sometimes, when storing things, it is convenient to pack cipher together with nonce (WN) into the same array.

    +-------+ +------+ +---------------+
    | nonce | | poly | |  data cipher  |
    +-------+ +------+ +---------------+
    | <----       WN format      ----> |

For this, secret_box has formatWN object, which is used analogously:

```javascript
// encrypting, and placing nonce as first 24 bytes infront NaCl's byte output layout
let cipher_bytes = nacl.secret_box.formatWN.pack(plain_bytes, nonce, key);

// decryption, or opening is done by
let result_bytes = nacl.secret_box.formatWN.open(cipher_bytes, key);

// extraction of nonce from cipher can be done as follows
let extracted_nonce = nacl.secret_box.formatWN.copyNonceFrom(cipher_bytes);
```

Cipher array here has no offset in the buffer, but decrypted array does have the same 32 zero bytes offset, as mentioned above.

It is important to always use different nonce, when encrypting something new with the same key. Object nonce contains functions to advance nonce, to calculate consequent nonces, etc. The 24 bytes of a nnce are taken as three 32-bit integers, and are advanced by 1 (oddly), by 2 (evenly), or by n. So, when encrypting many segments of a huge file, one can advance nonce oddly every time. When key is shared, and is used for communication between two parties, one party's initial nonce may be oddly advanced initial nonce, received from the second party, and all other respective nonces are advanced evenly on both sides of communication. This way, unique nonces are used for every message send.

```javascript
// nonce changed in place oddly
nacl.nonce.advanceOddly(nonce);

// nonce changed in place evenly
nacl.nonce.advanceEvenly(nonce);

// nonce changed in place by delta
nacl.nonce.advance(nonce, delta);

// calculate related nonce
let relatedNonce = nacl.nonce.calculateNonce(nonce, delta, arrayFactory);

// find delta between nonces (null result is for unrelated nonces)
let delta = nacl.nonce.calculateDelta(n1, n2);
```

It is common, that certain code needs to be given encryption/decryption functionality, but according to [principle of least authority](https://en.wikipedia.org/wiki/Principle_of_least_privilege) such code does not necessarily need to know secret key, with which encryption is done. So, one may make an encryptor and a decryptor. These are made to produce and read ciphers with-nonce format.

```javascript
// delta is optional, defaults to one
let encryptor = nacl.secret_box.formatWN.makeEncryptor(key, nextNonce, delta);

// packing bytes is done with
let cipher_bytes = encryptor.pack(plain_bytes);

// when encryptor is no longer needed, key should be properly wiped from memory
encryptor.destroy();

let decryptor = nacl.secret_box.formatWN.makeDecryptor(key);

// opening is done with
let result_bytes = decryptor.open(cipher_bytes);

// when encryptor is no longer needed, key should be properly wiped from memory
decryptor.destroy();
```

### API for public-key authenticated encryption

[Public-key authenticated](http://nacl.cr.yp.to/box.html) encryption is provided by box, which implements Curve25519+XSalsa20+Poly1305. Given pairs of secret-public keys, corresponding shared, in Diffie–Hellman sense, key is calculated (Curve25519) and is used for data encryption with secret_box (XSalsa20+Poly1305).

Given any random secret key, we can generate corresponding public key:

```javascript
let public_key = nacl.box.generate_pubkey(secret_key);
```

Secret key may come from `crypto`'s function, or be derived from a passphrase with scrypt.

There are two ways to use box. The first way is to always do two things, calculation of DH-shared key and subsequent packing/opening, in one step.

```javascript
// Alice encrypts message for Bob
let cipher_bytes = nacl.box.pack(msg_bytes, nonce, bob_pkey, alice_skey);

// Bob opens the message
let msg_bytes = nacl.box.open(cipher_bytes, nonce, alice_pkey, bob_skey);
```

The second way is to calculate DH-shared key once and use it for packing/opening multiple messages, with box.stream.pack and box.stream.open, which are just nicknames of described above secret_box.pack and secret_box.open.

```javascript
// Alice calculates DH-shared key
let dhshared_key = nacl.box.calc_dhshared_key(bob_pkey, alice_skey);
// Alice encrypts message for Bob
let cipher_bytes = nacl.box.stream.pack(msg_bytes, nonce, dhshared_key);

// Bob calculates DH-shared key
let dhshared_key = nacl.box.calc_dhshared_key(alice_pkey, bob_skey);
// Bob opens the message
let msg_bytes = nacl.box.stream.open(cipher_bytes, nonce, dhshared_key);
```

Or, we may use box encryptors that do first step of DH-shared key calculation only at creation.

Alice's side:

```javascript
// generate nonce
let nonce = crypto.randomBytes(24);

// make encryptor to produce with-nonce format (default delta is two)
let encryptor = nacl.box.formatWN.makeEncryptor(bob_pkey, alice_skey, nonce);

// pack messages to Bob
let cipher_to_send = encryptor.pack(msg_bytes);

// open mesages from Bob
let decryptor = nacl.box.formatWN.makeDecryptor(bob_pkey, alice_skey);
let msg_from_bob = decryptor.open(received_cipher);
    
// when encryptor is no longer needed, key should be properly wiped from memory
encryptor.destroy();
decryptor.destroy();
```

Bob's side:

```javascript
// get nonce from Alice's first message, advance it oddly, and
// use for encryptor, as encryptors on both sides advance nonces evenly
let nonce = nacl.box.formatWN.copyNonceFrom(cipher1_from_alice);
nacl.nonce.advanceOddly(nonce);

// make encryptor to produce with-nonce format (default delta is two)
let encryptor = nacl.box.formatWN.makeEncryptor(alice_pkey, bob_skey, nonce);

// pack messages to Alice
let cipher_to_send = encryptor.pack(msg_bytes);

// open mesages from Alice
let decryptor = nacl.box.formatWN.makeDecryptor(alice_pkey, bob_skey);
let msg_from_alice = encryptor.open(received_cipher);
    
// when encryptor is no longer needed, key should be properly wiped from memory
encryptor.destroy();
decryptor.destroy();
```

### Signing

Code for signing is a re-write of Ed25519 C version from [SUPERCOP's](http://bench.cr.yp.to/supercop.html), referenced in [NaCl](http://nacl.cr.yp.to/sign.html).

signing object contains all related functionality.

```javascript
// signing key pair can be generated from some seed array, which can
// either be random itself, or be generated from a password
let pair = nacl.signing.generate_keypair(seed);

// make signature bytes, for msg
let msgSig = nacl.signing.signature(msg, pair.skey);

// verify signature
let sigIsOK = nacl.signing.verify(msgSig, msg, pair.pkey);
```

There are functions like [NaCl's](http://nacl.cr.yp.to/sign.html) sign and sign_open methods, which place signature and message into one array, and expect the same for opening (verification).
In a context of [JWK](http://self-issued.info/docs/draft-ietf-jose-json-web-key.html), abovementioned functions seem to be more flexible and useful than C's API.

### Random number generation

NaCl does not do it. The randombytes in the original code is a unix shim with the following rational, given in the comment, quote: "it's really stupid that there isn't a syscall for this".

So, you should obtain cryptographically strong random bytes yourself. In node, there is crypto. There is crypto in browser. IE6? IE6 must die! Stop supporting insecure crap! Respect your users, and tell them truth, that they need modern secure browser(s).

### Scrypt - key derivation from passphrases

Scrypt derives a key from users password.
Algorithm is memory-hard, which means it uses lots and lots of memory.
There are three parameters that go into derivation: `N` , `r` and `p` .

Amount of memory used is roughly `128 * N * r == r * 2^(7+logN)`  bytes.
With `r = 8` , when `logN`  is 10, it is a MB range of memory, when `logN`  is 20, it is a GB range of memory in use.

Parameter `p`  says how many times should the whole operation occur.
So, when running out of memory (js is not giving enough memory for `logN = 20` ), one may up `p`  value.

It goes without saying, that such operations take time, and this implementation has a callback for progress reporting.

```javascript
// given pass (secret), salt and other less-secret parameters
// key of length keyLen is generated as follows:
let logN = 17;
let r = 8;
let p = 2;
let key = nacl.scrypt(pass, salt, logN, r, p, keyLen, function(pDone) {
    console.log('derivation progress: ' + pDone + '%');
}); 
```

Colin Percival's [paper](http://www.tarsnap.com/scrypt/scrypt.pdf) about scrypt makes for a lovely weekend-long reading. 


## License

This code is provided here under [Mozilla Public License Version 2.0](https://www.mozilla.org/MPL/2.0/).

NaCl C library is public domain code by Daniel J. Bernstein and co. We thank thy wisdom of giving us developer-friendly library.

Scrypt C library is created by Colin Percival. We thank thee for bringing us strong new ideas in key derivation tasks.
