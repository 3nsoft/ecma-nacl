# ecma-nacl: Pure JavaScript (ECMAScript) version of NaCl cryptographic library.

[NaCl](http://nacl.cr.yp.to/) is a great crypto library that is not placing a burden of crypto-math choices onto developers, providing only solid high-level functionality (box - for public-key, and secret_box - for secret key  authenticated encryption), in a let's [stop blaming users](http://cr.yp.to/talks/2012.08.08/slides.pdf) of cryptographic library (e.g. end product developers, or us) manner.
Take a look at details of NaCl's design  "[The security impact of a new cryptographic
library](http://cr.yp.to/highspeed/coolnacl-20120725.pdf)".

ecma-nacl is a re-write of most important NaCl's functionality, which is ready for production, box and secret_box. Signing code still has XXX comments, indicating that the warning in [signing in NaCl](http://nacl.cr.yp.to/sign.html) should be taken seriously.

Rewrite is based on the copy of NaCl, included in this repository.
Tests are written to correspond those in C code, to make sure that output of this library is the same as that of C's version.
Besides this, we added comparison runs between ecma-nacl, and js-nacl, which is an [Emscripten](https://github.com/kripken/emscripten)-compilation of C library.
These comparison runs can be done in both node and browsers.

Your mileage may vary, but just three weeks ago, js-nacl was running 10% faster on Chrome.
Today, with new version of Chrome, it is ecma-nacl that is faster.
Given smaller size, and much better auditability of actual js code, ecma-nacl might be more preferable than js-nacl.

## NPM Package

This library is [registered on
npmjs.org](https://npmjs.org/package/ecma-nacl). To install it:

    npm install ecma-nacl

## Browser Package

make-browserified.js will let you make a browserified module. So, make sure that you have [browserify module](http://browserify.org/) to run the script. You may also modify it to suite your particular needs.

## XSP file format
Each NaCl's cipher must be read completely, before any plain text output.
Such requirement makes reading big files awkward.
Thus, the simplest solution is to pack NaCl's binary ciphers into self-contained small segments.
Each segment must be encrypted with a different nonce.
When segments are same-size, there is a predictable mapping when random access is needed.
Such format we call XSP (XSalsa+Poly), and provide utility to pack and open segments.
Each file's first segment contains file header with encrypted file key, suggesting a policy of one key per file.
This may allow simpler sharing of files in a web-service setting, as only file key section needs to be re-encrypted, when a new user gets the file.
