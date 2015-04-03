var boxes = ['./boxes/box', './boxes/core', './boxes/onetimeauth', './boxes/scalarmult', './boxes/secret_box', './boxes/stream'];
var hashes = ['./hash/sha512'];
var signing = ['./signing/sign'];
var file = ['./file/xsp'];
var scrypt = ['./scrypt/sha256', './scrypt/scrypt'];
function run(modules, comment) {
    console.log("\n===== START " + comment + " =====\n");
    modules.forEach(function (mod) {
        try {
            require(mod);
        }
        catch (e) {
            console.error(e.stack);
        }
    });
    console.log("\n===== FINISH " + comment + " =====\n");
}
run(boxes, "Tests of boxes (XSalsa, Poly, Curve and combinations)");
run(hashes, "Tests of hashes (sha512, sha256)");
run(signing, "Tests of signing");
run(file, "Tests of file formats (XSP)");
run(scrypt, "Tests of scrypt library for key derivation");
