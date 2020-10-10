/*
 Copyright(c) 2020 3NSoft Inc.
 This Source Code Form is subject to the terms of the Mozilla Public
 License, v. 2.0. If a copy of the MPL was not distributed with this
 file, you can obtain one at http://mozilla.org/MPL/2.0/.
*/

import { isMainThread, Worker, parentPort } from 'worker_threads';
import * as nacl from '../../lib/ecma-nacl';
import { beforeAllAsync, afterAllAsync, defer, itAsync } from '../libs-for-tests/async-jasmine';
import { asciiStrToUint8Array } from '../libs-for-tests/test-utils';
import { randomFillSync } from 'crypto';
import { bytesEqual } from '../libs-for-tests/bytes-equal';
import { Buffer } from 'buffer';


interface RequestMsg {
	func: Func;
	args: any[];
}

type Func = 'scrypt' |
	'box.calc_dhshared_key' | 'box.generate_pubkey' |
	'sbox.open' | 'sbox.pack' |
	'sbox.formatWN.open' | 'sbox.formatWN.pack' |
	'sign.generate_keypair' | 'sign.signature' | 'sign.verify';

interface ReplyMsg {
	res?: any;
	interim?: any;
	err?: any;
}

function transfer(...arrs: Uint8Array[]): ArrayBuffer[]|undefined {
	const transferLst: ArrayBuffer[] = [];
	for (const arr of arrs) {
		const buffer = arr.buffer;
		if (!transferLst.includes(buffer)) {
			transferLst.push(buffer);
		}
	}
	return transferLst;
}

function tests() {

	const workerStart = defer<void>();
	const worker = new Worker(__filename)
	.on('error', workerStart.reject)
	.on('online', workerStart.resolve);

	async function callWorker<T>(
		func: Func, args: any[], trans?: ArrayBuffer[], interim?: (v: any) => void
	): Promise<T> {
		const reply = defer<T>();
		const msgListener = (msg: ReplyMsg) => {
			if (msg.res !== undefined) {
				reply.resolve(msg.res);
			} else if (msg.interim !== undefined) {
				if (interim) {
					interim(msg.interim);
				}
			} else {
				reply.reject(msg.err);
			}
		};
		worker.on('message', msgListener);
		const request: RequestMsg = { func, args };
		if (trans) {
			worker.postMessage(request, trans);
		} else {
			worker.postMessage(request);
		}
		const result = await reply.promise;
		worker.removeListener('message', msgListener);
		return result;
	}

	beforeAllAsync(async () => {
		await workerStart.promise;
	});

	afterAllAsync(async () => {
		await worker.terminate();
	});

	itAsync(`scrypt function`, async () => {
		const passSalt = randomFillSync(Buffer.alloc(32));
		const passStr = 'Some passphrase, long and strong enough';
		const pass = Buffer.alloc(passStr.length);
		pass.set(asciiStrToUint8Array(passStr));

		const progressNums: number[] = [];
		const sk1 = await callWorker<Uint8Array>(
			'scrypt',
			[ pass, passSalt, 4, 1, 1, nacl.box.KEY_LENGTH ],
			transfer(pass, passSalt), p => progressNums.push(p));
		expect(sk1.length).toBe(nacl.box.KEY_LENGTH);
		expect(progressNums.length).toBeGreaterThan(1);
		progressNums.forEach(p => expect(typeof p).toBe('number'));
	});

	itAsync(`box functions`, async () => {
		const sk1 = randomFillSync(Buffer.alloc(nacl.box.KEY_LENGTH));
		const pk1 = await callWorker<Uint8Array>(
			'box.generate_pubkey', [ sk1 ]);
		expect(pk1.length).toBe(nacl.box.KEY_LENGTH);
		const sk2 = Buffer.alloc(nacl.box.KEY_LENGTH);
		const shared = await callWorker<Uint8Array>(
			'box.calc_dhshared_key', [ pk1, sk2 ]);
		expect(shared.length).toBe(nacl.secret_box.KEY_LENGTH);
	});

	itAsync(`secret_box functions`, async () => {
		const m = randomFillSync(Buffer.alloc(3000));
		const k = randomFillSync(Buffer.alloc(nacl.secret_box.KEY_LENGTH));
		const n = randomFillSync(Buffer.alloc(nacl.secret_box.NONCE_LENGTH));
		const c = await callWorker<Uint8Array>(
			'sbox.pack', [ m, n, k ]);
		expect(c.length).toBe(m.length+nacl.secret_box.POLY_LENGTH);
		const decryptedM = await callWorker<Uint8Array>(
			'sbox.open', [ c, n, k ], transfer(c));
		expect(c.length).toBe(0);	// c has been transfered, and isn't here
		expect(bytesEqual(decryptedM, m)).toBe(true);
	});

	itAsync(`secret_box formatWN functions`, async () => {
		const m = randomFillSync(Buffer.alloc(3000));
		const k = randomFillSync(Buffer.alloc(nacl.secret_box.KEY_LENGTH));
		const n = randomFillSync(Buffer.alloc(nacl.secret_box.NONCE_LENGTH));
		const cn = await callWorker<Uint8Array>(
			'sbox.formatWN.pack', [ m, n, k ]);
		expect(cn.length).toBe(
			m.length+nacl.secret_box.NONCE_LENGTH+nacl.secret_box.POLY_LENGTH);
		const decryptedM = await callWorker<Uint8Array>(
			'sbox.formatWN.open', [ cn, k ], transfer(cn));
		expect(cn.length).toBe(0);	// cn has been transfered, and isn't here
		expect(bytesEqual(decryptedM, m)).toBe(true);
	});

	itAsync(`signing functions`, async () => {
		const seed = randomFillSync(Buffer.alloc(nacl.signing.SEED_LENGTH));
		const keypair = await callWorker<nacl.signing.Keypair>(
			'sign.generate_keypair', [ seed ], transfer(seed));
		expect(keypair.pkey.length).toBe(nacl.signing.PUBLIC_KEY_LENGTH);
		expect(keypair.skey.length).toBe(nacl.signing.SECRET_KEY_LENGTH);
		const m = randomFillSync(Buffer.alloc(3000));
		const sig = await callWorker<Uint8Array>(
			'sign.signature', [ m, keypair.skey ]);
		expect(sig.length).toBe(64);
		const sigOK = await callWorker<boolean>(
			'sign.verify', [ sig, m, keypair.pkey ]);
		expect(sigOK).toBe(true);
	});

}

function workerMain(port: NonNullable<typeof parentPort>) {

	const arrFactory = nacl.arrays.makeFactory();
	const wipe = nacl.arrays.wipe;

	type Code = (args: any[]) => { res: any; trans?: ArrayBuffer[] };

	const funcs: { [key in Func]: Code; } = {

		'scrypt': args => {
			const progressCB = (n: number): void => {
				const reply: ReplyMsg = { interim: n };
				port.postMessage(reply);
			};
			const res = nacl.scrypt(
				args[0], args[1], args[2], args[3], args[4], args[5],
				progressCB, arrFactory);
			wipe(args[0]);
			return { res, trans: transfer(res) };
		},

		'box.calc_dhshared_key': args => {
			const res = nacl.box.calc_dhshared_key(args[0], args[1], arrFactory);
			wipe(args[0], args[1]);
			return { res, trans: transfer(res) };
		},
		'box.generate_pubkey': args => {
			const res = nacl.box.generate_pubkey(args[0], arrFactory);
			wipe(args[0]);
			return { res, trans: transfer(res) };
		},

		'sbox.open': args => {
			const res = nacl.secret_box.open(
				args[0], args[1], args[2], arrFactory);
			wipe(args[2]);
			return { res, trans: transfer(res) };
		},
		'sbox.pack': args => {
			const res = nacl.secret_box.pack(
				args[0], args[1], args[2], arrFactory);
			wipe(args[2]);
			return { res, trans: transfer(res) };
		},
		'sbox.formatWN.open': args => {
			const res = nacl.secret_box.formatWN.open(
				args[0], args[1], arrFactory);
			wipe(args[1]);
			return { res, trans: transfer(res) };
		},
		'sbox.formatWN.pack': args => {
			const res = nacl.secret_box.formatWN.pack(
				args[0], args[1], args[2], arrFactory);
			wipe(args[2]);
			return { res, trans: transfer(res) };
		},

		'sign.generate_keypair': args => {
			const pair = nacl.signing.generate_keypair(args[0], arrFactory);
			wipe(args[0]);
			return { res: pair, trans: transfer(pair.pkey, pair.skey) };
		},
		'sign.signature': args => {
			const res = nacl.signing.signature(args[0], args[1], arrFactory);
			wipe(args[1]);
			return { res, trans: transfer(res) };
		},
		'sign.verify': args => {
			const ok = nacl.signing.verify(args[0], args[1], args[2], arrFactory);
			return { res: ok };
		}

	};

	function wrapError(err: any) {
		if ((err as any).failedCipherVerification) {
			return { failedCipherVerification: true };
		} else {
			return {
				message: `Error occured in cryptor worker thread`,
				stack: err.stack
			};
		}
	}
	
	port.on('message', (msg: RequestMsg) => {
		const { args, func } = msg;
		const code = funcs[func];
		if (!code) { throw new Error(`Function ${func} is unknown`); }
		try {
			const { res, trans } = code(args);
			const reply: ReplyMsg = { res };
			port.postMessage(reply, trans);
		} catch (err) {
			const reply: ReplyMsg = { err: wrapError(err) };
			port.postMessage(reply);
		}
	});

}

if (isMainThread) {
	describe('ecma-nacl outputs arrays, passable from', tests);
} else {
	if (!parentPort) { throw new Error(`Parent port is missing`); }
	workerMain(parentPort);
}