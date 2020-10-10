/*
 Copyright (C) 2016 - 2018, 2020 3NSoft Inc.
 This Source Code Form is subject to the terms of the Mozilla Public
 License, v. 2.0. If a copy of the MPL was not distributed with this
 file, you can obtain one at http://mozilla.org/MPL/2.0/.
*/

export function itAsync(
	expectation: string, assertion?: () => Promise<void>, timeout?: number,
	setup?: { isUp: boolean; }
): void {
	if (assertion) {
		it(expectation, callbackFor(assertion, setup), timeout);
	} else {
		it(expectation);
	}
}

function callbackFor(
	assertion: () => Promise<void>, setup: { isUp: boolean; }|undefined
): (done: DoneFn) => void {
	return done => {
		if (setup && !setup.isUp) {
			done.fail(`Test setup is not up`);
		} else {
			assertion().then(() => done(), err => done.fail(err));
		}
	}
}

export function xitAsync(
	expectation: string, assertion?: () => Promise<void>, timeout?: number,
	setup?: { isUp: boolean; }
): void {
	if (assertion) {
		xit(expectation, callbackFor(assertion, setup), timeout);
	} else {
		xit(expectation);
	}
}

export function fitAsync(
	expectation: string, assertion?: () => Promise<void>, timeout?: number,
	setup?: { isUp: boolean; }
): void {
	if (assertion) {
		fit(expectation, callbackFor(assertion, setup), timeout);
	} else {
		fit(expectation);
	}
}

export function beforeAllAsync(
	action: () => Promise<void>, timeout?: number
): void {
	beforeAll(callbackWithTimeout(action, true, timeout, 'beforeAll'), timeout);
}

function callWithTimeout<T>(
	f: () => Promise<T>, timeout: number, timeoutErr: () => any
): Promise<T> {
	let isDone = false;
	const deferred = defer<T>();
	f().then(res => {
		if (isDone) { return; }
		isDone = true;
		deferred.resolve(res);
	}, err => {
		if (isDone) { return; }
		isDone = true;
		deferred.reject(err);
	});
	sleep(timeout).then(() => {
		if (isDone) { return; }
		isDone = true;
		const err = timeoutErr();
		if (err) {
			deferred.reject(err);
		}
	});
	return deferred.promise;
}

export interface Deferred<T> {
	resolve: (v: T) => void;
	reject: (err?: any) => void;
	promise: Promise<T>;
}

export function defer<T>(): Deferred<T> {
	const d = <Deferred<T>> {};
	d.promise = new Promise<T>((resolve, reject) => {
		d.resolve = resolve;
		d.reject = reject;
	});
	return d;
}

function sleep(millis: number): Promise<void> {
	return new Promise<void>((resolve) => setTimeout(resolve, millis).unref());
}

const DEFAULT_TIMEOUT_INTERVAL = 5000;

function callbackWithTimeout(
	action: () => Promise<void>, throwIfErr: boolean, timeout: number|undefined,
	actionType: string
): ImplementationCallback {
	const millisToSleep = ((timeout === undefined) ?
		DEFAULT_TIMEOUT_INTERVAL : timeout);
	const timeoutErr = {};
	return async done => {
		try {
			await callWithTimeout(action, millisToSleep - 5, () => timeoutErr);
			done();
		} catch (err) {
			if (err === timeoutErr) {
				console.log(`\n>>> timeout in ${actionType}: action hasn't completed in ${millisToSleep - 5} milliseconds`);
				done();
			} else if (throwIfErr) {
				done.fail(err);
			} else {
				done();
			}
		}
	};
}

export function beforeEachAsync(
	action: () => Promise<void>, timeout?: number
): void {
	beforeEach(callbackWithTimeout(
		action, true, timeout, 'beforeEach'), timeout);
}

// Adjust this static flag to hide/show errors thrown in afterXXX()
const throwErrorInAfter = false;

export function afterAllAsync(
	action: () => Promise<void>, timeout?: number
): void {
	afterAll(callbackWithTimeout(
		action, throwErrorInAfter, timeout, 'afterAll'), timeout);
}

export function afterEachAsync(
	action: () => Promise<void>, timeout?: number
): void {
	afterEach(callbackWithTimeout(
		action, throwErrorInAfter, timeout, 'afterEach'), timeout);
}

Object.freeze(exports);