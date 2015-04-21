/* Copyright(c) 2013 - 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

/*
 * This shall have utilities for in-browser testing
 */

declare var crypto: any;

export function getRandom(numOfBytes: number): Uint8Array {
	// crypto.getRandomValues() complains, when we ask for more than
	// 64K at a time (in firefox), thus, we should take it step by step 
	var arr = new Uint8Array(numOfBytes);
	var numOf64Ks = Math.floor(numOfBytes / (64*1024))
	var subArr: Uint8Array;
	for ( var i = 0; i < numOf64Ks; i += 1) {
		subArr = new Uint8Array(arr.buffer, i*(64*1024), 64*1024);
		crypto.getRandomValues(subArr);
	}
	var oddBytes = numOfBytes - numOf64Ks*(64*1024);
	if (oddBytes > 0) {
		subArr = new Uint8Array(arr.buffer, numOf64Ks*(64*1024), oddBytes);
		crypto.getRandomValues(new Uint8Array(arr.buffer,
				numOf64Ks * 64 * 1024, oddBytes));
	}
	return arr;
}

export function logTestResult(str: string, isError?: boolean): void {
	if (!str) { return; }
	var p = document.createElement('p');
	p.textContent = (isError? 'ERROR: ' : '')+str;
	var logs = document.getElementById("tests-log");
	logs.appendChild(p);
	p.scrollIntoView();
}

export function clearLog(): void {
	var logs = document.getElementById("tests-log");
	logs.innerHTML = "";
}

