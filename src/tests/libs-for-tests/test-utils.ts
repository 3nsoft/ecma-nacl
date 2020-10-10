/*
 Copyright(c) 2013 - 2015, 2020 3NSoft Inc.
 This Source Code Form is subject to the terms of the Mozilla Public
 License, v. 2.0. If a copy of the MPL was not distributed with this
 file, you can obtain one at http://mozilla.org/MPL/2.0/.
*/

import { randomBytes } from 'crypto';

export function runTimingAndLogging(
	numOfRuns: number, msgPref: string, run: () => void
): void {
	const startTime = process.hrtime();
	for (let i=0; i<numOfRuns; i+=1) {
		run();
	}
	const hrtimes = process.hrtime(startTime);
	const diff = (hrtimes[0]*1e9 + hrtimes[1]) / numOfRuns / 1e6;
	console.log((msgPref? msgPref+'' : '')+diff.toFixed(3)+" milliseconds");
}

export function getRandom(numOfBytes: number): Uint8Array {
	return randomBytes(numOfBytes);
}

export function asciiStrToUint8Array(str: string): Uint8Array {
	const arr = new Uint8Array(str.length);
	for (let i=0; i<str.length; i+=1) {
		arr[i] = str.charCodeAt(i);
	}
	return arr;
}
