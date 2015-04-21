/* Copyright(c) 2013-2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * This module provide an object pool for typed arrays used in the library.
 * When we turn off reusing, by always making new arrays, time for boxes goes up
 * dramatically (due to arrays needed in stream?).
 */

class NumericArrPool<T> {
	private arrFactory: () => T = null;
	private numOfElemsInObj: number;
	private pool = new Array<T>(16);
	private poolIndex = -1;
	private wipedIndex = -1;
	
	static makeUint8ArrayPool(numOfElemsInObj: number): NumericArrPool<Uint8Array> {
		var pool = new NumericArrPool<Uint8Array>(numOfElemsInObj);
		pool.arrFactory = () => {
			return new Uint8Array(pool.numOfElemsInObj);
		}
		return pool;
	}
	
	static makeUint32ArrayPool(numOfElemsInObj: number): NumericArrPool<Uint32Array> {
		var pool = new NumericArrPool<Uint32Array>(numOfElemsInObj);
		pool.arrFactory = () => {
			return new Uint32Array(pool.numOfElemsInObj);
		}
		return pool;
	}
	
	constructor (numOfElemsInObj: number) {
		this.numOfElemsInObj = numOfElemsInObj;
		Object.seal(this);
	}

	/**
	 * This either creates new, or gets a spare array from the pool.
	 * Newly created array is not put into pool, because it is given to someone for
	 * use.
	 * If someone forgets to return it, there shall be no leaking references.
	 * @returns TypedArray, created by set arrFactory, with set number of elements
	 * in it.
	 * Note that array may and shall have arbitrary data in it, thus, any
	 * initialization must be performed explicitly.
	 */
	get(): T {
		var arr;
		if (this.poolIndex < 0) {
			arr = this.arrFactory();
		} else {
			arr = this.pool[this.poolIndex];
			this.pool[this.poolIndex] = null;
			this.poolIndex -= 1;
			if (this.poolIndex < this.wipedIndex) {
				this.wipedIndex = this.poolIndex;
			}
		}
		return arr;
	}

	/**
	 * This puts array into the pool, but it does not touch a content of array.
	 * @param arr
	 */
	recycle(arr: T): void {
		this.poolIndex += 1;
		this.pool[this.poolIndex] = arr;
	}

	/**
	 * This wipes all arrays in this pool.
	 */
	wipe(): void {
		var uintArr;
		for (var i=(this.wipedIndex+1); i<=this.poolIndex; i+=1) {
			uintArr = <any> this.pool[i];
			for (var j=0; j<uintArr.length; j+=1) {
				uintArr[j] = 0;
			}
		}
		this.wipedIndex = this.poolIndex;
	}
	
}

interface mapOfPools<T> {
	[len: number]: NumericArrPool<T>;
}

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
	recycle(...arrays): void;
	
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
	wipe(...arrays): void;
}

export function makeFactory(): Factory {
	var f = new ArrFactory();
	return {
		getUint8Array: f.getUint8Array.bind(f),
		getUint32Array: f.getUint32Array.bind(f),
		recycle: f.recycle.bind(f),
		wipeRecycled: f.wipeRecycled.bind(f),
		clear: f.clear.bind(f),
		wipe: wipe
	};
}

class ArrFactory {
	private uint8s: mapOfPools<Uint8Array> = {};
	private uint32s: mapOfPools<Uint32Array> = {};

	constructor() {
		Object.freeze(this);
	}
	
	getUint8Array(len: number): Uint8Array {
		var pool = this.uint8s[len];
		return (pool ? pool.get() : new Uint8Array(len));
	}

	getUint32Array(len: number): Uint32Array {
		var pool = this.uint32s[len];
		return (pool ? pool.get() : new Uint32Array(len));
	}

	private recycleUint8Array(arr: Uint8Array): void {
		var pool = this.uint8s[arr.length];
		if (!pool) {
			pool = NumericArrPool.makeUint8ArrayPool(arr.length);
			this.uint8s[arr.length] = pool;
		}
		pool.recycle(arr);
	}

	private recycleUint32Array(arr: Uint32Array): void {
		var pool = this.uint32s[arr.length];
		if (!pool) {
			pool = NumericArrPool.makeUint32ArrayPool(arr.length);
			this.uint32s[arr.length] = pool;
		}
		pool.recycle(arr);
	}

	recycle(...arrays): void {
		var arr;
		for (var i=0; i<arrays.length; i+=1) {
			arr = arrays[i];
			if (!arr) continue;
			if ((arr.byteOffset !== 0) ||
					(arr.length*arr.BYTES_PER_ELEMENT !== arr.buffer.byteLength)) {
				throw new TypeError("Given, as argument #"+(i+1)+" is a view "+
						"of an array, and these are not supposed to be recycled.");
			}
			if (arr.BYTES_PER_ELEMENT === 1) {
				this.recycleUint8Array(arr);
			} else if (arr.BYTES_PER_ELEMENT === 4) {
				this.recycleUint32Array(arr);
			} else {
				throw new TypeError(
						"This works with typed arrays that have 1 or 4 bytes "+
						"per element, while given at position "+i+
						" array claims to have "+arr.BYTES_PER_ELEMENT);
			}
		}
	}

	wipeRecycled(): void {
		for (var fieldName in this.uint8s) { this.uint8s[fieldName].wipe(); }
		for (var fieldName in this.uint32s) { this.uint32s[fieldName].wipe(); }
	}

	clear(): void {
		for (var fieldName in this.uint8s) { delete this.uint8s[fieldName]; }
		for (var fieldName in this.uint32s) { delete this.uint32s[fieldName]; }
	}

	wipe = wipe;
	
}

Object.freeze(ArrFactory);
Object.freeze(ArrFactory.prototype);


/**
 * This zeros all elements of given arrays, or given array views.
 * Use this function on things that needs secure cleanup, but should not be
 * recycled due to their odd and/or huge size, as it makes pooling inefficient.
 */
export function wipe(...arrays): void {
	var arr;
	for (var i=0; i<arrays.length; i+=1) {
		arr = arrays[i];
		if (!arr) continue;
		try {
			for (var j=0; j<arr.length; j+=1) { arr[j] = 0; }
		} catch (e) {}
	}
}


Object.freeze(exports);