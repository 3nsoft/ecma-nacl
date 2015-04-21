/* Copyright(c) 2013 - 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */
/*
 * All code for Ecma-NaCl comparison to other libs.
 */

/// <reference path="../../../typings/tsd.d.ts" />

import util = require('../util');
import comp = require('./comparison-runs');

// here we have stuff specific to running tests in UI event loop. 
(<any> window).runTestsInUIEventLoop = () => {
	util.logTestResult("=== Start running tests in browser's main loop ===");
	var tests =
		[ () => { comp.timeBoxEncryption(20, 4); },
		  () => { comp.timeBoxEncryption(10, 40); },
		  () => { comp.timeSecretBoxEncryption(100, 4); },
		  () => { comp.timeSecretBoxEncryption(50, 64); },
		  () => { comp.timeSecretBoxEncryption(10, 1024); }
		  ];
	var testNum = 0;
	// This will be a recursion through setTimeout
	function run() {
		if (testNum >= tests.length) {
			util.logTestResult(
				"### Test run in browser's main loop is complete. ###");
			return;
		}
		try {
			tests[testNum]();
			testNum += 1;
		} catch (e) {
			util.logTestResult("logged to the console: "+e.message, true);
			console.error(e);
			return;
		}
		setTimeout(run, 10);
	}
	run();
};


(<any> window).clearLog = util.clearLog;

var testWorker: Worker = null;
var testCounter = 0;

function initWebWorker(): Worker {
	if (testWorker) { return null; }
	try {
		testWorker = new Worker("./worker.js");
	} catch (e) {
		console.error(e);
		var logMsg = 
			'Chances are that local script file is not allowed to be read.\n'+
			'For testing only make following changes:\n'+
			'\tFirefox: in about:config, set \n'+
			'\t\tsecurity.fileuri.strict_origin_policy === false \n'+
			'\tChrome:  run Chrome with the \n'+
			'\t\t--allow-file-access-from-files flag set.';
		alert('Cannot instantiate web worker.\n'+
			'Error is logged to a console.\n'+logMsg);
		return null;
	}
	testWorker.addEventListener('message', function(e) {
		if (e.data.logMsg) {
			util.logTestResult(e.data.logMsg);
		}
		if (e.data.errMsg) {
			util.logTestResult("ERROR in web worker: "+e.data.errMsg);
		}
		if (e.data.done) {
			testCounter -= 1;
		}
		if (testCounter < 1) {
			util.logTestResult(
				"### Batch of test runs in web worker is complete. ###");
			testWorker.terminate();
			testWorker = null;
		}
	});
	return testWorker;
}

(<any> window).startTestsInWebWorker = () => {
	if (testWorker) {
		alert("Previous batch of tests has not completed its run, yet.\n"+
			"Wait a little.");
		return;
	}
	var w = initWebWorker();
	util.logTestResult("=== Start running tests in web worker ===");
	comp.startBoxEncryption(w, 100, 4);
	testCounter += 1;
	comp.startBoxEncryption(w, 100, 40);
	testCounter += 1;
	comp.startSecretBoxEncryption(w, 100, 4);
	testCounter += 1;
	comp.startSecretBoxEncryption(w, 100, 64);
	testCounter += 1;
	comp.startSecretBoxEncryption(w, 10, 1024);
	testCounter += 1;
}
