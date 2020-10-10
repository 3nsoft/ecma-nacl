/*
 Copyright(c) 2020 3NSoft Inc.
 This Source Code Form is subject to the terms of the Mozilla Public
 License, v. 2.0. If a copy of the MPL was not distributed with this
 file, you can obtain one at http://mozilla.org/MPL/2.0/.
*/

// NOTE: due to bad definition file, typescript below is not 100% type-strict.

const jas = new (require('jasmine'))();

const specsFromCLI: string[] = [];
for (let i=2; i<process.argv.length; i+=1) {
	specsFromCLI.push(process.argv[i]);
}

const ALL_SPECS = [
	'boxes/*.js',
	'hash/*.js',
	'scrypt/*.js',
	'signing/*.js',
	'util/*.js',
	'node-worker-threads/*.js'
];

jas.loadConfig({
	spec_dir: 'build/tests',
	spec_files: ((specsFromCLI.length > 0) ? specsFromCLI : ALL_SPECS)
});

jas.configureDefaultReporter({
	showColors: true
});

jas.execute();
