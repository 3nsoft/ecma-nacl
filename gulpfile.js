/**
 * 
 */

var gulp = require('gulp');
var typescript = require('gulp-typescript');
var merge = require('merge2');
var browserify = require('browserify');
var source = require('vinyl-source-stream');
var streamify = require('gulp-streamify');
var uglify = require('gulp-uglify');
var rename = require('gulp-rename');
var nodeunit = require("gulp-nodeunit-runner");

var SRC = 'src';
var DIST = 'dist';

gulp.task('lib', function() {
	return gulp.src(SRC+'/lib/**/*.ts')
	.pipe(typescript({
		target: 'ES5',
		module: 'commonjs'
	}))
	.js.pipe(gulp.dest(DIST+'/lib'));
});

/**
 * Note that currently generated declarations should go through editing
 * process, so as to be useful in things like DefinitelyTyped.
 */
gulp.task('lib-declarations', function() {
	return gulp.src(SRC+'/lib/**/*.ts')
	.pipe(typescript({
		target: 'ES5',
		module: 'commonjs',
		declarationFiles: true
	}))
	.dts.pipe(gulp.dest(DIST+'/lib-declarations'));
});

gulp.task('lib-browser', function() {
	return browserify()
	.require(__dirname+'/'+SRC+'/lib/ecma-nacl.ts',
			{ expose: 'ecma-nacl' })
	.plugin('tsify', {
		target: 'ES5',
		module: 'commonjs'
	})
	.bundle()
	.pipe(source('ecma-nacl.js'))
	.pipe(gulp.dest(DIST+'/lib-browser'));
});

gulp.task('lib-browser-min', ['lib-browser'], function() {
	return gulp.src(DIST+'/lib-browser/ecma-nacl.js')
	.pipe(streamify(uglify()))
	.pipe(rename('ecma-nacl.min.js'))
	.pipe(gulp.dest(DIST+'/lib-browser'));
});

function browserifyTS(path) {
	return browserify()
	.add(__dirname+'/'+SRC+'/tests/in-browser/'+path)
	.external('ecma-nacl')
	.plugin('tsify', {
		target: 'ES5',
		module: 'commonjs'
	})
	.bundle()
	.pipe(source(path.substring(0, path.length-2)+'js'));
}

gulp.task('test-browser', ['lib-browser'], function() {
	return merge(
			browserifyTS('ecma-nacl_runs/index.ts'),
			browserifyTS('ecma-nacl_runs/worker.ts'),
			browserifyTS('comparison/index.ts'),
			browserifyTS('comparison/worker.ts'),
			gulp.src([ DIST+'/lib-browser/ecma-nacl.js',
	                   SRC+'/tests/in-browser/**/*.js',
	                   SRC+'/tests/in-browser/**/*.html' ]))
	.pipe(gulp.dest(DIST+'/test-browser'));
});

gulp.task('test-node', ['lib'], function() {
	var ts = gulp.src([ SRC+'/tests/**/*.ts',
	                  '!'+SRC+'/tests/in-browser/**/*.ts',
	                  SRC+'/typings/**/*.ts' ])
	.pipe(typescript({
		target: 'ES5',
		module: 'commonjs'
	}))
	.js;
	var cp = gulp.src(SRC+'/tests/in-browser/ext-libs/js-scrypt.js')
	.pipe(rename('performance/js-scrypt.js'));
	return merge(ts, cp)
	.pipe(gulp.dest(DIST+'/test-node'));
});

gulp.task('run-unittest', [ 'test-node' ], function() {
	var tests = [ DIST+'/test-node/boxes/*.js',
	              DIST+'/test-node/file/*.js',
	              DIST+'/test-node/hash/*.js',
	              DIST+'/test-node/scrypt/*.js',
	              DIST+'/test-node/sign/*.js' ];
	return gulp.src(tests)
	.pipe(nodeunit());
});

gulp.task('run-performance', [ 'test-node' ], function() {
	require('./'+DIST+'/test-node/performance/ecma-nacl_runs');
});

gulp.task('run-comparison', [ 'test-node' ], function() {
	require('./'+DIST+'/test-node/performance/comparison');
});

gulp.task('compile-dist', [ 'lib', 'lib-browser', 'lib-browser-min' ]);
gulp.task('compile-all', [ 'compile-dist', 'test-node', 'test-browser' ]);

gulp.task('default', [ 'compile-dist' ]);

gulp.task('help', function() {
	var h = '\nThe following gulp tasks are defined:\n'+
		'\t1) "compile-dist" (current default) task compiles library for both'+
		' node and browser distributions (see dist/);\n'+
		'\t2) "compile-all" task compiles both distribution and test code;\n'+
		'\t3) "run-unittest" task runs unit tests;\n'+
		'\t4) "run-performance" task runs timing code;\n'+
		'\t5) "run-comparison" task runs comparisons to other NaCl implementing'+
		' libraries.\n\n'+
		'After complete compilation, one may run performance and comparison'+
		' code in browser, opening test pages, located in dist/test-browser'+
		' folder.';
	console.log(h+'\n');
});
