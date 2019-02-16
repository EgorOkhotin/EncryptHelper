/// <binding Clean='clean' />
"use strict";

var gulp = require("gulp"),
    concat = require('gulp-concat'),
    uglify = require('gulp-uglify-es').default,
    cssMin = require('gulp-cssmin'),
    rename = require('gulp-rename'),
    reload = require('browser-sync').reload,
    clean = require('gulp-clean'),
    ts = require('gulp-typescript'),
    sass = require("gulp-sass");

var paths = {
    scripts:{
        source: "./Content/Scripts/src/",
        tsFiles: "./Content/Scripts/src/*.ts",
        tmp: "./Content/Scripts/tmp/",
        bin: "./Content/Scripts/lib/"
    },
    css:{
        source: "./Content/CSS/src/",
        scssFiles: "./Content/CSS/src/*.scss",
        bin:"./Content/CSS/lib/"
    },
    allFonts: "./Content/CSS/fonts/*",
    media: "./Content/Media/*"
};

var releasePaths = {
    webroot: "./wwwroot/",
    css: "./wwwroot/css",
    js: "./wwwroot/js",
    fonts: "./wwwroot/fonts"
};

///
///     JS
///

gulp.task("ts-compile",function(){
    return gulp.src(paths.scripts.tsFiles)
    .pipe(ts())
    .pipe(rename("compiled.js"))
    .pipe(gulp.dest(paths.scripts.tmp))
});

gulp.task("js-prepare", function(){
    return gulp.src(paths.scripts.source + "*.js")
    .pipe(gulp.dest(paths.scripts.tmp));
});

gulp.task("clear-scripts-bin", function(){
    return gulp.src(paths.scripts.bin + "*")
    .pipe(clean());
});

gulp.task("js-concat", function(){
    return gulp.src(paths.scripts.tmp + "*.js")
    .pipe(concat("site.js"))
    .pipe(clean({}))
    .pipe(gulp.dest(paths.scripts.bin));
});

gulp.task("js-min", function () {
    return gulp.src(paths.scripts.bin + "*.js")
        .pipe(rename("site.min.js"))
        .pipe(uglify())
        .pipe(gulp.dest(paths.scripts.bin));
});

gulp.task("js-deploy", function(){
    return gulp.src(paths.scripts.bin + "*.js")
    .pipe(gulp.dest(releasePaths.js));
});

gulp.task('js-compile', gulp.series('clear-scripts-bin','ts-compile', 'js-prepare'));

/// 
///     CSS
///
gulp.task("clean-css-bin", function(){
    return gulp.src(paths.css.bin + "*")
    .pipe(clean());
});

gulp.task("sass", function() {
    return gulp.src(paths.css.scssFiles)
        .pipe(concat("concat.scss"))
        .pipe(sass())
        .pipe(rename("site.css"))
        .pipe(gulp.dest(paths.css.bin));
});

gulp.task("css-min", function () {
    return gulp.src(paths.css.bin)
        .pipe(cssMin())
        .pipe(rename("site.min.css"))
        .pipe(gulp.dest(releasePaths.css));
});

gulp.task("css-deploy", function () {
    return gulp.src(paths.css.bin + "*.css")
    .pipe(gulp.dest(releasePaths.css));
});

gulp.task('css-processing', gulp.series('clean-css-bin', 'sass'));


///
///     OTHER
///
gulp.task("deploy-fonts", function () {
    return gulp.src([paths.allFonts])
        .pipe(gulp.dest(releasePaths.fonts));
});


///
/// COMMON
///
gulp.task('compile', gulp.series('js-compile', 'css-processing'));

gulp.task('concat', gulp.series('js-concat'));

gulp.task('minimize', gulp.series('js-min','css-min'));

gulp.task('deploy', gulp.series('js-deploy', 'css-deploy'));

///
/// GENERAL
///
gulp.task("build-release", gulp.series('compile','concat','minimize', 'deploy'));

gulp.task("build-debug", gulp.series('compile','concat', 'deploy'));





