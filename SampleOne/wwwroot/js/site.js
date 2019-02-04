// Please see documentation at https://docs.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Write your JavaScript code.

function forwardPageLoad() {
    let elements = document.getElementsByClassName("movable-onload");
    let hidden = document.getElementsByClassName("hidden")[0];
    if (typeof elements !== "undefined") {
        $.each(elements, (index, element) => {
            element.classList.add("bounceInRight");
            element.classList.add("animated");
        });
    }
    if (typeof hidden !== "undefined")
        hidden.classList.remove("hidden");
}

function backPageLoad() {
    let elements = document.getElementsByClassName("movable-onload");
    let hidden = document.getElementsByClassName("hidden")[0];
    if (typeof elements !== "undefined") {
        $.each(elements, (index, element) => {
            element.classList.add("bounceInLeft");
            element.classList.add("animated");
        });
    }
    if (typeof hidden !== "undefined")
        hidden.classList.remove("hidden");
}

function pageNext() {
    let elements = document.getElementsByClassName("movable-exit");
    if (typeof elements !== "undefined") {
        $.each(elements, (index, element) => {
            element.classList.add("bounceOutLeft");
            element.classList.add("animated");
        });
    }
}

function pageBack() {
    let elements = document.getElementsByClassName("movable-exit");
    if (typeof elements !== "undefined") {
        $.each(elements, (index, element) => {
            element.classList.add("bounceOutRight");
            element.classList.add("animated");
        });
    }
}

function getRandomPassword(charCount, callback) {
    let result = "";
    $.get("/Home/GetRandomPassword?charCount=" + charCount).done(function (data) {
        console.log("Get random password result: " + data);
        result = data;
        callback(result);
    }).fail(function () {
        console.log("Get random password failed")
        result = "400";
        callback(result);
    }); 
}

function getTransformedText(text, direction, callback) {
    let result = ""
    $.ajax({
        url: "/Home/TransformText",
        data: { text: text, direction: direction },
        success: (data) => { callback(data); },
        dataType: "text"
    });
}
