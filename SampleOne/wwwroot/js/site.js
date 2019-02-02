// Please see documentation at https://docs.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Write your JavaScript code.

function forwardPageLoad() {
    let elements = document.getElementsByClassName("movable-onload");
    let hidden = document.getElementsByClassName("hidden")[0];
    $.each(elements, (index, element) => {
        element.classList.add("bounceInRight");
        element.classList.add("animated");
    });
    if (hidden !== null)
        hidden.classList.remove("hidden");
}

function backPageLoad() {
    let elements = document.getElementsByClassName("movable-onload");
    let hidden = document.getElementsByClassName("hidden")[0];
    $.each(elements, (index, element) => {
        element.classList.add("bounceInLeft");
        element.classList.add("animated");
    });
    if (hidden !== null)
        hidden.classList.remove("hidden");
}

function pageNext() {
    let elements = document.getElementsByClassName("movable-exit");
    $.each(elements, (index, element) => {
        element.classList.add("bounceOutLeft");
        element.classList.add("animated");
    });
}

function pageBack() {
    let elements = document.getElementsByClassName("movable-exit");
    $.each(elements, (index, element) => {
        element.classList.add("bounceOutRight");
        element.classList.add("animated");
    });
}
