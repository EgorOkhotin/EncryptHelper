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

function nextPageAnimate() {
    let elements = document.getElementsByClassName("movable-exit");
    if (typeof elements !== "undefined") {
        $.each(elements, (index, element) => {
            element.classList.add("bounceOutLeft");
            element.classList.add("animated");
        });
    }
}

function previousPageAnimate() {
    let elements = document.getElementsByClassName("movable-exit");
    if (typeof elements !== "undefined") {
        $.each(elements, (index, element) => {
            element.classList.add("bounceOutRight");
            element.classList.add("animated");
        });
    }
}

function getTransformedText(text, direction, callback) {
    let result = ""
    $.ajax({
        type: "POST",
        url: "/Home/Encryption",
        data: { text: text, direction: direction },
        success: (data) => { callback(data); },
        dataType: "text"
    });
}

function postRequest(requestData, url, callback, failCallback) {
    $.post(url, requestData)
    .done(function (responseData) {
        callback(responseData);
    }).fail(function (responseData) {
        failCallback(responseData);
    });
}

function getRequest(url, callback, failCallback) {
    $.get(url)
        .done(function (responseData) {
            callback(responseData);
        })
        .fail(function (responseData) {
            failCallback(failCallback);
        });
}

function loadPage(direction) {
    if (direction === "back") {
        backPageLoad();
    }
    else { forwardPageLoad(); }
}

function nextPage(data) {
    nextPageWithTimeOut(data, 300);
}

function nextPageWithTimeOut(data, timeOut) {
    nextPageAnimate();
    let container = document.getElementById("mainContainer");
    setTimeout(() => {
        container.innerHTML = data;
        forwardPageLoad();
    }, timeOut);
     
}

function previousPage(data) {
    previousPageAnimate();
    let container = document.getElementById("mainContainer");
    setTimeout(() => {
        container.innerHTML = data;
        backPageLoad();
    }, 200);
}

function deleteData() {
    postRequest("", "/Home/EmergencyDeleteData", () => { }, () => { });
}

const pageCache = { chosePage: "", settingsPage: "", encryptionPage: "" };
const passwordsInfo = { passwordCache: [], passwordCount: 0, minPasswordLength: 4 };

const chosePage = (function () {
    function choseProtected() {
        nextPageRequest({ selectedTypeNumber: "1" });
    }

    function choseSecret() {
        nextPageRequest({ selectedTypeNumber: "2" });
    }

    function choseTopSecret() {
        nextPageRequest({ selectedTypeNumber: "3" });
    }

    function nextPageCallback(data) {
		pageCache.settingsPage = data;
        nextPage(data);
    }

    function errorCallback(data) {
        alert('' + data);
    }

    function nextPageRequest(data) {
        postRequest(data, "/Home/Chose", nextPageCallback, errorCallback);
    }

    return {
        choseSecret: choseSecret,
        choseTopSecret: choseTopSecret,
        choseProtected: choseProtected
    }
})();

const settingsPage = (function () {
	
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

    function generatePassword() {
        if (isValidCharCount()) {
            getRandomPassword(getCharCount(), passwordCallBack);
        }
        else alert("Char count are wrong!");
    }

    function passwordCallBack(pass) {
        console.log("Generated password: " + pass);
        showPassword(pass);
    }

    function isValidCharCount() {
        let charCount = getCharCount();
        if (charCount !== null) {
            return charCount > 3;
        }
    }

    function getCharCount() {
        return document.getElementById("numberBox").value;
    }

    function showPassword(password) {
        hideModalElements();
        setTimeout(() => {
            let label = document.getElementById("resultPassword");
            label.innerText = password;
            label.classList.remove("fadeOut");
            label.classList.add("fadeIn", "animated");
            label.classList.remove("hidden");
        }, 300);
    }

    function hideModalElements() {
        let numberBox = document.getElementById("numberBox");
        let generateButton = document.getElementById("generateButton");
        let label = document.getElementById("resultPassword");

        numberBox.classList.add("fadeOut", "animated");
        generateButton.classList.add("fadeOut", "animated");
        label.classList.add("fadeOut", "animated");

        setTimeout(() => {
            numberBox.classList.add("hidden");
            generateButton.classList.add("hidden");
            label.classList.add("hidden");
        }, 200);
    }

    function showModalElements() {
        let numberBox = document.getElementById("numberBox");
        let generateButton = document.getElementById("generateButton");
        let label = document.getElementById("resultPassword");

        label.innerText = "Char count: ";
        label.classList.remove("fadeIn", "animated");
        numberBox.classList.remove("fadeOut", "animated", "hidden");
        generateButton.classList.remove("fadeOut", "animated", "hidden");
    }

    function charCountCorrection() {
        let numberBox = document.getElementById("numberBox");
        if (numberBox.value < 4) numberBox.value = 4;
    }

    function passwordChecker(id) {
        let button = document.getElementById("submitPasswords");
        let isNotEmptyPassword = true;

        if (passwordsInfo.passwordCount === 0) {
            passwordsInfo.passwordCount = document.getElementById("PasswordsCount").value;
        }

        let passwordId = "Passwords_" + id + "_";
        if (passwordsInfo.passwordCache.length < (id + 1)) {
            passwordsInfo.passwordCache.push(document.getElementById(passwordId).value);
        }
        else{
            passwordsInfo.passwordCache[id] = document.getElementById(passwordId).value;
        }
        
        for (let i = 0; i < passwordsInfo.passwordCount; i++) {
            let element = document.getElementById("Passwords_" + i + "_");
            if (element.value.length < passwordsInfo.minPasswordLength) {
                isNotEmptyPassword = false;
                break;
            }
        }

        if (isNotEmptyPassword) {
            button.disabled = false;
            button.classList.remove("disabled");
        }
        else {
            if (!button.disabled) {
                button.disabled = true;
                button.classList.add("disabled");
            }
        }
    }

    function gotoPreviousPage() {
        previousPage(pageCache.chosePage);
    }

    function submitEncryptionPasswords() {
        let data = { PasswordsCount: passwordsInfo.passwordCount, Passwords: passwordsInfo.passwordCache };
        postRequest(data, "/Home/Settings", nextPageCallback, errorCallback);
    }

    function nextPageCallback(data) {
		pageCache.encryptionPage = data;
        nextPage(data);
    }

    function errorCallback(data) {
        console.log(data);
        alert('' + data);
    }

    return {
        generatePassword: generatePassword,
        showModalElements: showModalElements,
        charCountCorrection: charCountCorrection,
        passwordChecker: passwordChecker,
        submitEncryptionPasswords: submitEncryptionPasswords,
        gotoPreviousPage: gotoPreviousPage
    }
})();

const encryptionPage = (function () {
	    function transform() {
        if (isValidDirection() && isNotEmptyText()) {
            transformText(getTextboxValue(), getTransformDirection());
        }
        else alert("Input parametrs are wrong!");
        
    }

    function transformText(text, direction) {
        getTransformedText(text, direction, transformCallback);
    }

    function transformCallback(text) {
        //console.log(text);
        let textBox = document.getElementById("textBox");
        textBox.value = text;
    }

    function changeEncryptionDirection(direction) {
        if (direction === 'encryption') {
            let checkbox = document.getElementById('decryptionCheckbox');
            checkbox.checked = false;
        }
        else {
            let checkbox = document.getElementById('encryptionCheckbox');
            checkbox.checked = false;
        }
    }

    function isValidDirection() {
        let checkbox = document.getElementById('decryptionCheckbox');
        if (checkbox.checked) return true;
        checkbox = document.getElementById('encryptionCheckbox');
        if (checkbox.checked) return true;
        else return false;
    }

    function isNotEmptyText() {
        let text = getTextboxValue();
        return (text !== '' || text !== null);
    }

    function getTextboxValue() {
        return document.getElementById("textBox").value;
    }

    function getTransformDirection() {
        let checkbox = document.getElementById('decryptionCheckbox');
        if (checkbox.checked) return "decrypt";
        else return "encrypt";
    }

    function gotoPreviousPage() {
        previousPage(pageCache.settingsPage);
    }
	
	return {
		transform: transform,
        changeEncryptionDirection: changeEncryptionDirection,
        gotoPreviousPage: gotoPreviousPage
	}
})();
