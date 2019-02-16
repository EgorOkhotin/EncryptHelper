import reqwest = require("./reqwest");

const loadPageDelay = 500;
const pageCache = { chosePage: "", settingsPage: "", encryptionPage: "" };
const passwordsInfo = { passwordCache: [], passwordCount: 0, minPasswordLength: 4 };

function forEach(array : HTMLCollectionOf<Element>, elementFunction : Function) {
    for (let index = 0; index < array.length; index++) {
        elementFunction(array[index]);
    }
}

function forwardPageLoad() {
    let elements = document.getElementsByClassName("movable-onload");
    let hidden = document.getElementsByClassName("hidden")[0];
    if (typeof elements !== "undefined") {
        forEach(elements, (element : Element) => {
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
        forEach(elements, (element:Element) => {
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
        forEach(elements, (element:Element) => {
            element.classList.add("bounceOutLeft");
            element.classList.add("animated");
        })
    }
}

function previousPageAnimate() {
    let elements = document.getElementsByClassName("movable-exit");
    if (typeof elements !== "undefined") {
        forEach(elements, (element:Element) => {
            element.classList.add("bounceOutRight");
            element.classList.add("animated");
        });
    }
}

function getTransformedText(text:string, direction:string, callback:Function) {
    reqwest({
        url: "/Home/Encryption",
        method: "post",
        data: { text: text, direction: direction },
        success: (data:string)=>{ callback(data);} 
    });
}

function postRequest(requestData : object, url:string, callback:Function, failCallback:Function) {
    reqwest({
        url:url,
        method:"post",
        data:requestData,
        success: (response:string) => {callback(response);},
        error: (response:string)=>{failCallback(response);}
    });
}

function getRequest(url : string, callback : Function, failCallback : Function) {
    reqwest({
        url:url,
        method: "get",
        success: (response:string)=>{callback(response);},
        error: (response:string)=>{failCallback(response);},
    })
}

function loadPage(direction : string) {
    if (direction === "back") {
        backPageLoad();
    }
    else { forwardPageLoad(); }
}

function nextPage(data:string) {
    nextPageWithTimeOut(data, loadPageDelay);
}

function nextPageWithTimeOut(data:string, timeOut:number) {
    nextPageAnimate();
    let container = document.getElementById("mainContainer");
    setTimeout(() => {
        container.innerHTML = data;
        forwardPageLoad();
    }, timeOut);
     
}

function previousPage(data:string) {
    previousPageAnimate();
    let container = document.getElementById("mainContainer");
    setTimeout(() => {
        container.innerHTML = data;
        backPageLoad();
    }, loadPageDelay);
}

function deleteData() {
    postRequest(null, "/Home/EmergencyDeleteData", () => { }, () => { });
}

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

    function nextPageCallback(data:string) {
		pageCache.settingsPage = data;
        nextPage(data);
    }

    function errorCallback(data:string) {
        alert('' + data);
    }

    function nextPageRequest(data:object) {
        postRequest(data, "/Home/Chose", nextPageCallback, errorCallback);
    }

    return {
        choseSecret: choseSecret,
        choseTopSecret: choseTopSecret,
        choseProtected: choseProtected
    }
})();

const settingsPage = (function () {
	
	function getRandomPassword(charCount:number, callback:Function) {
    let result = "";
    getRequest("/Home/GetRandomPassword?charCount=" + charCount, 
    function (data:string) {
        console.log("Get random password result: " + data);
        result = data;
        callback(result);
    },
    function (error:string) {
        console.log("Get random password failed")
        result = "400";
        callback("Bad request 400");
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
            return charCount >= passwordsInfo.minPasswordLength;
        }
    }

    function getCharCount() {
        return (<any>document.getElementById("numberBox")).value;
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
        let charNumbers:number = getCharCount();
        if (charNumbers < 4) charNumbers = 4;
    }

    function passwordChecker(id:number) {
        
        let isValidPasswords = true;

        refreshPasswordsCount();
        refreshPasswordsChache(id);
        
        for (let i = 0; i < passwordsInfo.passwordCount; i++) {
            let element = (<HTMLInputElement>document.getElementById("Passwords_" + i + "_"));
            if (element.value.length < passwordsInfo.minPasswordLength) {
                isValidPasswords = false;
                break;
            }
        }

        enableButton(isValidPasswords);
    }

    function refreshPasswordsCount(){
        let passCount = (<any>document.getElementById("PasswordsCount")).value;
        if (passwordsInfo.passwordCount !== passCount) {
            passwordsInfo.passwordCount = passCount;
        }
    }

    function refreshPasswordsChache(id:number){
        let passwordId = "Passwords_" + id + "_";
        let changedPassword = (<HTMLInputElement>document.getElementById(passwordId)).value;
        if (passwordsInfo.passwordCache.length < (id + 1)) {
            passwordsInfo.passwordCache.push(changedPassword);
        }
        else{
            passwordsInfo.passwordCache[id] = changedPassword;
        }
    }

    function enableButton(isValidPasswords: boolean){
        let button = (<HTMLInputElement>document.getElementById("submitPasswords"));
        if (isValidPasswords) {
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

    function nextPageCallback(data:string) {
		pageCache.encryptionPage = data;
        nextPage(data);
    }

    function errorCallback(data:string) {
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

    function transformText(text:string, direction:string) {
        getTransformedText(text, direction, transformCallback);
    }

    function transformCallback(text:string) {
        let textBox = (<HTMLTextAreaElement>document.getElementById("textBox"));
        textBox.value = text;
    }

    function changeEncryptionDirection(direction:string) {
        if (direction === 'encryption') {
            let checkbox = (<HTMLInputElement>document.getElementById('decryptionCheckbox'));
            checkbox.checked = false;
        }
        else {
            let checkbox = (<HTMLInputElement>document.getElementById('encryptionCheckbox'));
            checkbox.checked = false;
        }
    }

    function isValidDirection() {
        let checkbox = (<HTMLInputElement>document.getElementById('decryptionCheckbox'));
        if (checkbox.checked) return true;
        checkbox = (<HTMLInputElement>document.getElementById('encryptionCheckbox'));
        if (checkbox.checked) return true;
        else return false;
    }

    function isNotEmptyText() {
        let text = getTextboxValue();
        return (text !== '' || text !== null);
    }

    function getTextboxValue() {
        return (<HTMLTextAreaElement>document.getElementById("textBox")).value;
    }

    function getTransformDirection() {
        let checkbox = <HTMLInputElement>document.getElementById('decryptionCheckbox');
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
