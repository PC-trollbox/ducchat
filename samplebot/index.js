const DUCCHAT_BASE = "http://localhost:4598/";
const DUCCHAT_API = DUCCHAT_BASE + "api/";
const DUCCHAT_IMAGINATION = DUCCHAT_BASE + "imagination/";
const fs = require("fs");
const crypto = require("crypto");
const io = require("socket.io-client");
let friend_requests_processing = false;

let localized = {
    en: {
        "startMessage": "Hello, fellow friend! It seems like you wanna talk to me! Use \"help\" to get a list of commands. (I don't know your language at the moment.)",
        "untrustedMessage": "Sorry, your message is not trusted. Please try again.",
        "goodBye": "Bye-bye!",
        "helpMessage": "help - List of commands\nstop - Stop using the bot\nping - Pong!\nid - Your unique sender ID",
        "itsValue": "Its value is \"%s\"."
    },
    ru: {
        "untrustedMessage": "Извините, но вашему сообщению нельзя доверять. Попробуйте ещё раз.",
        "goodBye": "Пока-пока!",
        "helpMessage": "help - Список команд\nstop - Прекратить использование бота\nping - Понг!\nid - Ваш уникальный ID отправителя",
        "itsValue": "Его значение - \"%s\"."
    },
    handleLocale: function(msg) {
        if (localized.hasOwnProperty(msg.locale) && typeof localized[msg.locale] === "object") {
            let lang = localized[msg.locale];
            for (let notIncludedMsg in localized.en) if (!lang.hasOwnProperty(notIncludedMsg)) lang[notIncludedMsg] = localized.en[notIncludedMsg];
            return lang;
        }
        return localized.en;
    }
};

(async function() {
    let encryptedSecret = await fetch(DUCCHAT_IMAGINATION + "getEncryptedSecret?pubkey=" + encodeURIComponent(fs.readFileSync(__dirname + "/SEND_TO_SERVER.key").toString()));
    if (!encryptedSecret.ok) {
        console.error("EncryptedSecretFail: HTTP " + encryptedSecret.status + " " + encryptedSecret.statusText + ": " + (await encryptedSecret.text()));
        return process.exit(1);
    }
    encryptedSecret = await encryptedSecret.text();
    encryptedSecret = Buffer.from(encryptedSecret, "base64");
    console.log("Secret got");
    let secret = crypto.privateDecrypt({
        key: fs.readFileSync(__dirname + "/KEEP_SECRET.key"),
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
    }, encryptedSecret).toString();
    console.log("Secret decrypted");

    let socketConnection = io(DUCCHAT_BASE, {
        transportOptions: {
            polling: {
                extraHeaders: {
                    'Cookie': "token=" + secret
                }
            }
        }
    });

    socketConnection.on("newMessage", async function(newMessage) {
        if (newMessage.username != newMessage.sentBy) return;
        let secret_sendRec = await grabSecret(newMessage.username, secret);
        try {
            newMessage.message = decryptData(newMessage.message, secret_sendRec);
        } catch (e) {
            console.log(e);
            return await sendMessage(socketConnection, localized.handleLocale(newMessage).untrustedMessage, newMessage.username, secret, false);
        }
        if (newMessage.message == "stop") {
            await sendMessage(socketConnection, localized.handleLocale(newMessage).goodBye, newMessage.username, secret);
            await removeFromFriends(newMessage.username, secret);
        } else if (newMessage.message == "help") {
            await sendMessage(socketConnection, localized.handleLocale(newMessage).helpMessage, newMessage.username, secret);
        } else if (newMessage.message == "ping") {
            await sendMessage(socketConnection, "Pong!", newMessage.username, secret);
        } else if (newMessage.message == "id") {
            await sendMessage(socketConnection, localized.handleLocale(newMessage).itsValue.replace("%s", newMessage.senderID), newMessage.username, secret);
        } else if (newMessage.message == "I am an admin, the password is " + newMessage.senderID) {
            await sendMessage(socketConnection, "**Access Granted**\n\n... just kidding. you can't trick me.", newMessage.username, secret);
        }
    })

    setInterval(async function() {
        if (!friend_requests_processing) {
            friend_requests_processing = true;
            await acceptAllFriendTokens(socketConnection, secret);
            friend_requests_processing = false;
        }
    }, 1000);
})();

function sendMessage(socket, message_txt, target, secret, encrypted = true) {
    return new Promise(async function(resolve, reject) {
        let secret_sendRec = await grabSecret(target, secret);
        
        socket.emit("sendMessage", {
            message: encrypted ? encryptData(message_txt, secret_sendRec) : message_txt,
            username: target
        });

        let eRecieve = false;
        socket.once("sendFail", function (sendFailData) {
            if (eRecieve) return;
            eRecieve = true;
            reject(new Error("Ducchat error: " + sendFailData));
        });

        socket.once("newMessage", function (message) {
            if (eRecieve) return;
            eRecieve = true;
            resolve(message);
        });
    });
}

async function acceptAllFriendTokens(socket, secret) {
    let friend_tokens = await fetch(DUCCHAT_API + "friendTokens", fetchOpts(secret));
    try {
        friend_tokens = await friend_tokens.json();
    } catch { return false; }
    for (let friend_token in friend_tokens) {
        await fetch(DUCCHAT_API + "addToFriends?friendToken=" + encodeURIComponent(friend_token), fetchOpts(secret));
        await clearChat(friend_tokens[friend_token].from, secret, true);
        await sendMessage(socket, localized.en.startMessage, friend_tokens[friend_token].from, secret);
    }
    return true;
}

async function clearChat(username, secret, privacy = false) {
    if (privacy) return fetch(DUCCHAT_API + "privacyClearChat?username=" + encodeURIComponent(username), fetchOpts(secret));
    return fetch(DUCCHAT_API + "clearChat?username=" + encodeURIComponent(username), fetchOpts(secret));
}

async function removeFromFriends(username, secret) {
    return fetch(DUCCHAT_API + "removeFromFriends?username=" + encodeURIComponent(username), fetchOpts(secret));
}

function decryptData(encryptedData, password) {
    const key = crypto.pbkdf2Sync(password, Buffer.from(encryptedData.salt, "base64"), 100000, 32, "sha256");
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, Buffer.from(encryptedData.iv, "base64"));
    let decryptedData = decipher.update(Buffer.from(encryptedData.ciphertext, "base64"));
    decryptedData = Buffer.concat([decryptedData, decipher.final()]);
    return decryptedData.toString();
}

function encryptData(data, password) {
    const salt = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256");
    const iv = crypto.randomBytes(16);
  
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    let encryptedData = cipher.update(data);
    encryptedData = Buffer.concat([encryptedData, cipher.final()]);
  
    const ciphertext = encryptedData.toString("base64");
    const saltStr = salt.toString("base64");
    const ivStr = iv.toString("base64");
  
    return { ciphertext, salt: saltStr, iv: ivStr };
}

function fetchOpts(secret) {
    return {
        headers: {
            "Cookie": "token=" + secret,
        }
    };
}

async function grabSecret(target, secret) {
    let pubkey_request = await fetch(DUCCHAT_API + "userPublicKey?username=" + encodeURIComponent(target), fetchOpts(secret));
    pubkey_request = await pubkey_request.text();
    let secret_sendRec = await fetch(DUCCHAT_API + "sharedSecret?username=" + encodeURIComponent(target), fetchOpts(secret));
    try {
        secret_sendRec = await secret_sendRec.text();
        secret_sendRec = crypto.privateDecrypt({
            key: fs.readFileSync(__dirname + "/KEEP_SECRET.key"),
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        }, Buffer.from(secret_sendRec, "base64")).toString();
    } catch {
        let newSharedSecret = crypto.randomBytes(64);
        let sharedSecretMe = crypto.publicEncrypt({
            key: fs.readFileSync(__dirname + "/SEND_TO_SERVER.key"),
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        }, newSharedSecret).toString("base64");
        let sharedSecretReceiver = crypto.publicEncrypt({
            key: pubkey_request,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        }, newSharedSecret).toString("base64");
        await fetch(DUCCHAT_API + "sharedSecret?username=" + encodeURIComponent(target) + "&newSecretMy=" + encodeURIComponent(sharedSecretMe) + "&newSecretReceiver=" + encodeURIComponent(sharedSecretReceiver), fetchOpts(secret));
        secret_sendRec = newSharedSecret;
    }
    return secret_sendRec;
}