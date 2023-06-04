const DUCCHAT_API = "http://localhost:4598/api/";
const DUCCHAT_IMAGINATION = "http://localhost:4598/imagination/";
const fs = require("fs");
const crypto = require("crypto");
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

    setInterval(async function() {
        if (!friend_requests_processing) {
            friend_requests_processing = true;
            await acceptAllFriendTokens(secret);
            await handleNewMessages(secret);
            friend_requests_processing = false;
        }
    }, 1000);
})();

async function sendMessage(message_txt, target, secret, encrypted = true) {
    let pubkey_request = await fetch(DUCCHAT_API + "userPublicKey?username=" + encodeURIComponent(target), {
        headers: {
            "Cookie": "token=" + secret,
        }
    });
    pubkey_request = await pubkey_request.text();
    let message = await fetch(DUCCHAT_API + "message", {
        headers: {
            "Cookie": "token=" + secret,
            "Content-Type": "application/json"
        },
        method: "POST",
        body: JSON.stringify({
            "message-myhist": encrypted ? crypto.publicEncrypt({
                key: fs.readFileSync(__dirname + "/SEND_TO_SERVER.key"),
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            }, message_txt).toString("base64") : message_txt,
            "message-userhist": encrypted ? crypto.publicEncrypt({
                key: pubkey_request,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            }, message_txt).toString("base64") : message_txt,
            username: target
        })
    });
    let server_reply = await message.text();
    if (!message.ok) throw new Error("Ducchat error: " + server_reply + " (HTTP " + message.status + " " + message.statusText + ")");
    return server_reply;
}

async function acceptAllFriendTokens(secret) {
    let friend_tokens = await fetch(DUCCHAT_API + "friendTokens", {
        headers: {
            "Cookie": "token=" + secret,
        }
    });
    try {
        friend_tokens = await friend_tokens.json();
    } catch { return false; }
    for (let friend_token in friend_tokens) {
        await fetch(DUCCHAT_API + "addToFriends?friendToken=" + encodeURIComponent(friend_token), {
            headers: {
                "Cookie": "token=" + secret,
            }
        });
        await clearChat(friend_tokens[friend_token].from, secret, true);
        await sendMessage(localized.en.startMessage, friend_tokens[friend_token].from, secret);
    }
    return true;
}

async function clearChat(username, secret, privacy = false) {
    if (privacy) return fetch(DUCCHAT_API + "privacyClearChat?username=" + encodeURIComponent(username), {
            headers: {
                "Cookie": "token=" + secret,
            }
        });
    else return fetch(DUCCHAT_API + "clearChat?username=" + encodeURIComponent(username), {
            headers: {
                "Cookie": "token=" + secret,
            }
        });
}

async function handleNewMessages(secret) {
    let contacts = await fetch(DUCCHAT_API + "contacts", {
        headers: {
            "Cookie": "token=" + secret,
        }
    });
    try {
        contacts = await contacts.json();
    } catch { return false; }
    for (let contact of contacts) {
        let recent_messages = await fetch(DUCCHAT_API + "messages?username=" + encodeURIComponent(contact) + "&limit=1", {
            headers: {
                "Cookie": "token=" + secret,
            }
        });
        try { recent_messages = await recent_messages.json(); } catch { continue }
        recent_messages = recent_messages[0];
        if (!recent_messages) continue
        if (recent_messages.sentBy != recent_messages.username) continue;
        try {
            recent_messages.message = crypto.privateDecrypt({
                key: fs.readFileSync(__dirname + "/KEEP_SECRET.key"),
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            }, Buffer.from(recent_messages.message, "base64")).toString();
        } catch {
            await sendMessage(localized.handleLocale(recent_messages).untrustedMessage, contact, secret, false);
            continue;
        }
        if (recent_messages.message == "stop") {
            await sendMessage(localized.handleLocale(recent_messages).goodBye, contact, secret);
            await removeFromFriends(contact, secret);
        } else if (recent_messages.message == "help") {
            await sendMessage(localized.handleLocale(recent_messages).helpMessage, contact, secret);
        } else if (recent_messages.message == "ping") {
            await sendMessage("Pong!", contact, secret);
        } else if (recent_messages.message == "id") {
            await sendMessage(localized.handleLocale(recent_messages).itsValue.replace("%s", recent_messages.senderID), contact, secret);
        }
    }
}

async function removeFromFriends(username, secret) {
    return fetch(DUCCHAT_API + "removeFromFriends?username=" + encodeURIComponent(username), {
        headers: {
            "Cookie": "token=" + secret,
        }
    });
}