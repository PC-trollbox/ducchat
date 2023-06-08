const express = require("express");
const app = express();
const fs = require("fs");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const engine = require("jsembedtemplateengine");
const http = require("http").Server(app);
const io = require("socket.io")(http);
const cookie = require("cookie");
const he = require("he");
const execProcess = require("util").promisify(require('node:child_process').exec);
let friendTokens = {};
let tempSecTok = {};
let socketsForUser = {};
let productionEnvironment = false; // Makes JSON files smaller
if (process.env.NODE_ENV == "production") productionEnvironment = true;

app.use(cookieParser());
app.use(bodyParser.urlencoded({
	extended: true
}));
app.use(bodyParser.json());
engine(app, {
	embedOpen: "<nodejs-embed>",
	embedClose: "</nodejs-embed>"
});
app.set('views', '.')
app.set('view engine', 'jsembeds');

const user = {
	getUserByPubkey: function (pubk) {
		const username = Object.keys(this.db).find(user => this.db[user].pubkey == pubk);
		if (username) return { username: username, object: this.db[username] };
		return null;
	},
	getUserBySecret: function (secr) {
		const username = Object.keys(this.db).find(user => this.db[user].secret == secr);
		if (username) return { username: username, object: this.db[username] };
		return null;
	},
	getUserByName: (username) => user.db[username],
	setUser: function (name, data) {
		let snaps = this.db;
		snaps[name] = data;
		this.db = snaps;
	},
	deleteUser: function (name) {
		let snaps = this.db;
		delete snaps[name];
		this.db = snaps;
	},
	get db() {
		return JSON.parse(fs.readFileSync(__dirname + "/users.json"));
	},
	set db(val) {
		return fs.writeFileSync(__dirname + "/users.json", productionEnvironment ? JSON.stringify(val) : JSON.stringify(val, null, "\t"));
	}
}

function RequiredUserMiddleware(req, res, next) {
	if (req.cookies.token && user.getUserBySecret(req.cookies.token)) {
		req.user = user.getUserBySecret(req.cookies.token);
		return next();
	}
	res.clearCookie("token");
	res.redirect("/");
}

function fingerprint(key) {
	return "sha256:" + crypto.createHash("sha256").update(key).digest("base64").replaceAll("=", "");
}

function RequiredNoUserMiddleware(req, res, next) {
	if (!req.cookies.token || !user.getUserBySecret(req.cookies.token || "")) return next();
	res.redirect("/home");
}

function JustRecognizeUserMiddleware(req, res, next) {
	req.user = user.getUserBySecret(req.cookies.token || "");
	next();
}

function getLocalePath(file, AL, dirname = __dirname) {
	if (fs.existsSync(dirname + "/locale-" + String(AL).split(";")[0].split(",")[0].split("-")[0].split("_")[0].toLowerCase() + "/" + file)) return dirname + "/locale-" + String(AL).split(";")[0].split(",")[0].split("-")[0].split("_")[0].toLowerCase() + "/" + file;
	if (fs.existsSync(dirname + "/global/" + file)) return dirname + "/global/" + file;
	if (fs.existsSync(dirname + "/locale-" + String(AL).split(";")[0].split(",")[0].split("-")[0].split("_")[0].toLowerCase() + "/notImplemented.jsembeds")) return dirname + "/locale-" + String(AL).split(";")[0].split(",")[0].split("-")[0].split("_")[0].toLowerCase() + "/notImplemented.jsembeds";
	if (fs.existsSync(dirname + "/global/notImplemented.jsembeds")) return dirname + "/global/notImplemented.jsembeds";
	return __dirname + "/unknownFile.jsembeds";
}

app.get("/", RequiredNoUserMiddleware, (req, res) => res.render(getLocalePath("logonPage.jsembeds", req.headers["accept-language"])));

app.get("/ducchat.css", (req, res) => res.sendFile(__dirname + "/ducchat.css"));

app.get("/home", RequiredUserMiddleware, function (req, res) {
	res.render(getLocalePath("homePage.jsembeds", req.headers["accept-language"]), {
		username: he.encode(req.user.username),
		usernam_js: JSON.stringify(req.user.username)
	});
});

app.get("/logout", RequiredUserMiddleware, function (req, res) {
	res.clearCookie("token");
	res.redirect("/");
})

app.get("/register", RequiredNoUserMiddleware, (req, res) => res.render(getLocalePath("register.jsembeds", req.headers["accept-language"])));

app.post("/imagination/register", function (req, res) {
	if (!req.body.pubkey) return res.status(400).send("Bad request!");
	if (!req.body.username) return res.status(400).send("Bad request!");

	if (user.getUserByName(req.body.username)) return res.status(400).send("That user already exists! Try another one.");
	if (user.getUserByPubkey(req.body.pubkey)) return res.status(400).send("That public key is already taken! Try another one.");
	if (req.body.username == "system") return res.status(400).send("You attempted to impersonate the system user. You can't do that!");
	try {
		user.setUser(req.body.username, {
			pubkey: req.body.pubkey,
			secret: crypto.randomBytes(64).toString("hex"),
			friends: [],
			messages: [],
			recentlyChatted: [],
			uniqueSenderID: crypto.randomBytes(64).toString("hex")
		});
	} catch {
		return res.status(500).send("Something went terribly wrong when creating your account");
	}
	res.send("OK");
});

app.get("/imagination/getEncryptedSecret", RequiredNoUserMiddleware, function (req, res) {
	if (!user.getUserByPubkey(req.query.pubkey)) return res.status(401).send("Invalid public key: unregistered or blocked user?");
	try {
		res.send(crypto.publicEncrypt({
			key: req.query.pubkey,
			padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash: 'sha256'
		}, Buffer.from(user.getUserByPubkey(req.query.pubkey).object.secret, "utf-8")).toString("base64"));
	} catch {
		res.status(500).send("Something went terribly wrong when encrypting the secret token");
	}
});

app.use("/imagination", express.static(__dirname + "/imagination"));

app.get("/api/isFriend/", RequiredUserMiddleware, function (req, res) {
	if (!req.query.username) return res.status(400).send("Bad request!");
	if (!user.getUserByName(req.query.username)) return res.status(404).send("User not found!");
	res.json(req.user.object.friends.includes(req.query.username));
});

app.get("/api/userPublicKey/", RequiredUserMiddleware, function (req, res) {
	if (!req.query.username) return res.status(400).send("Bad request!");
	if (!user.getUserByName(req.query.username)) return res.status(404).send("User not found!");
	res.send(user.getUserByName(req.query.username).pubkey);
});

app.get("/api/addToFriends/", RequiredUserMiddleware, function (req, res) {
	if (!req.query.friendToken) {
		if (!req.query.username) return res.status(400).send("Bad request!");
		if (!user.getUserByName(req.query.username)) return res.status(404).send("User not found!");
		if (req.query.username == req.user.username) return res.status(400).send("Bad request! You can't add yourself as a friend.");
		let token = crypto.randomBytes(4).toString("hex");
		friendTokens[token] = {
			from: req.user.username,
			to: req.query.username
		};
		res.json({
			friendQueued: true,
			friendToken: token,
			friendAdded: false
		});
	} else {
		if (!friendTokens.hasOwnProperty(req.query.friendToken)) return res.status(400).send("Bad request! Invalid friend token.");
		let friendTokenInfo = friendTokens[req.query.friendToken];
		if (friendTokenInfo.to != req.user.username) return res.status(400).send("Bad request! The friend request does not belong to you.");
		if (!user.getUserByName(friendTokenInfo.from)) return res.status(404).send("The user who requested you as a friend was not found!");
		if (!req.user.object.friends.includes(friendTokenInfo.from)) req.user.object.friends.push(friendTokenInfo.from);
		if (!req.user.object.recentlyChatted.includes(friendTokenInfo.from)) req.user.object.recentlyChatted.push(friendTokenInfo.from);

		let fromNewObject = user.getUserByName(friendTokenInfo.from);
		if (!fromNewObject.friends.includes(req.user.username)) fromNewObject.friends.push(req.user.username);
		if (!fromNewObject.recentlyChatted.includes(req.user.username)) fromNewObject.recentlyChatted.push(req.user.username);

		user.setUser(req.user.username, req.user.object);
		user.setUser(friendTokenInfo.from, fromNewObject);

		delete friendTokens[req.query.friendToken];
        if (!socketsForUser[req.user.username]) socketsForUser[req.user.username] = [];
        if (!socketsForUser[friendTokenInfo.from]) socketsForUser[friendTokenInfo.from] = [];
        for (let any of socketsForUser[req.user.username]) any.emit("rehistory");
        for (let any of socketsForUser[friendTokenInfo.from]) any.emit("rehistory");
        for (let any of socketsForUser[req.user.username]) any.emit("contacts", req.user.object.recentlyChatted);
        for (let any of socketsForUser[friendTokenInfo.from]) any.emit("contacts", fromNewObject.recentlyChatted);
		res.json({
			friendQueued: false,
			friendToken: req.query.friendToken,
			friendAdded: true
		});
	}
});

app.get("/api/removeFromFriends/", RequiredUserMiddleware, function (req, res) {
	if (!req.query.username) return res.status(400).send("Bad request!");
	if (!user.getUserByName(req.query.username)) return res.status(404).send("User not found!");
	if (!req.user.object.friends.includes(req.query.username)) return res.status(400).send("User not in friend list.");
	req.user.object.friends = req.user.object.friends.filter((a) => a != req.query.username);
	let friendUser = user.getUserByName(req.query.username);
	friendUser.friends = friendUser.friends.filter((a) => a != req.user.username);
	user.setUser(req.query.username, friendUser);
	user.setUser(req.user.username, req.user.object);
    if (!socketsForUser[req.user.username]) socketsForUser[req.user.username] = [];
    if (!socketsForUser[req.query.username]) socketsForUser[req.query.username] = [];
    for (let any of socketsForUser[req.user.username]) any.emit("rehistory");
    for (let any of socketsForUser[req.query.username]) any.emit("rehistory");
    for (let any of socketsForUser[req.user.username]) any.emit("contacts", req.user.object.recentlyChatted);
    for (let any of socketsForUser[req.query.username]) any.emit("contacts", friendUser.recentlyChatted);
	res.send("OK");
});

app.get("/api/clearChat/", RequiredUserMiddleware, function (req, res) {
	if (!req.query.username) return res.status(400).send("Bad request!");
	req.user.object.messages = req.user.object.messages.filter((a) => a.username != req.query.username);
	user.setUser(req.user.username, req.user.object);
    if (!socketsForUser[req.user.username]) socketsForUser[req.user.username] = [];
    for (let any of socketsForUser[req.user.username]) any.emit("rehistory");
	res.send("OK");
});

app.get("/api/deleteChat/", RequiredUserMiddleware, function (req, res) {
	if (!req.query.username) return res.status(400).send("Bad request!");
	if (req.user.object.friends.includes(req.query.username)) return res.status(400).send("User still in friend list.");
	req.user.object.messages = req.user.object.messages.filter((a) => a.username != req.query.username);
	req.user.object.recentlyChatted = req.user.object.recentlyChatted.filter((a) => a != req.query.username);
	user.setUser(req.user.username, req.user.object);
    if (!socketsForUser[req.user.username]) socketsForUser[req.user.username] = [];
    for (let any of socketsForUser[req.user.username]) any.emit("contacts", req.user.object.recentlyChatted);
    for (let any of socketsForUser[req.user.username]) any.emit("rehistory");
	res.send("OK");
});

app.get("/api/privacyClearChat/", RequiredUserMiddleware, function (req, res) {
	if (!req.query.username) return res.status(400).send("Bad request!");
	if (!user.getUserByName(req.query.username)) return res.status(404).send("User not found!");
	let usr2 = user.getUserByName(req.query.username);
	req.user.object.messages = req.user.object.messages.filter((a) => a.username != req.query.username);
	usr2.messages = usr2.messages.filter((a) => a.username != req.user.username);
	user.setUser(req.user.username, req.user.object);
	user.setUser(req.query.username, usr2);
    if (!socketsForUser[req.user.username]) socketsForUser[req.user.username] = [];
    if (!socketsForUser[req.query.username]) socketsForUser[req.query.username] = [];
    for (let any of socketsForUser[req.user.username]) any.emit("rehistory");
    for (let any of socketsForUser[req.query.username]) any.emit("rehistory");
	res.send("OK");
});

app.get("/api/friends", RequiredUserMiddleware, (req, res) => res.json(req.user.object.friends));

app.get("/api/friendTokens", RequiredUserMiddleware, function (req, res) {
	let filteredFriendTokens = {};
	for (let friendToken in friendTokens)
		if (friendTokens[friendToken].to == req.user.username) filteredFriendTokens[friendToken] = friendTokens[friendToken];
	res.json(filteredFriendTokens);
});

app.get("/friendRequests", RequiredUserMiddleware, function (req, res) {
	res.render(getLocalePath("friendRequests.jsembeds", req.headers["accept-language"]), {
		username_unsan: req.user.username,
		friends: req.user.object.friends,
		friendTokens: friendTokens
	});
});

app.get("/manageAccount", RequiredUserMiddleware, function (req, res) {
	if (req.query.security_token) {
		if (!tempSecTok.hasOwnProperty(req.query.security_token)) return res.redirect("/manageAccount");
		if (tempSecTok[req.query.security_token] != req.user.username) return res.redirect("/manageAccount");
		return res.render(getLocalePath("manageAccount.jsembeds", req.headers["accept-language"]), {
			security_token: req.query.security_token
		});
	}
	res.render(getLocalePath("manageAccountPreEnvironment.jsembeds", req.headers["accept-language"]));
});

app.get("/manageAccountSecurityToken", RequiredUserMiddleware, function (req, res) {
	if (!user.getUserByPubkey(req.query.pubkey)) return res.status(401).send("Invalid public key: unregistered or blocked user?");
	try {
		let tst = crypto.randomBytes(64).toString("hex");
		tempSecTok[tst] = req.user.username;
		res.send(crypto.publicEncrypt({
			key: req.query.pubkey,
			padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash: 'sha256'
		}, Buffer.from(tst, "utf-8")).toString("base64"));
	} catch {
		res.status(500).send("Something went terribly wrong when encrypting the secret token");
	}
});

app.get("/manageAccount/goBackToChat", RequiredUserMiddleware, function (req, res) {
	if (!req.query.security_token) return res.redirect("/home");
	if (!tempSecTok.hasOwnProperty(req.query.security_token)) return res.redirect("/home");
	if (tempSecTok[req.query.security_token] != req.user.username) return res.redirect("/home");
	delete tempSecTok[req.query.security_token];
	res.redirect("/home");
});

app.get("/manageAccount/changeKeypair", RequiredUserMiddleware, function (req, res) {
	if (!req.query.security_token) return res.redirect("/manageAccount");
	if (!tempSecTok.hasOwnProperty(req.query.security_token)) return res.redirect("/manageAccount");
	if (tempSecTok[req.query.security_token] != req.user.username) return res.redirect("/manageAccount");
	if (!req.body.pubkey) return res.status(400).send("Bad request!");
	if (user.getUserByPubkey(req.body.pubkey)) return res.status(400).send("That public key is already taken! Try another one.");

	delete tempSecTok[req.query.security_token];
	try {
		req.user.object.pubkey = req.query.pubkey;
		req.user.object.recentlyChatted = req.user.object.recentlyChatted.filter((a) => a != "system");
		req.user.object.recentlyChatted.unshift("system");
		req.user.object.secret = crypto.randomBytes(64).toString("hex");
		user.setUser(req.user.username, req.user.object);
	} catch {
		return res.status(500).send("Something went terribly wrong when changing your pubkey");
	}
	res.send("OK");
});

app.get("/manageAccount/changeSecret", RequiredUserMiddleware, function (req, res) {
	if (!req.query.security_token) return res.redirect("/manageAccount");
	if (!tempSecTok.hasOwnProperty(req.query.security_token)) return res.redirect("/manageAccount");
	if (tempSecTok[req.query.security_token] != req.user.username) return res.redirect("/manageAccount");
	req.user.object.secret = crypto.randomBytes(64).toString("hex");
	user.setUser(req.user.username, req.user.object)
	delete tempSecTok[req.query.security_token];
	res.redirect("/manageAccount");
});

app.get("/manageAccount/removeAccount", RequiredUserMiddleware, function (req, res) {
	if (!req.query.security_token) return res.redirect("/manageAccount");
	if (!tempSecTok.hasOwnProperty(req.query.security_token)) return res.redirect("/manageAccount");
	if (tempSecTok[req.query.security_token] != req.user.username) return res.redirect("/manageAccount");
	for (let friend of req.user.object.friends) {
		let friendObj = user.getUserByName(friend) || {
			friends: [],
			notExist: true
		};
		friendObj.friends = friendObj.friends.filter((a) => a != req.user.username);
		if (!friendObj.notExist) user.setUser(friend, friendObj);
	}
	req.user.object.friends = [];
	for (let message of req.user.object.messages) {
		let contactObj = user.getUserByName(message.username) || {
			messages: [],
			notExist: true
		};
		contactObj.messages = contactObj.messages.filter((a) => a.username != req.user.username);
		if (!contactObj.notExist) user.setUser(message.username, contactObj);
	}
	req.user.object.messages = [];
	req.user.object.recentlyChatted = [];
	user.deleteUser(req.user.username);
	delete tempSecTok[req.query.security_token];
	res.redirect("/");
});

app.get("/addons", (req, res) => res.render(getLocalePath("addons.jsembeds", req.headers["accept-language"])));

app.get("/api/commitVersion", async function(req, res) {
	try {
		let process = await execProcess("git rev-parse HEAD");
		res.send((productionEnvironment ? "production-" : "") + process.stdout || "unknown");
	} catch {
		res.send("unknown");
	}
});

app.get("/ducchat.js", RequiredUserMiddleware, (req, res) => res.sendFile(getLocalePath("ducchat.js", req.headers["accept-language"])));

app.get("/api/username", RequiredUserMiddleware, (req, res) => res.send(req.user.username));

app.get("/api/sharedSecret", RequiredUserMiddleware, function(req, res) {
	if (!req.query.newSecretMy && !req.query.newSecretReceiver) {
		if (req.user.object.secrets) return res.send(req.user.object.secrets[req.query.username]);
		res.status(404).send("Not configured");
	} else {
		if (!req.user.object.secrets) req.user.object.secrets = {};
		req.user.object.secrets[req.query.username] = req.query.newSecretMy;
		let receiver = user.getUserByName(req.query.username);
		if (!receiver.secrets) receiver.secrets = {};
		if (receiver) receiver.secrets[req.user.username] = req.query.newSecretReceiver;
		user.setUser(req.user.username, req.user.object);
		user.setUser(req.query.username, receiver);
		res.send("OK");
	}
});

io.on("connection", async function (client) {
	function socketIOLogon(client) {
		if (!client.handshake.headers.cookie || !cookie.parse(client.handshake.headers.cookie).token) {
			client.disconnect();
			return;
		}
		return user.getUserBySecret(cookie.parse(client.handshake.headers.cookie).token || "");
	}

	let logon = socketIOLogon(client);
	if (!logon) return client.disconnect();
	if (!socketsForUser[logon.username]) socketsForUser[logon.username] = [];
	let ind = socketsForUser[logon.username].push(client) - 1;

	client.on("sendMessage", async function (messageData) {
        let logon = socketIOLogon(client);
		if (!logon) return client.disconnect();
		if (typeof messageData !== "object") return client.disconnect();
		if (!messageData.username) return client.emit("sendFail", "NO_USERNAME");
		if (!messageData.message) return client.emit("sendFail", "NO_MESSAGE");
        if (!logon.object.friends.includes(messageData.username)) return client.emit("sendFail", "NOT_FRIENDS");
		let remoteUser = await user.getUserByName(messageData.username);
        if (!remoteUser) return client.emit("sendFail", "USER_NOT_FOUND");
		let remoteUserObj = {
			username: logon.username,
			message: messageData.message,
			sentBy: logon.username,
			senderID: logon.object.uniqueSenderID,
			locale: String(client.handshake.headers["accept-language"]).split(";")[0].split(",")[0].split("-")[0].split("_")[0].toLowerCase(),
			timestamp: Date.now()
		};
		let myUserObj = structuredClone(remoteUserObj);
		myUserObj.username = messageData.username;


        remoteUser.messages.push(remoteUserObj)
        logon.object.messages.push(myUserObj);
        user.setUser(logon.username, logon.object);
        user.setUser(messageData.username, remoteUser);
        if (!socketsForUser[messageData.username]) socketsForUser[messageData.username] = [];
        for (let thatClient of socketsForUser[messageData.username]) thatClient?.emit("newMessage", remoteUserObj);
        for (let thatClient of socketsForUser[logon.username]) thatClient?.emit("newMessage", myUserObj);
	});
    client.on("messagesFromHistory", async function(settingObj) {
        if (!settingObj) return client.disconnect();
        if (typeof settingObj !== "object") return client.disconnect();
        let logon = socketIOLogon(client);
		if (!logon) return client.disconnect();
		let msgs = logon.object.messages.filter(a => a.username == settingObj.username);
		if (settingObj.limit) msgs = msgs.slice(settingObj.limit * -1)
        client.emit("history", msgs);
    });
    client.on("contacts", function() {
        let logon = socketIOLogon(client);
		if (!logon) return client.disconnect();
        client.emit("contacts", logon.object.recentlyChatted);
    });

    client.emit("contacts", logon.object.recentlyChatted);
    client.on("disconnect", () => socketsForUser[logon.username].splice(ind, 1));
});

http.listen(4598, function () {
	console.log("HTTP at :4598");
});