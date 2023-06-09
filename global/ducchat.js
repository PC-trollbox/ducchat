(async function () {
	const AsyncFunction = (async () => {}).constructor;
	let addons = JSON.parse(localStorage.getItem("addons") || "{}");
	for (let addon in addons)
		if (addons[addon].runningIn?.includes("page-startup")) try {
			await new AsyncFunction(addons[addon].feature)("page-startup");
		} catch (e) {
			alert("The addon \"" + addon + "\" (version " + addons[addon].release + ") failed to launch:\n" + e.toString() + "\n" + e.stack + "\nPlease launch the Add-ons manager and uninstall this addon or apply a patch.");
		}
	let socket = null;
	let contactMenu = document.getElementById("contact");
	let textareaInput = document.getElementById("textareaInput");
	let sendInput = document.getElementById("sender");
	let currentContact = document.getElementById("currentContact");
	let messagesContainer = document.getElementById("messagesContainer");
	let commitLbl = document.getElementById("commit");
	let seeingMessages = document.getElementById("seeingMessages");
	let settingShower = document.getElementById("settingShower");
	let contextMenu = document.getElementById("contextMenu");
	let username = await fetch("/api/username");
	username = await username.text();
	contactMenu.id = "";
	textareaInput.id = "";
	sendInput.id = "";
	currentContact.id = "";
	messagesContainer.id = "";
	commitLbl.id = "";
	seeingMessages.id = "";
	settingShower.id = "";
	contextMenu.id = "";
	textareaInput.value = "This user is not in your friend list. You can't communicate with them.";
	textareaInput.notFriendDisabled = true;
	textareaInput.disabled = true;
	sendInput.disabled = true;
	let activeContact = null;
	let contactAmount = 0;
	let receiver_pubkey = null;
	let autoScroll = true;
    let shared_secret = null;

	let commit = await fetch("/api/commitVersion");
	commit = await commit.text();
	if (commit.startsWith("production-")) commitLbl.remove();
	commitLbl.innerText = "DucChat version " + commit;

	async function fingerprint(message) {
		const encoder = new TextEncoder();
		const data = encoder.encode(message);
		const hashBuffer = await crypto.subtle.digest('SHA-256', data);
		const hashB64 = imagination.encryption.arrayBufferToBase64(hashBuffer).replaceAll("=", "");
		return "sha256:" + hashB64;
	}

	let pubkey_data = localStorage.getItem("pubk");
	let privkey_data = localStorage.getItem("privk");
	if (!privkey_data || !pubkey_data) return cryptError("One or all of the keys are not located in the storage.")
	if (privkey_data.startsWith("encrypted:")) {
		let password = await prompt("Enter your passphrase, then press Enter:");
		try {
			privkey_data = await imagination.encryption.decryptAES(JSON.parse(privkey_data.replace("encrypted:", "")), password);
		} catch {}
	}
	let imports;
	try {
		imports = await imagination.encryption.importKeyPair(pubkey_data, privkey_data);
	} catch (e) {
		return cryptError(e);
	}
	socket = io();
	async function parseMarkdown(text) {
		text = String(text);
		for (let addon in addons)
			if (addons[addon].runningIn?.includes("parseMessage")) try {
				text = await new AsyncFunction(addons[addon].feature)("parseMessage", text);
			} catch (e) {
				alert("The addon \"" + addon + "\" (version " + addons[addon].release + ") failed to launch:\n" + e.toString() + "\n" + e.stack + "\nPlease launch the Add-ons manager and uninstall this addon or apply a patch.");
			}
		for (let addon in addons)
			if (addons[addon].runningIn?.includes("parseMessage")) return text;

		function htmlEscape(unsafe) {
			return unsafe
				.replace(/</g, "&lt;")
				.replace(/>/g, "&gt;")
				.replace(/"/g, "&quot;")
				.replace(/\n/g, "<br>");
		}
		const safe = htmlEscape(text);
		return safe
			.replace(/([^\\]|^)\*\*(.+?[^\\])\*\*/gs, "$1<b>$2</b>")
			.replace(/([^\\]|^)\*([^\*]+)\*/g, "$1<i>$2</i>")
			.replace(/([^\\]|^)__([^\*]+)__/g, "$1<u>$2</u>")
			.replace(/([^\\]|^)~~([^\*]+)~~/g, "$1<s>$2</s>")
			.replace(/([^\\]|^)```([^\*]+)```/g, "$1<pre>$2</pre>")
			.replace(/([^\\]|^)`([^\*]+)`/g, "$1<code>$2</code>")
			.replace(/\\\*/g, "*")
			.replace(/\\__/g, "__")
			.replace(/\\~~/g, "~~")
			.replace(/\\\\/g, "\\")
			.replace(/\\`/g, "`");
	}

	document.querySelectorAll("a").forEach(function (b) {
		if (b.href.endsWith("/logout")) return;
		b.addEventListener("click", function me(e) {
			function hideUp(e) {
				e.preventDefault();
				e.stopImmediatePropagation();
				seeingMessages.style.display = "";
				settingShower.style.display = "none";
			}
			if (settingShower.style.display == "") return hideUp(e);
			e.preventDefault();
			e.stopImmediatePropagation();
			seeingMessages.style.display = "none";
			settingShower.style.display = "";
			settingShower.src = b.href;
			settingShower.onload = function () {
				let linkHandler = (a) => a.onclick = hideUp;
				let backup = settingShower.contentWindow.onpagehide;
				settingShower.contentWindow.onpagehide = null;
				settingShower.contentWindow.document.querySelectorAll("a[href=\\/home]").forEach(linkHandler);
				settingShower.contentWindow.document.querySelectorAll("a[href=\\/]").forEach(linkHandler);
				settingShower.contentWindow.document.querySelectorAll("form[action=\\/manageAccount\\/goBackToChat]").forEach(function (c) {
					c.addEventListener("click", function (ae) {
						backup({
							preventDefault: () => {},
							stopImmediatePropagation: () => {},
							stopPropagation: () => {}
						});
						hideUp(ae);
					});
				});
			}
		});
	});

	socket.on("contacts", async function (contacts) {
		for (let addon in addons)
			if (addons[addon].runningIn?.includes("before-contact-render")) try {
				await new AsyncFunction(addons[addon].feature)("before-contact-render", contacts);
			} catch (e) {
				alert("The addon \"" + addon + "\" (version " + addons[addon].release + ") failed to launch:\n" + e.toString() + "\n" + e.stack + "\nPlease launch the Add-ons manager and uninstall this addon or apply a patch.");
			}
		for (let a = 0; a != contactAmount; a++) contactMenu.lastChild.remove();
		contactAmount = 0;
		let matchTest = activeContact?.innerText;
		for (let contact of contacts) {
			contactAmount++;
			let contactEl = document.createElement("div");
			contactEl.className = "contact";
			contactEl.innerText = contact;
			contactEl.addEventListener("click", async function () {
				if (!localStorage.getItem("pubkeys_cache")) localStorage.setItem("pubkeys_cache", "{}");
				let new_receiver_pubkey = await fetch("/api/userPublicKey?username=" + encodeURIComponent(contact));
				receiver_pubkey = JSON.parse(localStorage.getItem("pubkeys_cache") || "{}")[contact];
				if (new_receiver_pubkey.ok) {
					new_receiver_pubkey = await new_receiver_pubkey.text();
					if (!receiver_pubkey) {
						let confirmation = confirm("Import a public key of this contact?\nPublic key fingerprint: " + await fingerprint(new_receiver_pubkey) + "\nYour public key: " + await fingerprint(pubkey_data) + "\nThis key will be cached. If you don't accept, you might be unable to chat.");
						if (confirmation) {
							let pubkeys = JSON.parse(localStorage.getItem("pubkeys_cache") || "{}");
							pubkeys[contact] = new_receiver_pubkey;
							localStorage.setItem("pubkeys_cache", JSON.stringify(pubkeys));
							receiver_pubkey = new_receiver_pubkey;
						}
					} else if (receiver_pubkey != new_receiver_pubkey) {
						let confirmation = confirm("Import a newer version of a public key of this contact?\nOld public key fingerprint: " + await fingerprint(receiver_pubkey) + "\nNew public key fingerprint: " + await fingerprint(new_receiver_pubkey) + "\nYour public key: " + await fingerprint(pubkey_data) + "\nThis new key will be cached. If you don't accept, your friend may be unable to see your messages.");
						if (confirmation) {
							let pubkeys = JSON.parse(localStorage.getItem("pubkeys_cache") || "{}");
							pubkeys[contact] = new_receiver_pubkey;
							localStorage.setItem("pubkeys_cache", JSON.stringify(pubkeys));
							receiver_pubkey = new_receiver_pubkey;
							let newSharedSecret = crypto.getRandomValues(new Uint8Array(64));
							let sharedSecretMe = await imagination.encryption.encryptRSA(newSharedSecret, imports.publicKey);
							let sharedSecretReceiver = await imagination.encryption.encryptRSA(newSharedSecret, receiver_pubkey);
							await fetch("/api/sharedSecret?username=" + encodeURIComponent(contact) + "&newSecretMy=" + encodeURIComponent(sharedSecretMe) + "&newSecretReceiver=" + encodeURIComponent(sharedSecretReceiver));
							shared_secret = newSharedSecret;
						}
					}
				}
				receiver_pubkey = JSON.parse(localStorage.getItem("pubkeys_cache") || "{}")[contact];
				try {
					receiver_pubkey = (await imagination.encryption.importKeyPair(receiver_pubkey, privkey_data)).publicKey;
				} catch {}
				if (activeContact) {
					activeContact.classList.remove("active");
				}
				activeContact = contactEl;
				activeContact.classList.add("active");
                shared_secret = await fetch("/api/sharedSecret?username=" + encodeURIComponent(contact));
                shared_secret = await shared_secret.text();
                try {
                    shared_secret = (new TextEncoder()).encode(await imagination.encryption.decryptRSA(shared_secret, imports.privateKey));
                } catch {
                    let newSharedSecret = crypto.getRandomValues(new Uint8Array(64));
                    let sharedSecretMe = await imagination.encryption.encryptRSA(newSharedSecret, imports.publicKey);
                    let sharedSecretReceiver = await imagination.encryption.encryptRSA(newSharedSecret, receiver_pubkey);
                    await fetch("/api/sharedSecret?username=" + encodeURIComponent(contact) + "&newSecretMy=" + encodeURIComponent(sharedSecretMe) + "&newSecretReceiver=" + encodeURIComponent(sharedSecretReceiver));
                    shared_secret = newSharedSecret;
                }

				currentContact.innerText = contactEl.innerText;

				socket.emit("messagesFromHistory", {
					username: currentContact.innerText,
					limit: 50
				});
			});

			contactEl.addEventListener("contextmenu", async function (e) {
				e.preventDefault();
				e.stopImmediatePropagation();
				e.stopPropagation();

				contextMenu.style.top = e.clientY + "px";
				contextMenu.style.left = e.clientX + "px";
				contextMenu.hidden = false;
				Array.prototype.map.call(contextMenu.children, (a) => a).forEach(a => a.remove());

				let usernameLabel = document.createElement("button");
				let clearChatBtn = document.createElement("button");
				let deleteChatBtn = document.createElement("button");
				let privacyClearChatBtn = document.createElement("button");
				let regenerateSharedSecretBtn = document.createElement("button");
				let autoScrollBtn = document.createElement("button");
				usernameLabel.className = "contextMenuItem";
				clearChatBtn.className = "contextMenuItem";
				deleteChatBtn.className = "contextMenuItem";
				privacyClearChatBtn.className = "contextMenuItem";
				regenerateSharedSecretBtn.className = "contextMenuItem";
				autoScrollBtn.className = "contextMenuItem";
				usernameLabel.innerText = "Managing " + contactEl.innerText;
				usernameLabel.innerHTML = "<em>" + usernameLabel.innerHTML + "</em>";
				clearChatBtn.innerText = "Clear chat";
				clearChatBtn.title = "Clearing the chat will clear it on your side only.";
				deleteChatBtn.innerText = "Delete chat";
				deleteChatBtn.title = "You can only delete the chat if you're no longer friends.";
				privacyClearChatBtn.innerText = "Privacy clear chat";
				privacyClearChatBtn.title = "Privacy clear chat will clear the chat on both sides. Only use this for privacy reasons.";
				regenerateSharedSecretBtn.innerText = "Regenerate shared secret";
				regenerateSharedSecretBtn.title = "The shared secret needs to be refreshed after changing the keypair.";
				autoScrollBtn.innerText = "Turn auto-scroll " + (autoScroll ? "off" : "on");
				autoScrollBtn.title = "Auto-scroll automatically scrolls the chat down when you receive a new message.";
				usernameLabel.disabled = true;

				contextMenu.append(usernameLabel, clearChatBtn, deleteChatBtn, privacyClearChatBtn, regenerateSharedSecretBtn, autoScrollBtn);

				clearChatBtn.addEventListener("click", async () => await fetch("/api/clearChat?username=" + encodeURIComponent(contactEl.innerText)));
				deleteChatBtn.addEventListener("click", async () => await fetch("/api/deleteChat?username=" + encodeURIComponent(contactEl.innerText)));
				privacyClearChatBtn.addEventListener("click", async () => await fetch("/api/privacyClearChat?username=" + encodeURIComponent(contactEl.innerText)));
				regenerateSharedSecretBtn.addEventListener("click", async function() {
					let newSharedSecret = crypto.getRandomValues(new Uint8Array(64));
                    let sharedSecretMe = await imagination.encryption.encryptRSA(newSharedSecret, imports.publicKey);
                    let sharedSecretReceiver = await imagination.encryption.encryptRSA(newSharedSecret, receiver_pubkey);
                    await fetch("/api/sharedSecret?username=" + encodeURIComponent(contact) + "&newSecretMy=" + encodeURIComponent(sharedSecretMe) + "&newSecretReceiver=" + encodeURIComponent(sharedSecretReceiver));
					alert("Finished. To complete the refresh, please click on the chat again.");
				});
				autoScrollBtn.addEventListener("click", async () => autoScroll = !autoScroll);
			})
			if (matchTest == contactEl.innerText) contactEl.classList.add("active");
			contactMenu.appendChild(contactEl);
		}
		for (let addon in addons)
			if (addons[addon].runningIn?.includes("after-contact-render")) try {
				await new AsyncFunction(addons[addon].feature)("after-contact-render", contacts);
			} catch (e) {
				alert("The addon \"" + addon + "\" (version " + addons[addon].release + ") failed to launch:\n" + e.toString() + "\n" + e.stack + "\nPlease launch the Add-ons manager and uninstall this addon or apply a patch.");
			}
	});

	window.addEventListener("click", function() {
		if (!contextMenu.hidden) contextMenu.hidden = true;
	});

	async function handleMessage(message, runFriendChecking = true) {
		let messageEl = document.createElement("div");
		messageEl.className = "message";
		if (message.sentBy != username) messageEl.classList.add("read");
		else messageEl.classList.add("sent");
		let failedDecrypt = false;
		let timestamp = new Date(message.timestamp || 0).toLocaleDateString() + " " + new Date(message.timestamp || 0).toTimeString().split(" ")[0];
		for (let addon in addons)
			if (addons[addon].runningIn?.includes("decryptMessage")) try {
				message.message = await new AsyncFunction(addons[addon].feature)("decryptMessage", message.message);
			} catch {
				failedDecrypt = true;
			}
		try {
			messageEl.innerHTML = await parseMarkdown(await imagination.encryption.decryptAES(message.message, (new TextDecoder()).decode(shared_secret))) + "<div class=\"message-features\">" + timestamp + "</div>";
		} catch {
			messageEl.innerHTML = await parseMarkdown(message.message);
			messageEl.innerHTML = messageEl.innerHTML + "<div class=\"message-features\"><label title=\"Message is not encrypted. It may be insecure.\">🔓</label> " + timestamp + "</div>";
		}
		for (let addon in addons)
			if (addons[addon].runningIn?.includes("decryptMessage")) messageEl.innerHTML = await parseMarkdown(message.message) + "<div class=\"message-features\"><label title=\"Addon used.\">🧩</label> " + (failedDecrypt ? "<label title=\"Message is not encrypted. It may be insecure.\">🔓</label> " : "") + timestamp + "</div>";
		messagesContainer.appendChild(messageEl);
		if (autoScroll) messagesContainer.scrollTop = messagesContainer.scrollTopMax || Number.MAX_SAFE_INTEGER;
		if (runFriendChecking) await friendChecking();
	}
	async function friendChecking() {
		let isFriend = await fetch("/api/isFriend?username=" + encodeURIComponent(currentContact.innerText));
		try {
			isFriend = await isFriend.json();
		} catch {
			isFriend = false;
		}
		if (isFriend) {
			sendInput.disabled = false;
			textareaInput.disabled = false;
			if (textareaInput.notFriendDisabled) {
				textareaInput.value = "";
				textareaInput.notFriendDisabled = false;
			}
		} else {
			sendInput.disabled = true;
			textareaInput.disabled = true;
			textareaInput.notFriendDisabled = true;
			textareaInput.value = "This user is not in your friend list. You can't communicate with them.";
		}
	}

	socket.on("history", async function (messages) {
		let old_child = Array.prototype.map.call(messagesContainer.children, (a) => a);
		let rememberAutoScroll = autoScroll;
		if (rememberAutoScroll) autoScroll = false;
		for (let message of messages) await handleMessage(message, false);
		if (rememberAutoScroll) autoScroll = true;
		while (old_child[0]) old_child.shift().remove();
        if (autoScroll) messagesContainer.scrollTop = messagesContainer.scrollTopMax || Number.MAX_SAFE_INTEGER;
		await friendChecking();
	});
	socket.on("newMessage", async function (message) {
		if (message.username != currentContact.innerText) return;
		await handleMessage(message);
		await friendChecking();
	});

	socket.on("rehistory", () => socket.emit("messagesFromHistory", {
		username: currentContact.innerText,
		limit: 50
	}));

	sendInput.addEventListener("click", async function (e) {
		if (sendInput.disabled || textareaInput.disabled) return alert("Communication disabled!");
		if (!textareaInput.value) return;
		for (let addon in addons)
			if (addons[addon].runningIn?.includes("before-message-send")) try {
				await new AsyncFunction(addons[addon].feature)("before-message-send", textareaInput.value);
			} catch (e) {
				alert("The addon \"" + addon + "\" (version " + addons[addon].release + ") failed to launch:\n" + e.toString() + "\n" + e.stack + "\nPlease launch the Add-ons manager and uninstall this addon or apply a patch.");
			}

		let failedEncrypt = false;
		for (let addon in addons)
			if (addons[addon].runningIn?.includes("encryptMessage")) try {
				textareaInput.value = await new AsyncFunction(addons[addon].feature)("encryptMessage", textareaInput.value);
			} catch {
				failedEncrypt = true;
			}

		if (failedEncrypt) alert("The message has failed to be encrypted using an addon. An semi- or a completely unencrypted format was sent. It might be untrusted.");

		for (let addon in addons)
			if (addons[addon].runningIn?.includes("encryptMessage")) {
				socket.emit("sendMessage", {
					message: textareaInput.value,
					username: currentContact.innerText
				});

				textareaInput.value = "";
				return;
			}
		try {
			socket.emit("sendMessage", {
				message: await imagination.encryption.encryptAES(textareaInput.value, (new TextDecoder()).decode(shared_secret)),
				username: currentContact.innerText
			});
		} catch (e) {
			socket.emit("sendMessage", {
				message: textareaInput.value,
				username: currentContact.innerText
			});
			alert("Your message has failed to be encrypted. An unencrypted format was sent. It might be untrusted.");
		}
		for (let addon in addons)
			if (addons[addon].runningIn?.includes("after-message-send")) try {
				await new AsyncFunction(addons[addon].feature)("after-message-send", textareaInput.value);
			} catch (e) {
				alert("The addon \"" + addon + "\" (version " + addons[addon].release + ") failed to launch:\n" + e.toString() + "\n" + e.stack + "\nPlease launch the Add-ons manager and uninstall this addon or apply a patch.");
			}
		textareaInput.value = "";
	});
	addEventListener("keydown", function (e) {
		textareaInput.focus();
		if (e.key == "Enter" && !e.shiftKey) {
			e.preventDefault();
			e.stopImmediatePropagation();
			e.stopPropagation();
			if (!sendInput.disabled && !textareaInput.disabled) sendInput.click();
		}
	});
})();