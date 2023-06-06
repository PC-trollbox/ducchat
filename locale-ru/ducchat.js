(async function () {
	const AsyncFunction = (async () => {}).constructor;
	let addons = JSON.parse(localStorage.getItem("addons") || "{}");
	for (let addon in addons)
		if (addons[addon].runningIn?.includes("page-startup")) try {
			await new AsyncFunction(addons[addon].feature)("page-startup");
		} catch (e) {
			alert("Дополнение \"" + addon + "\" (версия " + addons[addon].release + ") не удалось запустить:\n" + e.toString() + "\n" + e.stack + "\nЗапустите менеджер дополнений и удалите это дополнение или примените обновление.");
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
	textareaInput.value = "Пользователь не находится в вашем списке друзей. Вы не можете с ним связаться.";
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
	commitLbl.innerText = "DucChat версия " + commit;

	async function fingerprint(message) {
		const encoder = new TextEncoder();
		const data = encoder.encode(message);
		const hashBuffer = await crypto.subtle.digest('SHA-256', data);
		const hashB64 = imagination.encryption.arrayBufferToBase64(hashBuffer).replaceAll("=", "");
		return "sha256:" + hashB64;
	}

	let pubkey_data = localStorage.getItem("pubk");
	let privkey_data = localStorage.getItem("privk");
	if (!privkey_data || !pubkey_data) return cryptError("Один или все ключи отсутствуют в хранилище.")
	if (privkey_data.startsWith("encrypted:")) {
		let password = await prompt("Введите парольную фразу, затем нажмите Ввод:");
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
		for (let addon in addons)
			if (addons[addon].runningIn?.includes("parseMessage")) try {
				text = await new AsyncFunction(addons[addon].feature)("parseMessage", text);
			} catch (e) {
				alert("Дополнение \"" + addon + "\" (версия " + addons[addon].release + ") не удалось запустить:\n" + e.toString() + "\n" + e.stack + "\nЗапустите менеджер дополнений и удалите это дополнение или примените обновление.");
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
			.replace(/\[addon=([a-zA-Z0-9\. ]+)\]([a-zA-Z0-9\/=]+)\[\/addon\]/g, (full, addon_name, _1, _2, base64) => {
				//if (backslash) return full;
				return `<button onclick="eval(atob(${JSON.stringify(base64).replace(/"/g, "'")}))">Установить дополнение ${addon_name} (выполняет код JavaScript!)</button>`;
			})
			.replace(/([^\\]|^)\*\*(.+?[^\\])\*\*/gs, "$1<b>$2</b>")
			.replace(/([^\\]|^)\*([^\*]+)\*/g, "$1<i>$2</i>")
			.replace(/([^\\]|^)__([^\*]+)__/g, "$1<u>$2</u>")
			.replace(/([^\\]|^)~~([^\*]+)~~/g, "$1<s>$2</s>")
			.replace(/([^\\]|^)`([^\*]+)`/g, "$1<code>$2</code>")
			.replace(/\\\*/g, "*")
			.replace(/\\\*\*/g, "**")
			.replace(/\\__/g, "__")
			.replace(/\\~~/g, "~~")
			.replace(/\\\\/g, "\\")
			.replace(/\\`/g, "`");
	}

	document.querySelectorAll("a").forEach(function (b) {
		if (b.href.endsWith("/logout")) return;
		b.onclick = function me(e) {
			e.preventDefault();
			e.stopImmediatePropagation();
			seeingMessages.style.display = "none";
			settingShower.style.display = "";
			settingShower.src = b.href;
			b.classList.add("active");
			settingShower.onload = function () {
				let linkHandler = function (a) {
					a.onclick = function (ae) {
						ae.preventDefault();
						ae.stopImmediatePropagation();
						seeingMessages.style.display = "";
						settingShower.style.display = "none";
						b.onclick = me;
					}
				};
				let backup = settingShower.contentWindow.onpagehide;
				settingShower.contentWindow.onpagehide = null;
				settingShower.contentWindow.document.querySelectorAll("a[href=\\/home]").forEach(linkHandler);
				settingShower.contentWindow.document.querySelectorAll("a[href=\\/]").forEach(linkHandler);
				settingShower.contentWindow.document.querySelectorAll("form[action=\\/manageAccount\\/goBackToChat]").forEach(function (c) {
					c.onclick = function (ae) {
						backup({
							preventDefault: () => {},
							stopImmediatePropagation: () => {},
							stopPropagation: () => {}
						});
						ae.preventDefault();
						ae.stopImmediatePropagation();
						seeingMessages.style.display = "";
						settingShower.style.display = "none";
						b.onclick = me;
					}
				});
			}
			b.onclick = function (e) {
				e.preventDefault();
				e.stopImmediatePropagation();
				seeingMessages.style.display = "";
				settingShower.style.display = "none";
				b.onclick = me;
			}
		}
	});

	socket.on("contacts", async function (contacts) {
		for (let addon in addons)
			if (addons[addon].runningIn?.includes("before-contact-render")) try {
				await new AsyncFunction(addons[addon].feature)("before-contact-render", contacts);
			} catch (e) {
				alert("Дополнение \"" + addon + "\" (версия " + addons[addon].release + ") не удалось запустить:\n" + e.toString() + "\n" + e.stack + "\nЗапустите менеджер дополнений и удалите это дополнение или примените обновление.");
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
						let confirmation = confirm("Импортировать открытый ключ этого контакта?\nОтпечаток открытого ключа: " + await fingerprint(new_receiver_pubkey) + "\nВаш открытый ключ: " + await fingerprint(pubkey_data) + "\nКлюч будет сохранён. Если вы не примете этот запрос, общение может быть невозможным.");
						if (confirmation) {
							let pubkeys = JSON.parse(localStorage.getItem("pubkeys_cache") || "{}");
							pubkeys[contact] = new_receiver_pubkey;
							localStorage.setItem("pubkeys_cache", JSON.stringify(pubkeys));
							receiver_pubkey = new_receiver_pubkey;
						}
					} else if (receiver_pubkey != new_receiver_pubkey) {
						let confirmation = confirm("Импортировать новую версию открытого ключа этого контакта?\nОтпечаток старого открытого ключа: " + await fingerprint(receiver_pubkey) + "\nОтпечаток нового открытого ключа: " + await fingerprint(new_receiver_pubkey) + "\nВаш открытый ключ: " + await fingerprint(pubkey_data) + "\nКлюч будет сохранён. Если вы не примете этот запрос, друг может не увидеть ваши сообщения.");
						if (confirmation) {
							let pubkeys = JSON.parse(localStorage.getItem("pubkeys_cache") || "{}");
							pubkeys[contact] = new_receiver_pubkey;
							localStorage.setItem("pubkeys_cache", JSON.stringify(pubkeys));
							receiver_pubkey = new_receiver_pubkey;
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
				let action = prompt("Выберите действие:\n[1] Очистить чат (очистит только на ВАШЕЙ стороне)\n[2] Удалить чат (работает только если вы больше не друзья)\n[3] Конфиденциальная очистка чата (очистит на обоих сторонах)\n[4] Переключить авто-прокрутку (сейчас " + (autoScroll ? "включена" : "выключена") + ")\n\nНапишите число или что-либо другое, чтобы отменить, затем нажмите Ввод.");
				if (action == "1") {
					await fetch("/api/clearChat?username=" + encodeURIComponent(contactEl.innerText));
				} else if (action == "2") {
					await fetch("/api/deleteChat?username=" + encodeURIComponent(contactEl.innerText));
				} else if (action == "3") {
					await fetch("/api/privacyClearChat?username=" + encodeURIComponent(contactEl.innerText));
				} else if (action == "4") {
					autoScroll = !autoScroll;
				}
			})
			if (matchTest == contactEl.innerText) contactEl.classList.add("active");
			contactMenu.appendChild(contactEl);
		}
		for (let addon in addons)
			if (addons[addon].runningIn?.includes("after-contact-render")) try {
				await new AsyncFunction(addons[addon].feature)("after-contact-render", contacts);
			} catch (e) {
				alert("Дополнение \"" + addon + "\" (версия " + addons[addon].release + ") не удалось запустить:\n" + e.toString() + "\n" + e.stack + "\nЗапустите менеджер дополнений и удалите это дополнение или примените обновление.");
			}
	});

	async function handleMessage(message, runFriendChecking = true) {
		let messageEl = document.createElement("div");
		messageEl.className = "message";
		if (message.sentBy != username) messageEl.classList.add("read");
		else messageEl.classList.add("sent");
		let failedDecrypt = false;
		for (let addon in addons)
			if (addons[addon].runningIn?.includes("decryptMessage")) try {
				message.message = await new AsyncFunction(addons[addon].feature)("decryptMessage", message.message);
			} catch {
				failedDecrypt = true;
			}
		try {
			messageEl.innerHTML = await parseMarkdown(await imagination.encryption.decryptAES(message.message, (new TextDecoder()).decode(shared_secret)));
		} catch {
			messageEl.innerHTML = await parseMarkdown(String(message.message));
			messageEl.innerHTML = messageEl.innerHTML + "<hr><em>Внимание: Сообщению можно не доверять, потому что расшифрование не удалось.</em>";
		}
		for (let addon in addons)
			if (addons[addon].runningIn?.includes("decryptMessage")) messageEl.innerHTML = await parseMarkdown(message.message) + (failedDecrypt ? "<hr><em>Внимание: Сообщению можно не доверять, потому что расшифрование с использованием дополнения не удалось.</em>" : "");
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
			textareaInput.value = "Пользователь не находится в вашем списке друзей. Вы не можете с ним связаться.";
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
				alert("Дополнение \"" + addon + "\" (версия " + addons[addon].release + ") не удалось запустить:\n" + e.toString() + "\n" + e.stack + "\nЗапустите менеджер дополнений и удалите это дополнение или примените обновление.");
			}

		let failedEncrypt = false;
		for (let addon in addons)
			if (addons[addon].runningIn?.includes("encryptMessage")) try {
				textareaInput.value = await new AsyncFunction(addons[addon].feature)("encryptMessage", textareaInput.value);
			} catch {
				failedEncrypt = true;
			}

		if (failedEncrypt) alert("Сообщение не удалось зашифровать при помощи дополнения. Было отправлено полу- или совершенно нешифрованное сообщение. Ему могут не доверять.");

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
			alert("Сообщение не удалось зашифровать. Было отправлено нешифрованное сообщение. Ему могут не доверять.");
		}
		for (let addon in addons)
			if (addons[addon].runningIn?.includes("after-message-send")) try {
				await new AsyncFunction(addons[addon].feature)("after-message-send", textareaInput.value);
			} catch (e) {
				alert("Дополнение \"" + addon + "\" (версия " + addons[addon].release + ") не удалось запустить:\n" + e.toString() + "\n" + e.stack + "\nЗапустите менеджер дополнений и удалите это дополнение или примените обновление.");
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