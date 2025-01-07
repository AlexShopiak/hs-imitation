const { logSend, logReceive,encryptText, decryptText } = require('./tool/tools.js');
const crypto = require('crypto');

(async () => {
	try {
		// Клієнт ініціює рукостискання
		const clientRandom = crypto.randomBytes(16).toString('base64');
		const helloResponse = await fetch('http://localhost:4000/hello', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ message: `Привіт:${clientRandom}` }),
		});
		logSend(`Привіт:${clientRandom}`)

		if (!helloResponse.ok) {
			console.error('Failed to get server hello');
			return;
		}

		const serverResponse1 = await helloResponse.json();
		const serverRandom = serverResponse1.message.split(":")[1];
		logReceive(serverResponse1.message);

		// Клієнт перевіряє SSL-сертифікат сервера в CA
		logSend('сертифікат до СА');
		const certificate = serverResponse1.certificate;
		const verifyResponse = await fetch('http://localhost:3000/verify', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				certificate: certificate,
			}),
		});
		
		const serverResponse2 = await verifyResponse.json();
		if (!serverResponse2.verified) {
			console.error('Отримано:'+'\x1b[31m Сертифікат сервера не валідний\x1b[0m', serverResponse2.message);
			process.exit(0);
		}
		logReceive('\x1b[32m Сертифікат сервера валідний\x1b[0m');		
		
		// Клієнт надсилає секрет premaster, який шифрується відкритим ключем сервера
		const premaster = crypto.randomBytes(32).toString('base64');
		console.log('Згенеровано premaster:', premaster);

		const sessionKey = crypto.createHash('sha256').update(premaster).update(clientRandom).update(serverRandom).digest('base64');
		console.log('Згенеровано sessionKey:', sessionKey);

		const encryptedPremaster = crypto.publicEncrypt(certificate.publicKey, Buffer.from(premaster, "base64")).toString('base64');
		logSend("encryptedPremaster")

		const premasterResponse = await fetch('http://localhost:4000/premaster', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ premaster: encryptedPremaster }),
		});
		const serverResponse3 = await premasterResponse.json()
		logReceive(serverResponse3.message);

		if (serverResponse3.message !==  'session key згенеровано') {
			console.error('\x1b[31m Сервер не зміг згенерувати session key\x1b[0m');
			process.exit(0);
		}

		// Клієнт надсилає повідомлення "готовий", зашифроване сеансовим ключем. 
		const readyMessage = 'готовий';
		const encryptedMessage = encryptText(readyMessage, sessionKey)
		
		logSend('готовий')
		const readyResponse = await fetch('http://localhost:4000/ready', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ encryptedMessage: encryptedMessage }),
		});
		const serverResponse4 = await readyResponse.json();

		const decryptedMessage = decryptText(serverResponse4.encryptedMessage, sessionKey);
		logReceive(decryptedMessage);

		if (decryptedMessage !==  'готовий') {
			console.error('\x1b[31m Сервер згенерував невірний session key\x1b[0m');
			process.exit(0);
		}

		// Отримати записи по захищеному каналу 
		const title = 'The Odyssey';
		logSend('запит опису книги ', title);
		const encryptedTitle = encryptText(title, sessionKey);
		const bookResponse1 = await fetch('http://localhost:4000/book', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ encryptedTitle: encryptedTitle }),
		});
		const serverResponse5 = await bookResponse1.json();
		const description = decryptText(serverResponse5.encryptedDescription, sessionKey);
		logReceive(description);

		// Отримати записи по захищеному каналу 2
		const title2 = 'Don Quixote';
		logSend('запит опису книги ', title2);
		const encryptedTitle2 = encryptText(title2, sessionKey);
		const bookResponse2 = await fetch('http://localhost:4000/book', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ encryptedTitle: encryptedTitle2 }),
		});
		const serverResponse6 = await bookResponse2.json();
		const description2 = decryptText(serverResponse6.encryptedDescription, sessionKey);
		logReceive(description2);

		// Отримати записи по захищеному каналу 2
		const title3 = 'nonexist';
		logSend('запит опису книги ', title3);
		const encryptedTitle3 = encryptText(title3, sessionKey);
		const bookResponse3 = await fetch('http://localhost:4000/book', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ encryptedTitle: encryptedTitle3 }),
		});
		const serverResponse7 = await bookResponse3.json();
		const description3 = decryptText(serverResponse7.encryptedDescription, sessionKey);
		logReceive(description3);

	} catch (err) {
		console.error(err);
	}
})();

