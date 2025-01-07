const { logSend, logReceive,encryptText, decryptText } = require('./tool/tools.js');
const express = require('express');
const crypto = require('crypto');

const PORT = 4000;
const app = express();
app.use(express.json());

let publicKey = null;
let privateKey = null;
let certificate = null;

let serverRandom = null;
let clientRandom = null;
let sessionKey = null;

const books = {
	"Romeo and Juliet": "Трагічна історія кохання двох молодих людей із ворогуючих сімей, написана Вільямом Шекспіром.",
	"The Odyssey": "Епічна поема Гомера про пригоди Одіссея, який намагається повернутися додому після Троянської війни.",
	"Faust": "Трагедія Гете про вченого, який укладає угоду з дияволом в обмін на знання і насолоду.",
	"Don Quixote": "Роман Сервантеса про рицаря, який прагне здійснювати подвиги, але стикається з реальністю.",
	"Pygmalion": "П'єса Бернарда Шоу про трансформацію простої дівчини на витончену леді завдяки навчанню.",
};

// Отримати сертифікат
(async () => {
	try {
		logSend('запит на сертифікат до СА')
		const response = await fetch('http://localhost:3000/generate', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ subject: 'Server Certificate'}),
		});
		
		if (!response.ok) {
			throw Error('Failed to get certificate from CA');
		}

		const data = await response.json();
		publicKey = data.certificate.publicKey
		privateKey = data.privateKey
		certificate = data.certificate

		logReceive('сертифікат від СА')
	} catch (error) {
		console.error(error);
	}
})();

// Сервер відповідає повідомленням "привіт сервера" з сертифікатом
app.post('/hello', async (req, res) => {
	const clientRequest = req.body.message;
	logReceive(clientRequest)

	clientRandom = clientRequest.split(":")[1];
	serverRandom = crypto.randomBytes(16).toString('base64');
	
	res.json({
		message: `Привіт сервера:${serverRandom}`,
		certificate: certificate
	});
	logSend(`Привіт сервера:${serverRandom}`)
});

// Сервер розшифровує premaster та генерує sessionKey
app.post('/premaster', (req, res) => {
	const { premaster } = req.body;
	const decryptedPremaster = crypto.privateDecrypt(privateKey, Buffer.from(premaster, 'base64')).toString('base64');
	logReceive('premaster');
	
	// Генерація session key
	sessionKey = crypto.createHash('sha256').update(decryptedPremaster).update(clientRandom).update(serverRandom).digest('base64');
	console.log('Згенеровано sessionKey:', sessionKey);

	res.json({ message: 'session key згенеровано' });
	logSend('session key згенеровано');
});

// Сервер у відповідь надсилає повідомлення "готовий", зашифроване сеансовим ключем. 
app.post('/ready', (req, res) => {
	const { encryptedMessage } = req.body;
	const readyMessage = 'готовий';

	const decrypted = decryptText(encryptedMessage, sessionKey);
	logReceive(decrypted);

	if (decrypted === readyMessage) {
		const encryptedMessage = encryptText(readyMessage, sessionKey);
		res.json({ encryptedMessage: encryptedMessage });
		logSend('готовий')
	} else {
		res.json({ encryptedMessage: "bad encryption" });
		logSend('bad encryption')
	}
});

// Отримати записи по захищеному каналу 
app.post('/book', (req, res) => {
	const { encryptedTitle } = req.body;

	const title = decryptText(encryptedTitle, sessionKey);
	logReceive('запит опису на книгу ', title);
	
	const description = books[title] ? books[title] : "Книгу не знайдено";
	const encryptedDescription = encryptText(description, sessionKey) ;

	res.json({ encryptedDescription: encryptedDescription });
	logSend(description);
});

app.listen(PORT, () => {
  	console.log(`Server is running on http://localhost:${PORT}`);
});