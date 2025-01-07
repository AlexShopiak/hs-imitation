const { logSend, logReceive } = require('./tool/tools.js');
const express = require('express');
const crypto = require('crypto');

const PORT = 3000;
const app = express();
app.use(express.json());

// Ключі СА
const { privateKey: CA_privateKey, publicKey: CA_publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

// Генерація сертифікату для користувача
app.post('/generate', (req, res) => {
	logReceive("запит на сертифікат")
	const { subject } = req.body;
	if (!subject) {
		return res.status(400).send('Subject is required');
	}

	// Генерація пари ключів для користувача
	const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
	console.log("Згенеровано ключі");

	// Створення часових міток
	const now = new Date();
	const notAfter = new Date(now);
	notAfter.setFullYear(now.getFullYear() + 1);
	console.log("Додано часові мітки");

	// Створення підпису
	const signature = crypto.createSign('sha256');
	signature.update(subject);
	const certificateSignature = signature.sign(CA_privateKey, 'base64');
	console.log("Підписано сертифікат")

	logSend("сертифікат")
	res.json({
		privateKey: privateKey.export({ type: 'pkcs1', format: 'pem' }),
		certificate: {
			version: 'X.509',
			serialNumber: Math.floor(Math.random() * 1000000).toString(),
			subject: { commonName: subject },
			issuer: { commonName: 'Oleksii Shopiak CA' },
			validity: {
				notBefore: now.toUTCString(),
				notAfter: notAfter.toUTCString(),
			},
			publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
			signature: certificateSignature,
		}
	});
});


// Верифікація сертифікату
app.post('/verify', (req, res) => {
	logReceive("запит на верифікацію")
    const { certificate } = req.body;
    if (!certificate || !certificate.signature) {
        return res.json({ verified: false, message: "No signature or crtificate"});
    }

    if (certificate.issuer.commonName !== 'Oleksii Shopiak CA') {
        return res.json({ verified: false, message: "Invalid issuer" });
    }

	const now = new Date();
	const notBefore = new Date(certificate.validity.notBefore);
	const notAfter = new Date(certificate.validity.notAfter);
	if (now <= notBefore && now >= notAfter) {
		return res.json({ verified: false, message: "Certificate is expired" });
	}

    // Перевірка підпису публічним ключем
	const data = certificate.subject.commonName;
	const isVerified = crypto.createVerify('sha256').update(data).verify(CA_publicKey, certificate.signature, 'base64');
	res.json({ verified: isVerified });
	logSend(isVerified);
});


app.listen(PORT, () => {
  	console.log(`CA is running on http://localhost:${PORT}`);
});
