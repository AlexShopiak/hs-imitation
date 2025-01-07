const crypto = require('crypto');

const logSend = (text, details=null) => {
    const mode = '\x1b[34mSEND\x1b[0m'
    console.log(`${mode}|${text}${details || ''}`)
}

const logReceive = ( text, details=null) => {
    const mode = '\x1b[33mRECEIVE\x1b[0m'
    console.log(`${mode}|${text}${details || ''}`)
}

const encryptText = (text, key) => {
    const cipher = crypto.createCipheriv('aes-256-ecb', Buffer.from(key, 'base64'), null);
    let encrypted = cipher.update(text, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
}

const decryptText = (encryptedData, key) => {
    const decipher = crypto.createDecipheriv('aes-256-ecb', Buffer.from(key, 'base64'), null);
    let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

module.exports = { logSend, logReceive, encryptText, decryptText};