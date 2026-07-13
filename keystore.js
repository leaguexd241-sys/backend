// keystore.js
const crypto = require('crypto');
const fs = require('fs');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const SALT_LENGTH = 64;
const KEY_LENGTH = 32;
const ITERATIONS = 100000;
const DIGEST = 'sha512';

/**
 * Deriva una clave de cifrado a partir de una contraseña y una sal
 */
function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LENGTH, DIGEST);
}

/**
 * Cifra una clave privada (hex string) con una contraseña
 * Retorna un objeto con los parámetros necesarios para descifrar
 */
function encryptPrivateKey(privateKeyHex, password) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const salt = crypto.randomBytes(SALT_LENGTH);
  const key = deriveKey(password, salt);
  
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(Buffer.from(privateKeyHex.replace(/^0x/, ''), 'hex')),
    cipher.final()
  ]);
  const authTag = cipher.getAuthTag();
  
  return {
    encrypted: encrypted.toString('hex'),
    iv: iv.toString('hex'),
    salt: salt.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

/**
 * Descifra una clave privada a partir de un objeto cifrado y la contraseña
 */
function decryptPrivateKey(encryptedData, password) {
  const { encrypted, iv, salt, authTag } = encryptedData;
  
  const key = deriveKey(password, Buffer.from(salt, 'hex'));
  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(iv, 'hex')
  );
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encrypted, 'hex')),
    decipher.final()
  ]);
  
  return '0x' + decrypted.toString('hex');
}

/**
 * Guarda la clave cifrada en un archivo JSON
 */
function saveEncryptedKey(privateKeyHex, password, filePath = './relayer.key.enc') {
  const encryptedData = encryptPrivateKey(privateKeyHex, password);
  fs.writeFileSync(filePath, JSON.stringify(encryptedData, null, 2));
  console.log(`🔐 Clave cifrada guardada en ${filePath}`);
}

/**
 * Carga la clave cifrada desde un archivo y la descifra
 */
function loadEncryptedKey(password, filePath = './relayer.key.enc') {
  const encryptedData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  return decryptPrivateKey(encryptedData, password);
}

module.exports = {
  encryptPrivateKey,
  decryptPrivateKey,
  saveEncryptedKey,
  loadEncryptedKey
};