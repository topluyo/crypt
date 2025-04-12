const crypto = require('crypto');

// Function to add checksum to the message
function encodeChecksum(message) {
  let sum = 0;
  for (let i = 0; i < message.length; i++) {
    sum += message.charCodeAt(i);
  }
  const prefix = String.fromCharCode(sum % 255);
  return prefix + message;
}


// Encryption with checksum
function encrypt(data, password) {
  const method = 'aes-256-cbc';
  const passwordHash = crypto.createHash('sha256').update(password).digest();
  const iv = Buffer.alloc(16, 0); // 16-byte zeroed buffer

  const dataWithChecksum = encodeChecksum(data);
  const cipher = crypto.createCipheriv(method, passwordHash, iv);
  let encrypted = cipher.update(dataWithChecksum, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
}


// Function to verify checksum and extract the original message
function decodeChecksum(message) {
  if (message.length < 2) {
    return false;
  }
  const checksumChar = message[0];
  const actualMessage = message.slice(1);
  let sum = 0;
  for (let i = 0; i < actualMessage.length; i++) {
    sum += actualMessage.charCodeAt(i);
  }
  const expectedChecksum = String.fromCharCode(sum % 255);
  return checksumChar === expectedChecksum ? actualMessage : false;
}

// Decryption with checksum verification
function decrypt(data, password) {
  const method = 'aes-256-cbc';
  const passwordHash = crypto.createHash('sha256').update(password).digest();
  const iv = Buffer.alloc(16, 0); // 16-byte zeroed buffer

  try {
    const decipher = crypto.createDecipheriv(method, passwordHash, iv);
    let decrypted = decipher.update(data, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    const original = decodeChecksum(decrypted);
    return original !== false ? original : '';
  } catch (e) {
    return '';
  }
}
