const crypto = require('crypto');


// Encryption with checksum
function encrypt(data, password) {
  const method = 'aes-256-cbc';
  const passwordHash = crypto.createHash('sha256').update(password).digest();
  const iv = Buffer.alloc(16, 0); // 16-byte zeroed buffer
  const dataWithChecksum = crypto.createHash('md5').update(data).digest('hex').substring(0,4) + data;
  const cipher = crypto.createCipheriv(method, passwordHash, iv);
  let encrypted = cipher.update(dataWithChecksum, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
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
    let checksum = decrypted.substring(0,4);
    let message  = decrypted.substring(4);
    if(md5(message).substring(0,4)==checksum){
      return message;
    }else{
      return "";
    }
  } catch (e) {
    return '';
  }
}

