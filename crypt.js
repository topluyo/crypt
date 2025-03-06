const crypto = require('crypto');

function encrypt(data,password){
    const method = 'aes-256-cbc';
    const passwordHash = crypto.createHash('sha256').update(password).digest();
    const iv = Buffer.alloc(16, 0); // 16-byte zeroed buffer
    const cipher = crypto.createCipheriv(method, passwordHash, iv);
    let encrypted = cipher.update(data, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
}

function decrypt(data,password){
    const method = 'aes-256-cbc';
    const passwordHash = crypto.createHash('sha256').update(password).digest();
    const iv = Buffer.alloc(16, 0); // 16-byte zeroed buffer
    const decipher = crypto.createDecipheriv(method, passwordHash, iv);
    let decrypted = decipher.update(data, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted
}
