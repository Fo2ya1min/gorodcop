// Запускается только внутри GitHub Actions во время деплоя.
// Берёт пароль и токен из переменных окружения (заполняются из GitHub Secrets),
// шифрует токен паролем и сохраняет результат в auth.json.
// В открытом виде ни пароль, ни токен никуда не записываются и не логируются.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const password = process.env.SITE_PASSWORD;
const token = process.env.WRITE_TOKEN;
const outDir = process.argv[2] || '.';

if (!password || !token) {
  console.error('Не заданы секреты SITE_PASSWORD и/или WRITE_TOKEN.');
  process.exit(1);
}

const ITERATIONS = 250000;
const salt = crypto.randomBytes(16);
const iv = crypto.randomBytes(12); // 12 байт — стандарт для AES-GCM

const key = crypto.pbkdf2Sync(password, salt, ITERATIONS, 32, 'sha256');

const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const encrypted = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
const authTag = cipher.getAuthTag();

// Web Crypto (браузер) ожидает тег аутентификации приклеенным в конец шифротекста
const combined = Buffer.concat([encrypted, authTag]);

const payload = {
  v: 1,
  iterations: ITERATIONS,
  salt: salt.toString('base64'),
  iv: iv.toString('base64'),
  ciphertext: combined.toString('base64')
};

fs.writeFileSync(path.join(outDir, 'auth.json'), JSON.stringify(payload));
console.log('auth.json сгенерирован (секреты в него не попали в открытом виде).');
