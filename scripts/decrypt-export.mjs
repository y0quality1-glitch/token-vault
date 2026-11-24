#!/usr/bin/env node
/**
 * Opens a Token Vault secret export (format token-vault-secret-export/v1): scrypt derives the key
 * from the passphrase chosen when the export was prepared; AES-256-GCM decrypts and checks it.
 *
 *   node scripts/decrypt-export.mjs export.json > secrets.json
 *
 * The passphrase is read from TV_EXPORT_PASSPHRASE, or asked for on the terminal (not echoed).
 * The output is plaintext secret values: keep it off shared disks, and delete it when done.
 * It can be imported again (Secrets > Import, format JSON).
 */
import { createDecipheriv, scryptSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';

const path = process.argv[2];
if (!path) {
  console.error('Usage: node scripts/decrypt-export.mjs <export.json>');
  process.exit(2);
}

function askHidden(question) {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
    rl._writeToOutput = (s) => {
      if (s.includes(question)) process.stderr.write(s);
    };
    rl.question(question, (answer) => {
      rl.close();
      process.stderr.write('\n');
      resolve(answer);
    });
  });
}

const file = JSON.parse(readFileSync(path, 'utf8'));
if (file.format !== 'token-vault-secret-export/v1') {
  console.error(`Not a Token Vault secret export (format: ${file.format ?? 'missing'})`);
  process.exit(1);
}
const passphrase = process.env.TV_EXPORT_PASSPHRASE ?? (await askHidden('Passphrase: '));
const { N, r, p, salt } = file.kdf;
const key = scryptSync(passphrase, Buffer.from(salt, 'base64'), 32, { N, r, p, maxmem: 128 * N * r * 2 });
const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(file.cipher.iv, 'base64'));
decipher.setAAD(Buffer.from(file.exportId));
decipher.setAuthTag(Buffer.from(file.cipher.tag, 'base64'));
try {
  const plain = Buffer.concat([decipher.update(Buffer.from(file.ciphertext, 'base64')), decipher.final()]).toString('utf8');
  process.stdout.write(JSON.stringify(JSON.parse(plain), null, 2) + '\n');
} catch {
  console.error('Wrong passphrase, or the file was changed.');
  process.exit(1);
}
