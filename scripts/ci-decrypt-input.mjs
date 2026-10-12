import { createDecipheriv,createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

const [input, output] = process.argv.slice(2);
if (!input || !output || path.resolve(input) === path.resolve(output)) {
  throw new Error('Usage: node ci-decrypt-input.mjs encrypted-source.enc private-source.tar.gz');
}
const encodedKey = process.env.LSC_IOS_BUILD_KEY ?? '';
if (!/^[A-Za-z0-9+/]{43}=$/.test(encodedKey)) throw new Error('The temporary build key is missing or malformed.');
const key = Buffer.from(encodedKey, 'base64');
if (key.length !== 32) throw new Error('An AES-256 key is required.');
const encrypted = await readFile(input);
const expected=process.env.LSC_IOS_INPUT_SHA256;
if(expected&&(!/^[a-f0-9]{64}$/.test(expected)||createHash('sha256').update(encrypted).digest('hex')!==expected))throw new Error('The encrypted input checksum does not match the requested source.');
const magic = Buffer.from('LSCIOS1\n', 'ascii');
if (encrypted.length < magic.length + 12 + 16 + 16 || !encrypted.subarray(0, magic.length).equals(magic)) {
  throw new Error('Invalid encrypted source package.');
}
const iv = encrypted.subarray(8, 20);
const tag = encrypted.subarray(20, 36);
const cipher = encrypted.subarray(36);
const decipher = createDecipheriv('aes-256-gcm', key, iv);
decipher.setAuthTag(tag);
const source = Buffer.concat([decipher.update(cipher), decipher.final()]);
if (source[0] !== 0x1f || source[1] !== 0x8b || source.length > 100 * 1024 * 1024) {
  throw new Error('The authenticated input must be a bounded gzip source archive.');
}
await writeFile(output, source, { flag: 'wx', mode: 0o600 });
key.fill(0);
source.fill(0);
console.log('Authenticated private build input decrypted inside the temporary runner workspace.');
