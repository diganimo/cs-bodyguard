// Implemented, following this specification: https://www.heise.de/netze/rfc/rfcs/rfc3394.shtml
// testet, using this test vector: https://datatracker.ietf.org/doc/html/rfc3394#section-4.6
// also tested with random values, checking the formular: key = unwrap(wrap(key, kek), kek)

/* eslint-disable id-length */
/* eslint-disable no-bitwise */

import { Buffer } from 'buffer';
import forge from 'node-forge';

const invalidKeyDataLengthException = new Error('Invalid KeyData length. Length must be multiple of and at least 16 byte.');
const invalidWrappedKeyDataLengthException = new Error('Invalid wrapped KeyData length. Length must be multiple of and at least 24 byte.');
const invalidKekLengthException = new Error('Invalid kek length. Length must be 32 byte.');
const unauthenticException = new Error('Inregrity check failed. Wrong kek?');

const iv = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');
const paddingOf16Byte = Buffer.from('10101010101010101010101010101010', 'hex');

const checkKekLength = (kek: Buffer): void => {
  if (kek.length !== 32) {
    throw invalidKekLengthException;
  }
};

const checkWrapInputLengths = (key: Buffer, kek: Buffer): void => {
  if ((key.length % 8) > 0 || key.length < 16) {
    throw invalidKeyDataLengthException;
  }

  checkKekLength(kek);
};

const checkUnwrapInputLengths = (wrappedKey: Buffer, kek: Buffer): void => {
  if ((wrappedKey.length % 8) > 0 || wrappedKey.length < 24) {
    throw invalidWrappedKeyDataLengthException;
  }

  checkKekLength(kek);
};

const aesEncrypt = (key: Buffer, plaintext: Buffer): Buffer => {
  const keyForgeBuffer = forge.util.createBuffer(key, 'raw');
  const plainForgeBuffer = forge.util.createBuffer(plaintext, 'raw');
  const cipher = forge.cipher.createCipher('AES-ECB', keyForgeBuffer);

  cipher.start({});
  cipher.update(plainForgeBuffer);
  cipher.finish();

  const encryptedHex = cipher.output.toHex();

  // Drop last 16 byte since this is the padding (padding can't be disabled with node-forge, unfortunately)
  return Buffer.from(encryptedHex, 'hex').slice(0, -16);
};

// Restore padding (padding can't be disabled with node-forge, unfortunately)
const restorePadding = (ciphertextWithoutPadding: Buffer, key: Buffer): Buffer => {
  const padding = aesEncrypt(key, paddingOf16Byte);

  return Buffer.concat([ ciphertextWithoutPadding, padding ]);
};

const aesDecrypt = (key: Buffer, ciphertext: Buffer): Buffer => {
  const ciphertextPadded = restorePadding(ciphertext, key);
  const keyForgeBuffer = forge.util.createBuffer(key, 'raw');
  const cipherForgeBuffer = forge.util.createBuffer(ciphertextPadded, 'raw');
  const cipher = forge.cipher.createDecipher('AES-ECB', keyForgeBuffer);

  cipher.start({});
  cipher.update(cipherForgeBuffer);
  cipher.finish();

  const decryptedHex = cipher.output.toHex();

  return Buffer.from(decryptedHex, 'hex');
};

const msb = (countOfBytes: number, buffer: Buffer): Buffer => buffer.slice(0, countOfBytes);

const lsb = (countOfBytes: number, buffer: Buffer): Buffer => buffer.slice(buffer.length - countOfBytes, buffer.length);

const calculateA = (B: Buffer, n: number, j: number, i: number): Buffer => {
  const msbBuffer = msb(8, B);

  const msbBigInt = msbBuffer.readBigUInt64BE(0);
  const resultBigInt = msbBigInt ^ BigInt((n * j) + i);
  const resultBuffer = Buffer.allocUnsafe(8);

  resultBuffer.writeBigUInt64BE(resultBigInt, 0);

  return resultBuffer;
};

const calculateB = (kek: Buffer, A: Buffer, j: number, i: number, n: number, r: Buffer): Buffer => {
  const tBigInt = BigInt((n * j) + i);
  const aBigInt = A.readBigUInt64BE(0);
  const aXoredBigInt = aBigInt ^ tBigInt;
  const aXoredBuffer = Buffer.allocUnsafe(8);

  aXoredBuffer.writeBigUInt64BE(aXoredBigInt, 0);

  return aesDecrypt(kek, Buffer.concat([ aXoredBuffer, r ]));
};

const aesWrapKey = ({ key, kek }: { key: Buffer; kek: Buffer }): Buffer => {
  checkWrapInputLengths(key, kek);

  const R: Buffer[] = [];
  const n = key.length / 8;

  for (let i = 0; i < n; i++) {
    R[i] = key.slice(8 * i, 8 * (i + 1));
  }

  const aCopy = new Uint8Array(iv.length);

  iv.copy(aCopy);
  let A = Buffer.from(aCopy);

  for (let j = 0; j <= 5; j++) {
    for (let i = 0; i < n; i++) {
      const B = aesEncrypt(kek, Buffer.concat([ A, R[i] ]));

      A = calculateA(B, n, j, i + 1);

      R[i] = lsb(8, B);
    }
  }

  return Buffer.concat([ A, ...R ]);
};

const aesUnwrapKey = ({ wrappedKey, kek }: { wrappedKey: Buffer; kek: Buffer }): Buffer => {
  checkUnwrapInputLengths(wrappedKey, kek);

  const n = (wrappedKey.length / 8) - 1;
  const R: Buffer[] = [];

  let A = wrappedKey.slice(0, 8);

  for (let i = 1; i <= n; i++) {
    R.push(wrappedKey.slice(8 * i, 8 * (i + 1)));
  }

  for (let j = 5; j >= 0; j--) {
    for (let i = n - 1; i >= 0; i--) {
      const B = calculateB(kek, A, j, i + 1, n, R[i]);

      A = msb(8, B);
      R[i] = lsb(8, B);
    }
  }

  if (!A.equals(iv)) {
    throw unauthenticException;
  }

  return Buffer.concat(R);
};

/* eslint-enable no-bitwise */
/* eslint-enable id-length */

export { aesWrapKey, aesUnwrapKey, invalidKekLengthException, invalidKeyDataLengthException,
  invalidWrappedKeyDataLengthException, unauthenticException };
