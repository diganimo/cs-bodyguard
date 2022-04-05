// Implemented, following this specification: https://www.heise.de/netze/rfc/rfcs/rfc3394.shtml (index approach),
// originated by http://csrc.nist.gov/encryption/kms/key-wrap.pdf
// Testet, using this test vector: https://datatracker.ietf.org/doc/html/rfc3394#section-4.6
// Also tested with random values, checking the formular: key = unwrap(wrap(key, kek), kek)

/* eslint-disable id-length */

import { Buffer } from 'buffer';
import forge from 'node-forge';

const invalidKeyDataLengthException = new Error('Invalid KeyData length. Length in byte must be 32.');
const invalidWrappedKeyDataLengthException = new Error('Invalid wrapped KeyData length. Length in byte must be 40.');
const invalidKekLengthException = new Error('Invalid kek length. Length in byte must be 32.');
const unauthenticException = new Error('Inregrity check failed. Wrong kek?');

const iv = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');
const paddingOf16Byte = Buffer.from('10101010101010101010101010101010', 'hex');

const checkKekLength = (kek: Buffer): void => {
  if (kek.length !== 32) {
    throw invalidKekLengthException;
  }
};

const checkWrapInputLengths = (key: Buffer, kek: Buffer): void => {
  if (key.length !== 32) {
    throw invalidKeyDataLengthException;
  }

  checkKekLength(kek);
};

const checkUnwrapInputLengths = (wrappedKey: Buffer, kek: Buffer): void => {
  if (wrappedKey.length !== 40) {
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

const split = (input: Buffer): Buffer[] => {
  const output: Buffer[] = [];

  for (let i = 0; i < input.length / 8; i++) {
    output[i] = input.slice(8 * i, 8 * (i + 1));
  }

  return output;
};

const join = (parts: Buffer[]): Buffer => Buffer.concat([ ...parts ]);

const copyBuffer = (src: Buffer): Buffer => {
  const copy = new Uint8Array(src.length);

  src.copy(copy);

  return Buffer.from(copy);
};

/* eslint-disable-next-line no-bitwise */
const xor = (left: bigint, right: bigint): bigint => left ^ right;

const calculateT = (n: number, j: number, i: number): number => (n * j) + i + 1;

const bufferToBigInt = (buffer: Buffer): bigint => buffer.readBigUInt64BE();

const bigIntToBuffer = (bigInt: bigint): Buffer => {
  const buffer = Buffer.allocUnsafe(8);

  buffer.writeBigUInt64BE(bigInt);

  return buffer;
};

const writeBigIntToBuffer = (buffer: Buffer, bigInt: bigint): void => {
  buffer.writeBigUInt64BE(bigInt, 0);
};

const doWrappingTransformation = (A: Buffer, R: Buffer[], kek: Buffer, n: number, j: number, i: number): void => {
  const t = calculateT(n, j, i);
  const W = join([ A, R[i] ]);
  const B = aesEncrypt(kek, W);
  const splitted = split(B);
  const xored = xor(bufferToBigInt(splitted[0]), BigInt(t));

  writeBigIntToBuffer(A, xored);

  // eslint-disable-next-line no-param-reassign
  R[i] = splitted[1];
};

const doWrappingRound = (A: Buffer, R: Buffer[], kek: Buffer, n: number, j: number): void => {
  for (let i = 0; i < n; i++) {
    doWrappingTransformation(A, R, kek, n, j, i);
  }
};

const doUnwrappingTransformation = (A: Buffer, R: Buffer[], kek: Buffer, n: number, j: number, i: number): void => {
  const t = calculateT(n, j, i);
  const xored = xor(bufferToBigInt(A), BigInt(t));
  const B = join([ bigIntToBuffer(xored), R[i] ]);
  const W = aesDecrypt(kek, B);
  const splitted = split(W);

  A.write(splitted[0].toString('binary'), 'binary');

  // eslint-disable-next-line no-param-reassign
  R[i] = splitted[1];
};

const doUnwrappingRound = (A: Buffer, R: Buffer[], kek: Buffer, n: number, j: number): void => {
  for (let i = n - 1; i >= 0; i--) {
    doUnwrappingTransformation(A, R, kek, n, j, i);
  }
};

const aesWrapKey = ({ key, kek }: { key: Buffer; kek: Buffer }): Buffer => {
  checkWrapInputLengths(key, kek);

  const R = split(key);
  const n = R.length;

  const A = copyBuffer(iv);

  for (let j = 0; j <= 5; j++) {
    doWrappingRound(A, R, kek, n, j);
  }

  return join([ A, ...R ]);
};

const aesUnwrapKey = ({ wrappedKey, kek }: { wrappedKey: Buffer; kek: Buffer }): Buffer => {
  checkUnwrapInputLengths(wrappedKey, kek);

  // eslint-disable-next-line prefer-const
  let [ A, ...R ] = split(wrappedKey);
  const n = R.length;

  for (let j = 5; j >= 0; j--) {
    doUnwrappingRound(A, R, kek, n, j);
  }

  if (!A.equals(iv)) {
    throw unauthenticException;
  }

  return Buffer.concat(R);
};

/* eslint-enable id-length */

export { aesWrapKey, aesUnwrapKey, invalidKekLengthException, invalidKeyDataLengthException,
  invalidWrappedKeyDataLengthException, unauthenticException };
