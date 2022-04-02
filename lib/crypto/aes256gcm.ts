import { Buffer } from 'buffer';
import forge from 'node-forge';
import { invalidCryptoInputLengthException, tooShortCryptoInputException, unauthenticException } from '../exceptions';

const checkInput = function (key: Buffer, iv: Buffer): void {
  if (key.length !== 32) {
    const input = 'key';
    const lengthGiven = key.length;
    const lengthExpected = 32;

    throw invalidCryptoInputLengthException({ input, lengthGiven, lengthExpected });
  }

  if (iv.length < 12) {
    const input = 'key';
    const lengthGiven = iv.length;
    const lengthAtLeastExpected = 12;

    throw tooShortCryptoInputException({ input, lengthGiven, lengthAtLeastExpected });
  }
};

const aes256gcmEncrypt = function ({ plain, key, iv, associated }: {
  plain: Buffer;
  key: Buffer;
  iv: Buffer;
  associated: Buffer;
}): Buffer {
  checkInput(key, iv);

  const plainForgeBuffer = forge.util.createBuffer(plain, 'raw');
  const keyForgeBuffer = forge.util.createBuffer(key, 'raw');
  const ivForgeBuffer = forge.util.createBuffer(iv, 'raw');
  const cipher = forge.cipher.createCipher('AES-GCM', keyForgeBuffer);

  cipher.start({ iv: ivForgeBuffer, tagLength: 128, additionalData: associated.toString('binary') });
  cipher.update(plainForgeBuffer);
  cipher.finish();

  const cipherHex = cipher.output.toHex();
  const tagHex = cipher.mode.tag.toHex();
  const cipherAndTagHex = `${cipherHex}${tagHex}`;

  return Buffer.from(cipherAndTagHex, 'hex');
};

const aes256gcmDecrypt = function ({ cipherAndTag, key, iv, associated }: {
  cipherAndTag: Buffer;
  key: Buffer;
  iv: Buffer;
  associated: Buffer;
}): Buffer {
  checkInput(key, iv);

  const cipherLength = cipherAndTag.length - 16;
  const cipherBuffer = cipherAndTag.slice(0, cipherLength);
  const tagBuffer = cipherAndTag.slice(cipherLength, cipherAndTag.length);
  const cipherForgeBuffer = forge.util.createBuffer(cipherBuffer, 'raw');
  const tagForgeBuffer = forge.util.createBuffer(tagBuffer, 'raw');
  const keyForgeBuffer = forge.util.createBuffer(key, 'raw');
  const ivForgeBuffer = forge.util.createBuffer(iv, 'raw');
  const cipher = forge.cipher.createDecipher('AES-GCM', keyForgeBuffer);

  cipher.start({
    iv: ivForgeBuffer,
    additionalData: associated.toString('binary'),
    tag: tagForgeBuffer
  });
  cipher.update(cipherForgeBuffer);
  const pass = cipher.finish();

  if (!pass) {
    throw unauthenticException();
  }

  const plainHex = cipher.output.toHex();

  return Buffer.from(plainHex, 'hex');
};

export { aes256gcmEncrypt, aes256gcmDecrypt };
