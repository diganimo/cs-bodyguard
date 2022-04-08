import { assert } from 'assertthat';
import { Buffer } from 'buffer';
import { getRandomBuffer } from '../../../lib/crypto/core/random';
import { aes256gcmDecrypt, aes256gcmEncrypt, invalidIvLengthException, invalidKeyLengthException, unauthenticException } from '../../../lib/crypto/core/aes256gcm';

// We are using test vector on line 65 from:
// https://boringssl.googlesource.com/boringssl/+/2214/crypto/cipher/cipher_test.txt
// vector on page given in order: KEY, IV, PLAIN, Cipher, AdditionalData, AuthTag
// we concatenated Cipher and AuthTag and renamed properties
const testVector = {
  keyHex: 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
  plainHex: 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
  associatedHex: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
  ivHex: 'cafebabefacedbaddecaf888',
  cipherAndTagHex: '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b'
};

describe('AES-GCM-256', (): void => {
  describe('Encryption, using test vector', (): void => {
    test('encrypts correctly, using test vector.', async (): Promise<void> => {
      const { keyHex, ivHex, plainHex, associatedHex, cipherAndTagHex } = testVector;
      const plain = Buffer.from(plainHex, 'hex');
      const key = Buffer.from(keyHex, 'hex');
      const iv = Buffer.from(ivHex, 'hex');
      const associated = Buffer.from(associatedHex, 'hex');
      const cipherAndTag = Buffer.from(cipherAndTagHex, 'hex');

      const result = aes256gcmEncrypt({ plain, key, iv, associated });

      assert.that(result).is.equalTo(cipherAndTag);
    });
  });

  describe('Decryption, using test vector', (): void => {
    test('decrypts correctly, using test vector.', async (): Promise<void> => {
      const { keyHex, ivHex, plainHex, associatedHex, cipherAndTagHex } = testVector;
      const plain = Buffer.from(plainHex, 'hex');
      const key = Buffer.from(keyHex, 'hex');
      const iv = Buffer.from(ivHex, 'hex');
      const associated = Buffer.from(associatedHex, 'hex');
      const cipherAndTag = Buffer.from(cipherAndTagHex, 'hex');

      const result = aes256gcmDecrypt({ cipherAndTag, key, iv, associated });

      assert.that(result).is.equalTo(plain);
    });
  });

  describe('encrypts and decrypts back, using random values', (): void => {
    test('encrypts and decrypts back, correctly.', async (): Promise<void> => {
      const key = await getRandomBuffer({ length: 32 });
      const iv = await getRandomBuffer({ length: 12 });
      const plain = await getRandomBuffer({ length: 42 });
      const associated = await getRandomBuffer({ length: 21 });

      const cipherAndTag = aes256gcmEncrypt({ plain, key, iv, associated });
      const plainBack = aes256gcmDecrypt({ cipherAndTag, key, iv, associated });

      assert.that(plainBack).is.equalTo(plain);
    });
  });

  describe('error case(s)', (): void => {
    test('throws unauthentic exception if authTag was tempered with.', async (): Promise<void> => {
      const { plainHex, keyHex, ivHex, associatedHex } = testVector;
      const plain = Buffer.from(plainHex, 'hex');
      const key = Buffer.from(keyHex, 'hex');
      const iv = Buffer.from(ivHex, 'hex');
      const associated = Buffer.from(associatedHex, 'hex');
      let exception = new Error('function did not throw an exception!');

      const cipherAndTag = aes256gcmEncrypt({ plain, key, iv, associated });

      // This tampers with the auth tag.
      cipherAndTag[50] = cipherAndTag[50] === 0 ? 1 : 0;

      try {
        aes256gcmDecrypt({ cipherAndTag, key, iv, associated });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception.message).is.equalTo(unauthenticException.message);
    });

    test('throws unauthentic exception if ciphertext was tempered with.', async (): Promise<void> => {
      const { plainHex, keyHex, ivHex, associatedHex } = testVector;
      const plain = Buffer.from(plainHex, 'hex');
      const key = Buffer.from(keyHex, 'hex');
      const iv = Buffer.from(ivHex, 'hex');
      const associated = Buffer.from(associatedHex, 'hex');
      let exception = new Error('function did not throw an exception!');

      const cipherAndTag = aes256gcmEncrypt({ plain, key, iv, associated });

      // This tampers with the ciphertext.
      cipherAndTag[12] = cipherAndTag[12] === 0 ? 1 : 0;

      try {
        aes256gcmDecrypt({ cipherAndTag, key, iv, associated });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception.message).is.equalTo(unauthenticException.message);
    });

    test('throws invalidKeyLength exception on encryption with invalid key length.', async (): Promise<void> => {
      const invalidTestVector = {
        ...testVector,
        keyHex: '010203'
      };
      const { plainHex, keyHex, ivHex, associatedHex } = invalidTestVector;
      const plain = Buffer.from(plainHex, 'hex');
      const key = Buffer.from(keyHex, 'hex');
      const iv = Buffer.from(ivHex, 'hex');
      const associated = Buffer.from(associatedHex, 'hex');
      let exception = new Error('function did not throw an exception!');

      try {
        aes256gcmEncrypt({ plain, key, iv, associated });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception.message).is.equalTo(invalidKeyLengthException.message);
    });

    test('throws invalidIvLength exception on encryption with invalid iv length.', async (): Promise<void> => {
      const invalidTestVector = {
        ...testVector,
        ivHex: '010203'
      };
      const { plainHex, keyHex, ivHex, associatedHex } = invalidTestVector;
      const plain = Buffer.from(plainHex, 'hex');
      const key = Buffer.from(keyHex, 'hex');
      const iv = Buffer.from(ivHex, 'hex');
      const associated = Buffer.from(associatedHex, 'hex');
      let exception = new Error('function did not throw an exception!');

      try {
        aes256gcmEncrypt({ plain, key, iv, associated });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception.message).is.equalTo(invalidIvLengthException.message);
    });

    test('throws invalidKeyLength exception on decryption with invalid key length.', async (): Promise<void> => {
      const invalidTestVector = {
        ...testVector,
        keyHex: '010203'
      };
      const { cipherAndTagHex, keyHex, ivHex, associatedHex } = invalidTestVector;
      const cipherAndTag = Buffer.from(cipherAndTagHex, 'hex');
      const key = Buffer.from(keyHex, 'hex');
      const iv = Buffer.from(ivHex, 'hex');
      const associated = Buffer.from(associatedHex, 'hex');
      let exception = new Error('function did not throw an exception!');

      try {
        aes256gcmDecrypt({ cipherAndTag, key, iv, associated });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception.message).is.equalTo(invalidKeyLengthException.message);
    });

    test('throws invalidCryptoInput exception on decryption with invalid iv length.', async (): Promise<void> => {
      const invalidTestVector = {
        ...testVector,
        ivHex: '010203'
      };
      const { cipherAndTagHex, keyHex, ivHex, associatedHex } = invalidTestVector;
      const cipherAndTag = Buffer.from(cipherAndTagHex, 'hex');
      const key = Buffer.from(keyHex, 'hex');
      const iv = Buffer.from(ivHex, 'hex');
      const associated = Buffer.from(associatedHex, 'hex');
      let exception = new Error('function did not throw an exception!');

      try {
        aes256gcmDecrypt({ cipherAndTag, key, iv, associated });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception.message).is.equalTo(invalidIvLengthException.message);
    });
  });
});
