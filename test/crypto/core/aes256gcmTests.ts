import { assert } from 'assertthat';
import { Buffer } from 'buffer';
import { getRandomBuffer } from '../../../lib/crypto/core/random';
import { aes256gcmDecrypt, aes256gcmEncrypt, invalidIvLengthException, invalidKeyLengthException, unauthenticException } from '../../../lib/crypto/core/aes256gcm';

// We are using test vectors from:
// https://boringssl.googlesource.com/boringssl/+/2214/crypto/cipher/cipher_test.txt
// test vectors on line 65, and 67
// vectors on page given in order: KEY, IV, PLAIN, Cipher, AdditionalData, AuthTag
// we concatenated Cipher and AuthTag
const testVectorsCommon = {
  key: 'feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308',
  plain: 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
  associated: 'feedfacedeadbeeffeedfacedeadbeefabaddad2'
};
const testVectors = [
  {
    ...testVectorsCommon,
    iv: 'cafebabefacedbaddecaf888',
    cipherAndTag: '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f66276fc6ece0f4e1768cddf8853bb2d551b'
  },
  {
    ...testVectorsCommon,
    iv: '9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b',
    cipherAndTag: '5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf40fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3fa44a8266ee1c8eb0c8b5d4cf5ae9f19a'
  }
];

const testVectorsWithBuffers = testVectors.map((vector): any => {
  const vectorsArray = Object.entries(vector);

  const vectorsArrayWithBuffers = vectorsArray.map(([ key, value ]): any => [ key, Buffer.from(value, 'hex') ]);

  return Object.fromEntries(vectorsArrayWithBuffers);
});

describe('AES-GCM-256', (): void => {
  describe('Encryption, using test vectors', (): void => {
    for (const [ index, vector ] of testVectorsWithBuffers.entries()) {
      const { key, iv, plain, associated, cipherAndTag } = vector;

      test(`encrypts correctly, using test vector ${index + 1}`, async (): Promise<void> => {
        const result = aes256gcmEncrypt({ plain, key, iv, associated });

        assert.that(result).is.equalTo(cipherAndTag);
      });
    }
  });

  describe('Decryption, using test vectors', (): void => {
    for (const [ index, vector ] of testVectorsWithBuffers.entries()) {
      const { key, iv, plain, associated, cipherAndTag } = vector;

      test(`decrypts correctly, using test vector ${index + 1}`, async (): Promise<void> => {
        const result = aes256gcmDecrypt({ cipherAndTag, key, iv, associated });

        assert.that(result).is.equalTo(plain);
      });
    }
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
      const { plain, key, iv, associated } = testVectorsWithBuffers[0];
      let exception: Error | null = null;

      const cipherAndTag = aes256gcmEncrypt({ plain, key, iv, associated });

      // This tampers with the auth tag.
      cipherAndTag[50] = cipherAndTag[50] === 0 ? 1 : 0;

      try {
        aes256gcmDecrypt({ cipherAndTag, key, iv, associated });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception?.message).is.equalTo(unauthenticException.message);
    });

    test('throws unauthentic exception if ciphertext was tempered with.', async (): Promise<void> => {
      const { plain, key, iv, associated } = testVectorsWithBuffers[0];
      let exception: Error | null = null;

      const cipherAndTag = aes256gcmEncrypt({ plain, key, iv, associated });

      // This tampers with the ciphertext.
      cipherAndTag[50] = cipherAndTag[12] === 0 ? 1 : 0;

      try {
        aes256gcmDecrypt({ cipherAndTag, key, iv, associated });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception?.message).is.equalTo(unauthenticException.message);
    });

    test('throws invalidCryptoInput exception on encryption with invalid key length.', async (): Promise<void> => {
      const testVector = testVectorsWithBuffers[0];
      const invalidTestVector = {
        ...testVector,
        key: Buffer.from('010203', 'hex')
      };
      const { plain, key, iv, associated } = invalidTestVector;
      let exception: Error | null = null;

      try {
        aes256gcmEncrypt({ plain, key, iv, associated });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception?.message).is.equalTo(invalidKeyLengthException.message);
    });

    test('throws invalidCryptoInput exception on encryption with invalid iv length.', async (): Promise<void> => {
      const testVector = testVectorsWithBuffers[0];
      const invalidTestVector = {
        ...testVector,
        iv: Buffer.from('010203', 'hex')
      };
      const { plain, key, iv, associated } = invalidTestVector;
      let exception: Error | null = null;

      try {
        aes256gcmEncrypt({ plain, key, iv, associated });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception?.message).is.equalTo(invalidIvLengthException.message);
    });

    test('throws invalidCryptoInput exception on decryption with invalid key length.', async (): Promise<void> => {
      const testVector = testVectorsWithBuffers[0];
      const invalidTestVector = {
        ...testVector,
        key: Buffer.from('010203', 'hex')
      };
      const { cipherAndTag, key, iv, associated } = invalidTestVector;
      let exception: Error | null = null;

      try {
        aes256gcmDecrypt({ cipherAndTag, key, iv, associated });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception?.message).is.equalTo(invalidKeyLengthException.message);
    });

    test('throws invalidCryptoInput exception on decryption with invalid iv length.', async (): Promise<void> => {
      const testVector = testVectorsWithBuffers[0];
      const invalidTestVector = {
        ...testVector,
        iv: Buffer.from('010203', 'hex')
      };
      const { cipherAndTag, key, iv, associated } = invalidTestVector;
      let exception: Error | null = null;

      try {
        aes256gcmDecrypt({ cipherAndTag, key, iv, associated });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception?.message).is.equalTo(invalidIvLengthException.message);
    });
  });
});
