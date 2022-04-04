import { assert } from 'assertthat';
import { Buffer } from 'buffer';
import { getRandomBuffer } from '../../lib/crypto/random';
import {
  aesUnwrapKey,
  aesWrapKey,
  invalidKekLengthException,
  invalidKeyDataLengthException,
  invalidWrappedKeyDataLengthException,
  unauthenticException
} from '../../lib/crypto/aesKeyWrap';

// Test vector from https://datatracker.ietf.org/doc/html/rfc3394#section-4.6
const testVector = {
  kekHex: '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
  keyHex: '00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F',
  wrappedKeyHex: '28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21'
};

describe('AES-KEY-Wrap', (): void => {
  describe('normal cases', (): void => {
    describe('Wrapping, using test vector', (): void => {
      test('wraps keyData correctly, using test vector.', async (): Promise<void> => {
        const { kekHex, keyHex, wrappedKeyHex } = testVector;
        const kek = Buffer.from(kekHex, 'hex');
        const key = Buffer.from(keyHex, 'hex');
        const expectedWrappedKey = Buffer.from(wrappedKeyHex, 'hex');

        const wrappedKey = aesWrapKey({ key, kek });

        assert.that(wrappedKey).is.equalTo(expectedWrappedKey);
      });
    });

    describe('Unwrapping, using test vector', (): void => {
      test('unwraps wrapped keyData correctly, using test vector.', async (): Promise<void> => {
        const { kekHex, keyHex, wrappedKeyHex } = testVector;
        const kek = Buffer.from(kekHex, 'hex');
        const expectedKey = Buffer.from(keyHex, 'hex');
        const wrappedKey = Buffer.from(wrappedKeyHex, 'hex');

        const key = aesUnwrapKey({ wrappedKey, kek });

        assert.that(key).is.equalTo(expectedKey);
      });
    });

    describe('Wrap and unwrap, using random values', (): void => {
      test('wraps and unwraps back, correctly, using random values.', async (): Promise<void> => {
        const key = await getRandomBuffer({ length: 32 });
        const kek = await getRandomBuffer({ length: 32 });

        const wrappedKey = aesWrapKey({ key, kek });
        const unwrappedKey = aesUnwrapKey({ wrappedKey, kek });

        assert.that(unwrappedKey).is.equalTo(key);
      });
    });
  });

  describe('error cases', (): void => {
    test('throws unauthenticException if kek is invalid.', async (): Promise<void> => {
      const key = await getRandomBuffer({ length: 32 });
      const kek = await getRandomBuffer({ length: 32 });
      const wrappedKey = aesWrapKey({ key, kek });
      let exception: Error | null = null;

      // This tampers with the first byte of the kek
      kek[0] = kek[0] === 0 ? 1 : 0;

      try {
        aesUnwrapKey({ wrappedKey, kek });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception?.message).is.equalTo(unauthenticException.message);
    });

    test('throws unauthenticException if wrapped key is invalid at the beginning (invalid tag).', async (): Promise<void> => {
      const key = await getRandomBuffer({ length: 32 });
      const kek = await getRandomBuffer({ length: 32 });
      const wrappedKey = aesWrapKey({ key, kek });
      let exception: Error | null = null;

      // This tampers with the first byte of the wrappedKey
      wrappedKey[0] = wrappedKey[0] === 0 ? 1 : 0;

      try {
        aesUnwrapKey({ wrappedKey, kek });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception?.message).is.equalTo(unauthenticException.message);
    });

    test('throws unauthenticException if wrapped key is invalid at the end (invalid ciphertext).', async (): Promise<void> => {
      const key = await getRandomBuffer({ length: 32 });
      const kek = await getRandomBuffer({ length: 32 });
      const wrappedKey = aesWrapKey({ key, kek });
      let exception: Error | null = null;

      // This tampers with the last byte of the wrappedKey
      wrappedKey[39] = wrappedKey[39] === 0 ? 1 : 0;

      try {
        aesUnwrapKey({ wrappedKey, kek });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception?.message).is.equalTo(unauthenticException.message);
    });

    test('throws invalidKeyDataLengthException if keyData is too short.', async (): Promise<void> => {
      const key = await getRandomBuffer({ length: 8 });
      const kek = await getRandomBuffer({ length: 32 });
      let exception: Error | null = null;

      try {
        aesWrapKey({ key, kek });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception?.message).is.equalTo(invalidKeyDataLengthException.message);
    });

    test('throws invalidKeyDataLengthException if keyData length is not multiple of 8.', async (): Promise<void> => {
      const key = await getRandomBuffer({ length: 20 });
      const kek = await getRandomBuffer({ length: 32 });
      let exception: Error | null = null;

      try {
        aesWrapKey({ key, kek });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception?.message).is.equalTo(invalidKeyDataLengthException.message);
    });

    test('throws invalidWrappedKeyDataLengthException if wrapped keyData is too short.', async (): Promise<void> => {
      const wrappedKey = await getRandomBuffer({ length: 16 });
      const kek = await getRandomBuffer({ length: 32 });
      let exception: Error | null = null;

      try {
        aesUnwrapKey({ wrappedKey, kek });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception?.message).is.equalTo(invalidWrappedKeyDataLengthException.message);
    });

    test('throws invalidWrappedKeyDataLengthException if wrapped keyData length is not multiple of 8.', async (): Promise<void> => {
      const wrappedKey = await getRandomBuffer({ length: 30 });
      const kek = await getRandomBuffer({ length: 32 });
      let exception: Error | null = null;

      try {
        aesUnwrapKey({ wrappedKey, kek });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception?.message).is.equalTo(invalidWrappedKeyDataLengthException.message);
    });

    test('throws invalidKekLengthException on wrapping if kek length is not 32.', async (): Promise<void> => {
      const key = await getRandomBuffer({ length: 32 });
      const kek = await getRandomBuffer({ length: 31 });
      let exception: Error | null = null;

      try {
        aesWrapKey({ key, kek });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception?.message).is.equalTo(invalidKekLengthException.message);
    });

    test('throws invalidKekLengthException on unwrapping if kek length is not 32.', async (): Promise<void> => {
      const wrappedKey = await getRandomBuffer({ length: 32 });
      const kek = await getRandomBuffer({ length: 33 });
      let exception: Error | null = null;

      try {
        aesUnwrapKey({ wrappedKey, kek });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception?.message).is.equalTo(invalidKekLengthException.message);
    });
  });
});
