import { aesUnwrapKey } from '../../../lib/crypto/core/aesKeyWrap';
import { assert } from 'assertthat';
import { createScryptHash } from '../../../lib/crypto/core/scrypt';
import { changePassword, cipherParams, getKeyRing, init, invalidPasswordException } from '../../../lib/crypto/tasks/master';

const base64For32ByteRegex = /^[a-z\d+\\/]{43}=$/iu;
const base64For40ByteRegex = /^[a-z\d+\\/]{54}==$/iu;

describe('Crypto Master', (): void => {
  describe('normal cases', (): void => {
    test('returns expected master item on init.', async (): Promise<void> => {
      const password = 'testPassword';

      const masterItem = await init({ password });

      const { id, hmac, timestamp, salt, wrappedMasterEncryptionKey,
        wrappedMasterHmacKey, cpuFactor, memoryFactor, parallelism, cipherSuite } = masterItem;

      assert.that(id).is.equalTo('master');
      assert.that(base64For32ByteRegex.test(hmac)).is.true();
      assert.that(timestamp).is.atLeast(Date.now() - 5_000);
      assert.that(timestamp).is.atMost(Date.now());
      assert.that(base64For32ByteRegex.test(salt)).is.true();
      assert.that(base64For40ByteRegex.test(wrappedMasterEncryptionKey)).is.true();
      assert.that(base64For40ByteRegex.test(wrappedMasterHmacKey)).is.true();
      assert.that(cpuFactor).is.equalTo(cipherParams.cpuFactor);
      assert.that(memoryFactor).is.equalTo(cipherParams.memoryFactor);
      assert.that(parallelism).is.equalTo(cipherParams.parallelism);
      assert.that(cipherSuite).is.equalTo(cipherParams.cipherSuite);
    });

    test('updates master item on changePassword.', async (): Promise<void> => {
      const oldPassword = 'testPassword';
      const newPassword = 'newTestPassword';

      const masterItem = await init({ password: oldPassword });

      const wrappedMasterEncryptionKeyBefore = masterItem.wrappedMasterEncryptionKey;
      const wrappedMasterHmacKeyBefore = masterItem.wrappedMasterHmacKey;

      await changePassword({ oldPassword, newPassword, masterItem });

      const wrappedMasterEncryptionKeyAfter = masterItem.wrappedMasterEncryptionKey;
      const wrappedMasterHmacKeyAfter = masterItem.wrappedMasterHmacKey;

      assert.that(wrappedMasterEncryptionKeyBefore).is.not.equalTo(wrappedMasterEncryptionKeyAfter);
      assert.that(wrappedMasterHmacKeyBefore).is.not.equalTo(wrappedMasterHmacKeyAfter);
    }, 7_500);

    test('returns key ring on getKeyRing.', async (): Promise<void> => {
      const password = 'testPassword';
      const masterItem = await init({ password });
      const { wrappedMasterEncryptionKey, wrappedMasterHmacKey, salt, cpuFactor, memoryFactor, parallelism } = masterItem;
      const kek = await createScryptHash({
        data: Buffer.from(password, 'utf8'),
        salt: Buffer.from(salt, 'base64'),
        cpuFactor,
        memoryFactor,
        parallelism,
        keyLength: cipherParams.kekLength
      });

      const keyRing = await getKeyRing({ password, masterItem });
      const { masterEncryptionKey, masterHmacKey } = keyRing;

      const expectedMasterEncryptionKey = aesUnwrapKey({
        wrappedKey: Buffer.from(wrappedMasterEncryptionKey, 'base64'),
        kek
      });
      const expectedMasterHmacKey = aesUnwrapKey({
        wrappedKey: Buffer.from(wrappedMasterHmacKey, 'base64'),
        kek
      });

      assert.that(masterEncryptionKey).is.equalTo(expectedMasterEncryptionKey);
      assert.that(masterHmacKey).is.equalTo(expectedMasterHmacKey);
    });
  });

  describe('error cases', (): void => {
    test('throws invalidPassword Exception on changePassword.', async (): Promise<void> => {
      const oldPassword = 'testPassword';
      const newPassword = 'newTestPassword';
      const masterItem = await init({ password: oldPassword });
      let exception = new Error('function did not throw an exception!');

      await changePassword({ oldPassword: 'invalid', newPassword, masterItem }).catch((ex: Error): void => {
        exception = ex;
      });

      assert.that(exception).is.not.null();
      assert.that(exception.message).is.equalTo(invalidPasswordException.message);
    });

    test('throws invalidPassword Exception on getKeyRing.', async (): Promise<void> => {
      const password = 'testPassword';
      const masterItem = await init({ password });
      let exception = new Error('function did not throw an exception!');

      await getKeyRing({ password: 'invalid', masterItem }).catch((ex: Error): void => {
        exception = ex;
      });

      assert.that(exception).is.not.null();
      assert.that(exception.message).is.equalTo(invalidPasswordException.message);
    });
  });
});
