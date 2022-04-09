import { assert } from 'assertthat';
import forge from 'node-forge';
import { changePassword, cipherParams, getKeyRing, init, invalidPasswordException } from '../../../lib/crypto/tasks/master';

// Derived from previously dynamic tests before they got refactored to be static
const expectedWrappedMasterEncryptionKey = 'k3kvNbWTnVgk/iqK3u6G6OeOuWcOaKgW6ycCGCsk72OJ6TqOfsGVAQ==';
const expectedWrappedMasterHmacKey = 'Z41ZV1rbJwHuYH5+V9oKAqbmr76zOhhaDVn/CWqK0L82MedU+GnQyg==';
const expectedHmac = 'sdqBiAb8YAl4n5VmFDpzeewEWXqlZfJXdn1pIbZqDvQ=';
const expectedModifiedWrappedMasterEncryptionKey = 'SR6mRjs1W3n7fjkMPe9GT+fqszhTk2IBeOetp2Ty6opQ0NG8ALiihw==';
const expectedModifiedWrappedMasterHmacKey = 'CRPd6Zkw8lYlhlbwswdUSviCx8aD/BKozOIALTRTZJo3i/67Ilub2A==';
const expectedModifiedHmac = 'KeNs6/goloEeW38MzHtW2ZwXtwkRacDr65NeJ3You88=';

const mockedTimestamp = 42;
const mockedModifiedTimestamp = 242;

const mockedRandomStrings = {
  salt: 'salt-salt-salt-salt-salt-salt...',
  encKey: 'encKey-encKey-encKey-encKey.....',
  macKey: 'macKey-macKey-macKey-macKey.....'
};

// eslint-disable-next-line no-undef
const randomMock = jest.spyOn(forge.random, 'getBytesSync');
// eslint-disable-next-line no-undef
const timeMock = jest.spyOn(Date, 'now');

const initialMasterItem = {
  id: 'master',
  hmac: expectedHmac,
  timestamp: mockedTimestamp,
  salt: Buffer.from(mockedRandomStrings.salt, 'binary').toString('base64'),
  cpuFactor: cipherParams.cpuFactor,
  memoryFactor: cipherParams.memoryFactor,
  parallelism: cipherParams.parallelism,
  wrappedMasterEncryptionKey: expectedWrappedMasterEncryptionKey,
  wrappedMasterHmacKey: expectedWrappedMasterHmacKey,
  cipherSuite: cipherParams.cipherSuite
};

describe('Crypto Master', (): void => {
  describe('normal cases', (): void => {
    test('returns expected master item on init.', async (): Promise<void> => {
      randomMock.mockReturnValueOnce(mockedRandomStrings.salt);
      randomMock.mockReturnValueOnce(mockedRandomStrings.encKey);
      randomMock.mockReturnValueOnce(mockedRandomStrings.macKey);
      timeMock.mockReturnValueOnce(mockedTimestamp);

      const password = 'testPassword';

      const masterItem = await init({ password });

      const { id, hmac, timestamp, salt, wrappedMasterEncryptionKey,
        wrappedMasterHmacKey, cpuFactor, memoryFactor, parallelism, cipherSuite } = masterItem;

      assert.that(id).is.equalTo('master');
      assert.that(hmac).is.equalTo(expectedHmac);
      assert.that(timestamp).is.equalTo(mockedTimestamp);
      assert.that(salt).is.equalTo(Buffer.from(mockedRandomStrings.salt, 'binary').toString('base64'));
      assert.that(wrappedMasterEncryptionKey).is.equalTo(expectedWrappedMasterEncryptionKey);
      assert.that(wrappedMasterHmacKey).is.equalTo(expectedWrappedMasterHmacKey);
      assert.that(cpuFactor).is.equalTo(cipherParams.cpuFactor);
      assert.that(memoryFactor).is.equalTo(cipherParams.memoryFactor);
      assert.that(parallelism).is.equalTo(cipherParams.parallelism);
      assert.that(cipherSuite).is.equalTo(cipherParams.cipherSuite);
    });

    test('updates master item on changePassword.', async (): Promise<void> => {
      timeMock.mockReturnValueOnce(mockedModifiedTimestamp);

      const oldPassword = 'testPassword';
      const newPassword = 'newTestPassword';
      const masterItem = { ...initialMasterItem };

      await changePassword({ oldPassword, newPassword, masterItem });

      assert.that(masterItem.timestamp).is.equalTo(mockedModifiedTimestamp);
      assert.that(masterItem.wrappedMasterEncryptionKey).is.equalTo(expectedModifiedWrappedMasterEncryptionKey);
      assert.that(masterItem.wrappedMasterHmacKey).is.equalTo(expectedModifiedWrappedMasterHmacKey);
      assert.that(masterItem.hmac).is.equalTo(expectedModifiedHmac);
    }, 7_500);

    test('returns key ring on getKeyRing.', async (): Promise<void> => {
      const password = 'testPassword';
      const masterItem = { ...initialMasterItem };

      const keyRing = await getKeyRing({ password, masterItem });
      const { masterEncryptionKey, masterHmacKey } = keyRing;

      assert.that(masterEncryptionKey).is.equalTo(Buffer.from(mockedRandomStrings.encKey, 'binary'));
      assert.that(masterHmacKey).is.equalTo(Buffer.from(mockedRandomStrings.macKey, 'binary'));
    });
  });

  describe('error cases', (): void => {
    test('throws invalidPassword Exception on changePassword.', async (): Promise<void> => {
      const oldPassword = 'invalid';
      const newPassword = 'newTestPassword';
      const masterItem = { ...initialMasterItem };
      let exception = new Error('function did not throw an exception!');

      await changePassword({ oldPassword, newPassword, masterItem }).catch((ex: Error): void => {
        exception = ex;
      });

      assert.that(exception).is.not.null();
      assert.that(exception.message).is.equalTo(invalidPasswordException.message);
    });

    test('throws invalidPassword Exception on getKeyRing.', async (): Promise<void> => {
      const password = 'invalid';
      const masterItem = { ...initialMasterItem };
      let exception = new Error('function did not throw an exception!');

      await getKeyRing({ password, masterItem }).catch((ex: Error): void => {
        exception = ex;
      });

      assert.that(exception).is.not.null();
      assert.that(exception.message).is.equalTo(invalidPasswordException.message);
    });
  });
});
