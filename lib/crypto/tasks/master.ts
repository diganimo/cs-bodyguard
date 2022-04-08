import { createScryptHash } from '../core/scrypt';
import { getRandomBuffer } from '../core/random';
import { MasterItem } from '../../index/indexItems/masterItem';
import { updateIndexItemHmac } from './indexIntegrity';
import { aesUnwrapKey, aesWrapKey, unauthenticException } from '../core/aesKeyWrap';

interface KeyRing {
  masterEncryptionKey: Buffer;
  masterHmacKey: Buffer;
}

const invalidPasswordException = new Error('Failed: Invalid password?');

const cipherParams = {
  kekLength: 32,
  cpuFactor: 32_768,
  memoryFactor: 8,
  parallism: 1,
  cipherSuite: 'scrypt-aeskeywrap256-aesgcm256-hmacsha256'
};

const getExceptionToThrow = (error: Error): Error => error.message === unauthenticException.message ? invalidPasswordException : error;

const rewrapKey = (oldKek: Buffer, newKek: Buffer, masterItem: MasterItem): Buffer => {
  let wrappedMasterEncryptionKey = Buffer.from(masterItem.wrappedMasterEncryptionKey, 'base64');
  let wrappedMasterHmacKey = Buffer.from(masterItem.wrappedMasterHmacKey, 'base64');

  const masterEncryptionKey = aesUnwrapKey({ wrappedKey: wrappedMasterEncryptionKey, kek: oldKek });
  const masterHmacKey = aesUnwrapKey({ wrappedKey: wrappedMasterHmacKey, kek: oldKek });

  wrappedMasterEncryptionKey = aesWrapKey({ key: masterEncryptionKey, kek: newKek });
  wrappedMasterHmacKey = aesWrapKey({ key: masterHmacKey, kek: newKek });

  /* eslint-disable no-param-reassign */
  masterItem.wrappedMasterEncryptionKey = wrappedMasterEncryptionKey.toString('base64');
  masterItem.wrappedMasterHmacKey = wrappedMasterHmacKey.toString('base64');
  /* eslint-enable no-param-reassign */

  return masterHmacKey;
};

const init = async ({ password }: { password: string }): Promise<MasterItem> => {
  const { cpuFactor, memoryFactor, parallism, kekLength, cipherSuite } = cipherParams;
  const salt = await getRandomBuffer({ length: 32 });
  const masterEncryptionKey = await getRandomBuffer({ length: 32 });
  const masterHmacKey = await getRandomBuffer({ length: 32 });
  const data = Buffer.from(password, 'utf8');
  const kek = await createScryptHash({ data, salt, cpuFactor, memoryFactor, parallism, keyLength: kekLength });
  const wrappedMasterEncryptionKey = aesWrapKey({ key: masterEncryptionKey, kek });
  const wrappedMasterHmacKey = aesWrapKey({ key: masterHmacKey, kek });
  const masterItem: MasterItem = {
    id: 'master',
    hmac: '',
    timestamp: Date.now(),
    salt: salt.toString('base64'),
    cpuFactor,
    memoryFactor,
    parallism,
    wrappedMasterEncryptionKey: wrappedMasterEncryptionKey.toString('base64'),
    wrappedMasterHmacKey: wrappedMasterHmacKey.toString('base64'),
    cipherSuite
  };

  updateIndexItemHmac({ indexItem: masterItem, key: masterHmacKey });

  return masterItem;
};

const changePassword = async ({ oldPassword, newPassword, masterItem }: {
  oldPassword: string; newPassword: string; masterItem: MasterItem; }): Promise<void> => {
  const { cpuFactor, memoryFactor, parallism, kekLength } = cipherParams;
  const salt = Buffer.from(masterItem.salt, 'base64');
  const oldPasswordBuffer = Buffer.from(oldPassword, 'utf8');
  const newPasswordBuffer = Buffer.from(newPassword, 'utf8');

  const oldKek = await createScryptHash({ data: oldPasswordBuffer, salt, cpuFactor, memoryFactor, parallism, keyLength: kekLength });
  const newKek = await createScryptHash({ data: newPasswordBuffer, salt, cpuFactor, memoryFactor, parallism, keyLength: kekLength });

  try {
    const masterHmacKey = rewrapKey(oldKek, newKek, masterItem);

    updateIndexItemHmac({ indexItem: masterItem, key: masterHmacKey });
  } catch (ex: unknown) {
    throw getExceptionToThrow(ex as Error);
  }
};

const getKeyRing = async ({ password, masterItem }: { password: string; masterItem: MasterItem }): Promise<KeyRing> => {
  const { cpuFactor, memoryFactor, parallism, kekLength } = cipherParams;
  const salt = Buffer.from(masterItem.salt, 'base64');
  const data = Buffer.from(password, 'utf8');
  const kek = await createScryptHash({ data, salt, cpuFactor, memoryFactor, parallism, keyLength: kekLength });
  const wrappedMasterEncryptionKey = Buffer.from(masterItem.wrappedMasterEncryptionKey, 'base64');
  const wrappedMasterHmacKey = Buffer.from(masterItem.wrappedMasterHmacKey, 'base64');

  try {
    const masterEncryptionKey = aesUnwrapKey({ wrappedKey: wrappedMasterEncryptionKey, kek });
    const masterHmacKey = aesUnwrapKey({ wrappedKey: wrappedMasterHmacKey, kek });

    return {
      masterEncryptionKey,
      masterHmacKey
    };
  } catch (ex: unknown) {
    throw getExceptionToThrow(ex as Error);
  }
};

export { init, changePassword, getKeyRing, cipherParams, invalidPasswordException };
