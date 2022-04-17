import { Buffer } from 'buffer';
import { IndexItem } from 'lib/index/indexItems/indexItem';
import { MasterItem } from 'lib/index/indexItems/masterItem';
import { checkHmac, updateHmac } from './tasks/indexIntegrity';
import { decrypt, encrypt } from './tasks/contentEncryption';
import { getKeyRing, init, KeyRing, updateKeys } from './tasks/master';

interface LockableKeyRing extends KeyRing {
  locked: boolean;
}

const lockableKeyRing: LockableKeyRing = {
  masterEncryptionKey: Buffer.from(''),
  masterHmacKey: Buffer.from(''),
  locked: true
};

const initialze = async ({ password }: { password: string }): Promise<MasterItem> => await init({ password });

const unlock = async ({ password, masterItem }: { password: string; masterItem: MasterItem }): Promise<void> => {
  const newKeyRing = await getKeyRing({ password, masterItem });

  lockableKeyRing.masterEncryptionKey = newKeyRing.masterEncryptionKey;
  lockableKeyRing.masterHmacKey = newKeyRing.masterHmacKey;
  lockableKeyRing.locked = false;
};

const lock = (): void => {
  lockableKeyRing.masterEncryptionKey = Buffer.from('');
  lockableKeyRing.masterHmacKey = Buffer.from('');
  lockableKeyRing.locked = true;
};

const changePassword = async ({ oldPassword, newPassword, masterItem }: {
  oldPassword: string; newPassword: string; masterItem: MasterItem; }): Promise<void> => {
  await updateKeys({ oldPassword, newPassword, masterItem });
};

const updateIndexItemHmac = async ({ indexItem }: { indexItem: IndexItem }): Promise<void> => {
  updateHmac({ indexItem, key: lockableKeyRing.masterHmacKey });
};

const checkIndexItemHmac = async ({ indexItem }: { indexItem: IndexItem }): Promise<void> => {
  checkHmac({ indexItem, key: lockableKeyRing.masterHmacKey });
};

const encryptContent = async ({ content, contentId }: { content: Buffer; contentId: string }): Promise<Buffer> =>
  await encrypt({ content, masterKey: lockableKeyRing.masterEncryptionKey, contentId });

const decryptContent = async ({ encryptedContent, contentId }: { encryptedContent: Buffer; contentId: string }): Promise<Buffer> =>
  decrypt({ encryptedContent, masterKey: lockableKeyRing.masterEncryptionKey, contentId });

export { changePassword, checkIndexItemHmac, decryptContent, encryptContent, initialze, lock, unlock, updateIndexItemHmac };
