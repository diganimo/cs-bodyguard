import { IndexItem } from './indexItem';

interface MasterItem extends IndexItem {
  salt: string;
  cpuFactor: number;
  memoryFactor: number;
  parallism: number;
  wrappedMasterEncryptionKey: string;
  wrappedMasterHmacKey: string;
  cipherSuite: string;
}

export { MasterItem };
