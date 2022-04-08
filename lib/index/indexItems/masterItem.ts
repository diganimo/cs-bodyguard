import { IndexItem } from './indexItem';

interface MasterItem extends IndexItem {
  salt: string;
  cpuFactor: number;
  memoryFactor: number;
  parallelism: number;
  wrappedMasterEncryptionKey: string;
  wrappedMasterHmacKey: string;
  cipherSuite: string;
}

export { MasterItem };
