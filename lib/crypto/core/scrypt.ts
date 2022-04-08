import { Buffer } from 'buffer';
import { scrypt } from 'scrypt-js';
import toBuffer from 'typedarray-to-buffer';

const createScryptHash = async function ({ data, salt, cpuFactor, memoryFactor, parallelism, keyLength }: {
  data: Buffer;
  salt: Buffer;
  cpuFactor: number;
  memoryFactor: number;
  parallelism: number;
  keyLength: number;
}): Promise<Buffer> {
  const sanitizedKeyLength = keyLength > 32 ? keyLength : 32;
  const key = await scrypt(data, salt, cpuFactor, memoryFactor, parallelism, sanitizedKeyLength, (): void => {
    // NO OP
  });

  return toBuffer(key);
};

export { createScryptHash };
