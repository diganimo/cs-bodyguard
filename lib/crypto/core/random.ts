import { Buffer } from 'buffer';
import forge from 'node-forge';

const forgeRandom = async function (length: number): Promise<string> {
  return new Promise((resolve, reject): void => {
    const sanitizedLength = length > 0 ? length : 1;

    try {
      // Sync method is ok here, because we are wrapping it with promise
      // eslint-disable-next-line no-sync
      resolve(forge.random.getBytesSync(sanitizedLength));
    } catch (ex: unknown) {
      reject(ex);
    }
  });
};

const getRandomBuffer = async function ({ length }: { length: number }): Promise<Buffer> {
  const bytes = await forgeRandom(length);
  const hex = forge.util.bytesToHex(bytes);

  return Buffer.from(hex, 'hex');
};

export { getRandomBuffer };
