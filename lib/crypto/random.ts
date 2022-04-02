import { Buffer } from 'buffer';
import forge from 'node-forge';

const forgeRandom = async function (length: number): Promise<string> {
  return new Promise((resolve, reject): void => {
    const sanitizedLength = length > 0 ? length : 1;

    forge.random.getBytes(sanitizedLength, (err, bytes): void => {
      if (err) {
        return reject(err);
      }
      resolve(bytes);
    });
  });
};

const getRandomBuffer = async function ({ length }: { length: number }): Promise<Buffer> {
  const bytes = await forgeRandom(length);
  const hex = forge.util.bytesToHex(bytes);

  return Buffer.from(hex, 'hex');
};

export { getRandomBuffer };
