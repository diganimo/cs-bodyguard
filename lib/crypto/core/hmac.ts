import { Buffer } from 'buffer';
import forge from 'node-forge';

const createHmac = function ({ data, key }: { data: string; key: Buffer }): string {
  const forgeHmac = forge.hmac.create();

  forgeHmac.start('sha256', key.toString('binary'));
  forgeHmac.update(data);

  const hmacHex = forgeHmac.digest().toHex();

  return Buffer.from(hmacHex, 'hex').toString('base64');
};

export { createHmac };
