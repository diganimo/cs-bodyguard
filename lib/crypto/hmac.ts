import { Buffer } from 'buffer';
import forge from 'node-forge';

const createHmac = function ({ data, key }: { data: string; key: Buffer }): string {
  const forgeHmac = forge.hmac.create();

  forgeHmac.start('sha256', key.toString('binary'));
  forgeHmac.update(data);

  return forgeHmac.digest().toHex();
};

const isValidHmac = function ({ data, key, givenHmac }: { data: string; key: Buffer; givenHmac: string }): boolean {
  const actualHmac = createHmac({ data, key });

  return actualHmac === givenHmac;
};

export { createHmac, isValidHmac };
