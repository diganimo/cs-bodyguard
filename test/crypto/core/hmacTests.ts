import { assert } from 'assertthat';
import { Buffer } from 'buffer';
import { createHmac } from '../../../lib/crypto/core/hmac';

// We are using test vectors from ietf
// https://datatracker.ietf.org/doc/html/rfc4231#section-4.1 (first 4 test cases)
const testVectors = [
  {
    keyHex: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    messageHex: '4869205468657265',
    expectedHmacHex: 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    testIndex: 1
  },
  {
    keyHex: '4a656665',
    messageHex: '7768617420646f2079612077616e7420666f72206e6f7468696e673f',
    expectedHmacHex: '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'
  },
  {
    keyHex: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    messageHex: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    expectedHmacHex: '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe'
  },
  {
    keyHex: '0102030405060708090a0b0c0d0e0f10111213141516171819',
    messageHex: 'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
    expectedHmacHex: '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b'
  }
];

describe('hmac', (): void => {
  for (const [ vectorIndex, { keyHex, messageHex, expectedHmacHex }] of testVectors.entries()) {
    test(`Returns real hmac for test case ${vectorIndex + 1}.`, async (): Promise<void> => {
      const key = Buffer.from(keyHex, 'hex');
      const data = Buffer.from(messageHex, 'hex').toString('binary');

      const createdHmac = createHmac({ data, key });

      assert.that(createdHmac).is.equalTo(expectedHmacHex);
    });
  }
});
