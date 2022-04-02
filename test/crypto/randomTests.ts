import { assert } from 'assertthat';
import { Buffer } from 'buffer';
import { getRandomBuffer } from '../../lib/crypto/random';

const lengthsToTest = [ 12, 32, 42 ];

describe('Random', (): void => {
  describe('normal cases', (): void => {
    for (const length of lengthsToTest) {
      test(`returns ${length} bytes buffer.`, async (): Promise<void> => {
        const bytes = await getRandomBuffer({ length });

        assert.that(bytes.length).is.equalTo(length);
      });
    }
  });

  describe('error cases', (): void => {
    test('returns one byte buffer on given length 0.', async (): Promise<void> => {
      const length = 0;
      const bytes = await getRandomBuffer({ length });

      assert.that(bytes.length).is.equalTo(1);
    });

    test('returns one byte buffer on negative given length.', async (): Promise<void> => {
      const length = -1;
      const bytes = await getRandomBuffer({ length });

      assert.that(bytes.length).is.equalTo(1);
    });
  });
});
