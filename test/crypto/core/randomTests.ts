import { assert } from 'assertthat';
import forge from 'node-forge';
import { getRandomBuffer } from '../../../lib/crypto/core/random';

const lengthsToTest = [ 12, 32, 42 ];

describe('Random', (): void => {
  describe('length checks', (): void => {
    for (const length of lengthsToTest) {
      test(`returns ${length} bytes buffer.`, async (): Promise<void> => {
        const bytes = await getRandomBuffer({ length });

        assert.that(bytes.length).is.equalTo(length);
      });
    }

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

  describe('mocked random test', (): void => {
    test('returns expected buffer.', async (): Promise<void> => {
      const testRandomString = '1234';

      // eslint-disable-next-line no-undef
      const randomMock = jest.spyOn(forge.random, 'getBytesSync');

      randomMock.mockReturnValueOnce(testRandomString);

      const bytes = await getRandomBuffer({ length: 4 });

      assert.that(bytes).is.equalTo(Buffer.from(testRandomString, 'binary'));
    });
  });
});
