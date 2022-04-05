import { assert } from 'assertthat';
import { createHmac } from '../../../lib/crypto/core/hmac';
import { getRandomBuffer } from '../../../lib/crypto/core/random';
import { IndexItem } from '../../../lib/index/indexItems/indexItem';
import { checkIndexItemIntegrity, unauthenticException, updateIndexItemHmac } from '../../../lib/crypto/tasks/indexIntegrity';

describe('Index Item Integrity', (): void => {
  test('returns real hmac for given object.', async (): Promise<void> => {
    const key = await getRandomBuffer({ length: 32 });
    const indexItem: IndexItem = {
      id: 'testId',
      hmac: 'oldHmac',
      timestamp: 42
    };

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { hmac, ...dataObject } = indexItem;
    const data = JSON.stringify(dataObject);
    const expectedHmac = createHmac({ data, key });

    updateIndexItemHmac({ indexItem, key });

    // eslint-disable-next-line unicorn/consistent-destructuring
    assert.that(indexItem.hmac).is.equalTo(expectedHmac);
  });

  test('throws unauthentic exception if hmac is invalid.', async (): Promise<void> => {
    const key = await getRandomBuffer({ length: 32 });
    const indexItem: IndexItem = {
      id: 'testId',
      hmac: 'oldHmac',
      timestamp: 42
    };
    let exception: Error | null = null;

    updateIndexItemHmac({ indexItem, key });
    indexItem.hmac = 'invalid';

    try {
      checkIndexItemIntegrity({ indexItem, key });
    } catch (ex: unknown) {
      exception = ex as Error;
    }

    assert.that(exception).is.not.null();
    assert.that(exception?.message).is.equalTo(unauthenticException(indexItem.id).message);
  });

  test('throws no exception if hmac is valid.', async (): Promise<void> => {
    const key = await getRandomBuffer({ length: 32 });
    const indexItem: IndexItem = {
      id: 'testId',
      hmac: 'oldHmac',
      timestamp: 42
    };
    let exception: Error | null = null;

    updateIndexItemHmac({ indexItem, key });

    try {
      checkIndexItemIntegrity({ indexItem, key });
    } catch (ex: unknown) {
      exception = ex as Error;
    }

    assert.that(exception).is.null();
  });
});
