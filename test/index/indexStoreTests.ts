import { assert } from 'assertthat';
import { browserIndexStore } from '../../lib/index/browserIndexStore';
import { IndexItem } from 'lib/index/indexItems/indexItem';
import localforage from 'localforage';
import memoryStorageDriver from 'localforage-memoryStorageDriver';
import { noSuchIndexItemException } from '../../lib/exceptions';

const testItem: IndexItem = {
  id: 'testId',
  hmac: 'testHmac',
  timestamp: 42
};

const modifiedTestItem: IndexItem = {
  id: 'testId',
  hmac: 'testHmac2',
  timestamp: 242
};

const anotherTestItem: IndexItem = {
  id: 'testId3',
  hmac: 'testHmac3',
  timestamp: 342
};

let useInMemoryEnabledForBrowserIndexStrore = false;

const setupBrowserStoreBeforeEach = async function (): Promise<void> {
  if (useInMemoryEnabledForBrowserIndexStrore) {
    return;
  }
  await browserIndexStore.useInMemory(memoryStorageDriver);
  useInMemoryEnabledForBrowserIndexStrore = true;
};

const setupBrowserStoreAfterEach = async function (): Promise<void> {
  await localforage.clear();
};

const getItemFromBrowserStore = async function (id: string): Promise<IndexItem | null> {
  return await localforage.getItem(id) ?? null;
};

const setItemToBrowserStore = async function (item: IndexItem): Promise<void> {
  await localforage.setItem(item.id, item);
};

const storeTestResources = [
  {
    suiteName: 'IndexStore - browser',
    store: browserIndexStore,
    storeSetupBeforeEach: setupBrowserStoreBeforeEach,
    storeSetupAfterEach: setupBrowserStoreAfterEach,
    getItem: getItemFromBrowserStore,
    setItem: setItemToBrowserStore
  }
];

for (const resource of storeTestResources) {
  const { suiteName, store, storeSetupBeforeEach, storeSetupAfterEach, getItem, setItem } = resource;

  describe(suiteName, (): void => {
    beforeEach(storeSetupBeforeEach);
    afterEach(storeSetupAfterEach);

    describe('normal cases', (): void => {
      describe('add', (): void => {
        test('Adds an item in store.', async (): Promise<void> => {
          await store.setItem({ item: testItem });

          const item = await getItem(testItem.id);

          assert.that(item?.id).is.equalTo(testItem.id);
          assert.that(item?.hmac).is.equalTo(testItem.hmac);
          assert.that(item?.timestamp).is.equalTo(testItem.timestamp);
        });
      });

      describe('get', (): void => {
        test('Gets the item with given id from store.', async (): Promise<void> => {
          await setItem(testItem);

          const item = await store.getItem({ id: testItem.id });

          assert.that(item.id).is.equalTo(testItem.id);
          assert.that(item.hmac).is.equalTo(testItem.hmac);
          assert.that(item.timestamp).is.equalTo(testItem.timestamp);
        });

        test('Gets all 2 items from store.', async (): Promise<void> => {
          await setItem(testItem);
          await setItem(anotherTestItem);

          const items = await store.getAllRecentItems({ timestamp: -1 });

          assert.that(items.length).is.equalTo(2);
          assert.that(items[0].id).is.equalTo(testItem.id);
          assert.that(items[1].id).is.equalTo(anotherTestItem.id);
        });

        test('Gets most recent item from store.', async (): Promise<void> => {
          await setItem(testItem);
          await setItem(anotherTestItem);

          const items = await store.getAllRecentItems({ timestamp: 200 });

          assert.that(items.length).is.equalTo(1);
          assert.that(items[0].id).is.equalTo(anotherTestItem.id);
        });
      });

      describe('count', (): void => {
        test('Counts all 2 items from store.', async (): Promise<void> => {
          await setItem(testItem);
          await setItem(anotherTestItem);

          const count = await store.countAllRecentItems({ timestamp: -1 });

          assert.that(count).is.equalTo(2);
        });

        test('Counts most recent item from store.', async (): Promise<void> => {
          await setItem(testItem);
          await setItem(anotherTestItem);

          const count = await store.countAllRecentItems({ timestamp: 200 });

          assert.that(count).is.equalTo(1);
        });
      });

      describe('update', (): void => {
        test('Updates the item with given id from store, applying the given changes.', async (): Promise<void> => {
          await setItem(testItem);

          await store.setItem({ item: modifiedTestItem });

          const item = await getItem(testItem.id);

          assert.that(item?.id).is.equalTo(testItem.id);
          assert.that(item?.hmac).is.equalTo(modifiedTestItem.hmac);
          assert.that(item?.timestamp).is.equalTo(modifiedTestItem.timestamp);
        });
      });

      describe('delete', (): void => {
        test('Deletes the item with given id from store, but keeps the other.', async (): Promise<void> => {
          const { id } = modifiedTestItem;

          await setItem(testItem);
          await setItem(anotherTestItem);

          await store.deleteItem({ id });

          const item = await getItem(testItem.id);
          const anotherItem = await getItem(anotherTestItem.id);

          assert.that(item).is.null();
          assert.that(anotherItem).is.not.null();
        });

        test('Deletes all 2 items from store.', async (): Promise<void> => {
          await setItem(testItem);
          await setItem(anotherTestItem);

          await store.deleteAllItems();

          const item = await getItem(testItem.id);
          const anotherItem = await getItem(anotherTestItem.id);

          assert.that(item).is.null();
          assert.that(anotherItem).is.null();
        });
      });
    });

    describe('error cases', (): void => {
      test('Throws exception on getItem(...), if item with given id does not exist.', async (): Promise<void> => {
        const { id } = testItem;
        let exception = new Error('function did not throw an exception!');

        await store.getItem({ id }).catch((ex: Error): void => {
          exception = ex;
        });

        assert.that(exception).is.not.null();
        assert.that(exception.message).is.equalTo(noSuchIndexItemException({ id }).message);
      });

      test('Throws exception on deleteItem(...), if item with given id does not exist.', async (): Promise<void> => {
        const { id } = testItem;
        let exception = new Error('function did not throw an exception!');

        await store.deleteItem({ id }).catch((ex: Error): void => {
          exception = ex;
        });

        assert.that(exception).is.not.null();
        assert.that(exception.message).is.equalTo(noSuchIndexItemException({ id }).message);
      });
    });
  });
}
