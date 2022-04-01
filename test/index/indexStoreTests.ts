import { assert } from 'assertthat';
import { browserIndexStore } from '../../lib/index/browserIndexStore';
import { IndexItem } from 'lib/index/indexItems/indexItem';
import localforage from 'localforage';
import memoryStorageDriver from 'localforage-memoryStorageDriver';
import { nativeIndexStore } from '../../lib/index/nativeIndexStore';
import { noSuchIndexItemException } from '../../lib/exceptions';
import reactNativeFsMock from '../mocks/reactNativeFsMock';

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

const setupNativeStoreBeforeEach = async function (): Promise<void> {
  // No-Op
};

const setupNativeStoreAfterEach = async function (): Promise<void> {
  reactNativeFsMock.clear();
};

const getItemFromBrowserStore = async function (id: string): Promise<IndexItem | null> {
  return await localforage.getItem(id) ?? null;
};

const setItemToBrowserStore = async function (item: IndexItem): Promise<void> {
  await localforage.setItem(item.id, item);
};

const getItemFromNativeStore = async function (id: string): Promise<IndexItem | null> {
  const path = `${reactNativeFsMock.DocumentDirectoryPath}/${id}`;
  const itemString = await reactNativeFsMock.readFile(path, 'utf-8');

  return itemString === '' ? null : JSON.parse(itemString);
};

const setItemToNativeStore = async function (item: IndexItem): Promise<void> {
  const path = `${reactNativeFsMock.DocumentDirectoryPath}/${item.id}`;
  const itemString = JSON.stringify(item);
  const date = new Date();

  date.setTime(item.timestamp);

  await reactNativeFsMock.writeFile(path, itemString, 'utf-8');
  await reactNativeFsMock.touch(path, date);
};

const storeTestResources = [
  {
    suiteName: 'IndexStore - browser',
    store: browserIndexStore,
    storeSetupBeforeEach: setupBrowserStoreBeforeEach,
    storeSetupAfterEach: setupBrowserStoreAfterEach,
    getItem: getItemFromBrowserStore,
    setItem: setItemToBrowserStore
  },
  {
    suiteName: 'IndexStore - native',
    store: nativeIndexStore,
    storeSetupBeforeEach: setupNativeStoreBeforeEach,
    storeSetupAfterEach: setupNativeStoreAfterEach,
    getItem: getItemFromNativeStore,
    setItem: setItemToNativeStore
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
      });

      describe('delta', (): void => {
        test('Gets delta for all 2 items.', async (): Promise<void> => {
          await setItem(testItem);
          await setItem(anotherTestItem);

          const delta = await store.getDelta({ timestampSinceLastDelta: 0 });

          assert.that(delta.length).is.equalTo(2);
          assert.that(delta[0].id).is.equalTo(testItem.id);
          assert.that(delta[1].id).is.equalTo(anotherTestItem.id);
          assert.that(delta[0].timestamp).is.equalTo(testItem.timestamp);
          assert.that(delta[1].timestamp).is.equalTo(anotherTestItem.timestamp);
        });

        test('Gets delta for most recent item.', async (): Promise<void> => {
          await setItem(testItem);
          await setItem(anotherTestItem);

          const delta = await store.getDelta({ timestampSinceLastDelta: 100 });

          assert.that(delta.length).is.equalTo(1);
          assert.that(delta[0].id).is.equalTo(anotherTestItem.id);
          assert.that(delta[0].timestamp).is.equalTo(anotherTestItem.timestamp);
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
