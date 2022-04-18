import { IndexDelta } from './indexDelta';
import { IndexItem } from './indexItems/indexItem';
import localforage from 'localforage';
import { IndexStore, noSuchIndexItemException } from './indexStore';

interface BrowserIndexStore extends IndexStore {
  useInMemory: (memoryStorageDriver: any) => Promise<void>;
}

const browserIndexStore: BrowserIndexStore = {
  async setItem ({ item }: { item: IndexItem }): Promise<void> {
    await localforage.setItem(item.id, item);
  },

  async getItem ({ id }: { id: string }): Promise<IndexItem> {
    const item = await localforage.getItem(id);

    if (!item) {
      throw noSuchIndexItemException(id);
    }

    return item as IndexItem;
  },

  async deleteItem ({ id }: { id: string }): Promise<void> {
    const existingItem = await localforage.getItem(id);

    if (!existingItem) {
      throw noSuchIndexItemException(id);
    }

    await localforage.removeItem(id);
  },

  async getDelta ({ timestampSinceLastDelta }: { timestampSinceLastDelta: number }): Promise<IndexDelta[]> {
    const items: IndexDelta[] = [];
    const keys = await localforage.keys();

    for (const key of keys) {
      const item = await this.getItem({ id: key });

      if (item.timestamp > timestampSinceLastDelta) {
        const { id, timestamp } = item;

        items.push({ id, timestamp });
      }
    }

    return items;
  },

  async deleteAllItems (): Promise<void> {
    await localforage.clear();
  },

  async useInMemory (memoryStorageDriver: any): Promise<void> {
    await localforage.defineDriver(memoryStorageDriver);

    // eslint-disable-next-line no-underscore-dangle
    await localforage.setDriver(memoryStorageDriver._driver);
  }

};

export { browserIndexStore };
