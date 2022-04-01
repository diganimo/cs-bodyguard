import { IndexItem } from './indexItems/indexItem';
import { IndexStore } from './indexStore';
import localforage from 'localforage';
import { noSuchIndexItemException } from '../../lib/exceptions';

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
      throw noSuchIndexItemException({ id });
    }

    return item as IndexItem;
  },

  async deleteItem ({ id }: { id: string }): Promise<void> {
    const existingItem = await localforage.getItem(id);

    if (!existingItem) {
      throw noSuchIndexItemException({ id });
    }

    await localforage.removeItem(id);
  },

  async useInMemory (memoryStorageDriver: any): Promise<void> {
    await localforage.defineDriver(memoryStorageDriver);

    // eslint-disable-next-line no-underscore-dangle
    await localforage.setDriver(memoryStorageDriver._driver);
  },

  async getAllRecentItems ({ timestamp }: { timestamp: number }): Promise<IndexItem[]> {
    const items: IndexItem[] = [];
    const keys = await localforage.keys();

    for (const key of keys) {
      const item = await this.getItem({ id: key });

      if (item.timestamp > timestamp) {
        items.push(item);
      }
    }

    return items;
  },

  async countAllRecentItems ({ timestamp }: { timestamp: number }): Promise<number> {
    const keys = await localforage.keys();

    let count = 0;

    for (const key of keys) {
      const item = await this.getItem({ id: key });

      if (item.timestamp > timestamp) {
        count += 1;
      }
    }

    return count;
  },

  async deleteAllItems (): Promise<void> {
    await localforage.clear();
  }

};

export { browserIndexStore };
