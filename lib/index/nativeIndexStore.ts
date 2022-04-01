import { IndexItem } from './indexItems/indexItem';
import { IndexStore } from './indexStore';
import { noSuchIndexItemException } from '../exceptions';
import reactNativeFs from 'react-native-fs';

const encoding = 'utf-8';

// Directory path is without trailing slash
const directory = reactNativeFs.DocumentDirectoryPath;

const getPath = function (id: string): string {
  return `${directory}/${id}`;
};

const nativeIndexStore: IndexStore = {
  async setItem ({ item }: { item: IndexItem }): Promise<void> {
    const path = getPath(item.id);
    const itemString = JSON.stringify(item);

    await reactNativeFs.writeFile(path, itemString, encoding);
  },

  async getItem ({ id }: { id: string }): Promise<IndexItem> {
    const path = getPath(id);
    const itemString = await reactNativeFs.readFile(path, encoding);

    if (!itemString) {
      throw noSuchIndexItemException({ id });
    }

    return JSON.parse(itemString);
  },

  async deleteItem ({ id }: { id: string }): Promise<void> {
    const path = getPath(id);

    const itemString = await reactNativeFs.readFile(path, encoding);

    if (!itemString) {
      throw noSuchIndexItemException({ id });
    }

    await reactNativeFs.unlink(path);
  },

  async getAllRecentItems ({ timestamp }: { timestamp: number }): Promise<IndexItem[]> {
    const fileEntryList = await reactNativeFs.readDir(directory);
    const items: IndexItem[] = [];

    for (const entry of fileEntryList) {
      if (!entry.isFile() || !entry.mtime || entry.mtime.getTime() <= timestamp) {
        continue;
      }
      const itemString = await reactNativeFs.readFile(entry.path, encoding);
      const item = JSON.parse(itemString);

      items.push(item);
    }

    return items;
  },

  async countAllRecentItems ({ timestamp }: { timestamp: number }): Promise<number> {
    const fileEntryList = await reactNativeFs.readDir(directory);
    let count = 0;

    for (const entry of fileEntryList) {
      if (entry.isFile() && entry.mtime && entry.mtime.getTime() > timestamp) {
        count += 1;
      }
    }

    return count;
  },

  async deleteAllItems (): Promise<void> {
    const fileEntryList = await reactNativeFs.readDir(directory);

    for (const entry of fileEntryList) {
      if (entry.isFile()) {
        await reactNativeFs.unlink(entry.path);
      }
    }
  }
};

export { nativeIndexStore };
