import { IndexDelta } from './indexDelta';
import { IndexItem } from './indexItems/indexItem';
import reactNativeFs from 'react-native-fs';
import { IndexStore, noSuchIndexItemException } from './indexStore';

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
    const date = new Date();

    date.setTime(item.timestamp);

    await reactNativeFs.writeFile(path, itemString, encoding);
    await reactNativeFs.touch(path, date);
  },

  async getItem ({ id }: { id: string }): Promise<IndexItem> {
    const path = getPath(id);
    const itemString = await reactNativeFs.readFile(path, encoding);

    if (!itemString) {
      throw noSuchIndexItemException(id);
    }

    return JSON.parse(itemString);
  },

  async deleteItem ({ id }: { id: string }): Promise<void> {
    const path = getPath(id);

    const itemString = await reactNativeFs.readFile(path, encoding);

    if (!itemString) {
      throw noSuchIndexItemException(id);
    }

    await reactNativeFs.unlink(path);
  },

  async getDelta ({ timestampSinceLastDelta }: { timestampSinceLastDelta: number }): Promise<IndexDelta[]> {
    const fileEntryList = await reactNativeFs.readDir(directory);
    const items: IndexDelta[] = [];

    for (const entry of fileEntryList) {
      if (!entry.isFile() || !entry.mtime || entry.mtime.getTime() <= timestampSinceLastDelta) {
        continue;
      }
      const itemString = await reactNativeFs.readFile(entry.path, encoding);
      const item = JSON.parse(itemString);
      const { id, timestamp } = item;

      items.push({ id, timestamp });
    }

    return items;
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
