import { IndexDelta } from './indexDelta';
import { IndexItem } from './indexItems/indexItem';

interface IndexStore {
  setItem: ({ item }: { item: IndexItem }) => Promise<void>;
  getItem: ({ id }: { id: string }) => Promise<IndexItem>;
  deleteItem: ({ id }: { id: string }) => Promise<void>;
  getDelta: ({ timestampSinceLastDelta }: { timestampSinceLastDelta: number }) => Promise<IndexDelta[]>;
  deleteAllItems: () => Promise<void>;
}

const noSuchIndexItemException = (id: string): Error => new Error(`Index Item with id ${id} does not exist.`);

export { IndexStore, noSuchIndexItemException };
