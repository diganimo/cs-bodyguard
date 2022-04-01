import { IndexItem } from './indexItems/indexItem';

interface IndexStore {
  setItem: ({ item }: { item: IndexItem }) => Promise<void>;
  getItem: ({ id }: { id: string }) => Promise<IndexItem>;
  deleteItem: ({ id }: { id: string }) => Promise<void>;
  getAllRecentItems: ({ timestamp }: { timestamp: number }) => Promise<IndexItem[]>;
  countAllRecentItems: ({ timestamp }: { timestamp: number }) => Promise<number>;
  deleteAllItems: () => Promise<void>;
}

export { IndexStore };
