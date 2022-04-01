const isFile = (): boolean => true;

interface MockedFileEntry {
  path: string;
  contents: string;
  encoding: string;
  mtime: Date;
  isFile: () => boolean;
}

const mockedDirectory: MockedFileEntry[] = [];

const testDir = '/test/directory';

export default {

  DocumentDirectoryPath: testDir,

  async writeFile (filePath: string, value: string, encoding: string): Promise<void> {
    const foundEntry = mockedDirectory.find((entry): boolean => entry.path === filePath && entry.encoding === encoding);
    const date = new Date();

    date.setTime(JSON.parse(value).timestamp);

    const entry = {
      path: filePath,
      contents: value,
      encoding,
      mtime: date,
      isFile
    };

    if (foundEntry) {
      foundEntry.contents = value;
      foundEntry.mtime = new Date();
    } else {
      mockedDirectory.push(entry);
    }
  },

  async readFile (filePath: string, encoding: string): Promise<string> {
    const foundEntry = mockedDirectory.find((entry): boolean => entry.path === filePath && entry.encoding === encoding);

    return foundEntry?.contents ?? '';
  },

  async unlink (filePath: string): Promise<void> {
    const foundEntry = mockedDirectory.find((entry): boolean => entry.path === filePath);

    if (!foundEntry) {
      return;
    }

    const index = mockedDirectory.indexOf(foundEntry);

    mockedDirectory.splice(index, 1);
  },

  // //eslint-disable-next-line @typescript-eslint/no-unused-vars
  async readDir (dirPath: string): Promise<MockedFileEntry[]> {
    return dirPath === testDir ? [ ...mockedDirectory ] : [];
  },

  clear (): void {
    mockedDirectory.splice(0);
  }
};
