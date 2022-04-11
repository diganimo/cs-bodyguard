import { assert } from 'assertthat';
import { Buffer } from 'buffer';
import forge from 'node-forge';
import { getRandomBuffer } from '../../../lib/crypto/core/random';
import { chunkSize, decryptContent, encryptContent, unauthenticChunkException, unauthenticHeaderException }
  from '../../../lib/crypto/tasks/contentEncryption';

const mockedRandomStrings = {
  headerNonce: 'header-nonce',
  contentKey: 'contentKey-contentKey-contentKey',
  encKey: 'encKey-encKey-encKey-encKey.....',
  chunk1Nonce: 'chunk1-nonce',
  chunk2Nonce: 'chunk2-nonce',
  chunk3Nonce: 'chunk3-nonce'
};

// eslint-disable-next-line no-undef
let randomMock: jest.SpyInstance<string, [count: number]>;

const masterKey = Buffer.from('masterKey-masterKey-masterKey...', 'utf8');

const plaintexts = {
  tenChars: 'plaintext!',
  sixKiloBytes: '0'.repeat(chunkSize * 2.5),
  empty: ''
};

// Derived from previously dynamic tests before they got refactored to be static
const ecpectedEncryptedContentForTenCharsPlaintext = 'aGVhZGVyLW5vbmNl88uqopy4kogbf8grWiMPl2iggozs2vRvUGWA95GihwLZLnG' +
  'j52ImnRUvJo2yj8LKY2h1bmsxLW5vbmNl3KRlhmwnHbGpyzpqOBwkAPm08tqTKYUvhe8=';
const expectedEncryptedContentKeyForSixKiloBytesPlaintext =
  '88uqopy4kogbf8grWiMPl2iggozs2vRvUGWA95GihwLpsdX4nc46YRISUFPOoG5v';

const split = (input: Buffer): Buffer[] => {
  const partSize = 8;
  const output: Buffer[] = [];

  for (let i = 0; i < input.length / partSize; i++) {
    const begin = partSize * i;
    const end = Math.min(partSize * (i + 1), input.length);

    output[i] = input.slice(begin, end);
  }

  return output;
};

const tamperBit = (buffer: Buffer, bufferBitIndex: number): Buffer => {
  /* eslint-disable no-bitwise */
  const blockIndex = Math.floor(bufferBitIndex / 64);
  const blockBitIndex = bufferBitIndex % 64;
  const splitted = split(buffer);
  const originBuffer = splitted[blockIndex];
  const originBigint = originBuffer.readBigUInt64BE();
  const tamperer = BigInt(1 << (63 - blockBitIndex));
  const tampered = originBigint ^ tamperer;

  originBuffer.writeBigUint64BE(tampered);
  /* eslint-enable no-bitwise */

  return Buffer.concat(splitted);
};

const tamperHeader = (buffer: Buffer): Buffer => tamperBit(buffer, (12 * 8) + 1);
const tamperChunk1 = (buffer: Buffer): Buffer => tamperBit(buffer, (72 * 8) + 1);
const tamperChunk2 = (buffer: Buffer): Buffer => tamperBit(buffer, (4_196 * 8) + 1);

describe('Content Encryption', (): void => {
  beforeEach(async (): Promise<void> => {
    // eslint-disable-next-line no-undef
    randomMock = jest.spyOn(forge.random, 'getBytesSync');
  });

  afterEach(async (): Promise<void> => {
    randomMock.mockRestore();
  });

  describe('normal cases', (): void => {
    test('returns exact expected ciphertext on tenChars plaintext.', async (): Promise<void> => {
      randomMock.mockReturnValueOnce(mockedRandomStrings.headerNonce);
      randomMock.mockReturnValueOnce(mockedRandomStrings.contentKey);
      randomMock.mockReturnValueOnce(mockedRandomStrings.chunk1Nonce);

      const encryptedContent = await encryptContent({ content: Buffer.from(plaintexts.tenChars, 'utf8'), masterKey, contentId: 'plain1' });

      assert.that(encryptedContent).is.equalTo(Buffer.from(ecpectedEncryptedContentForTenCharsPlaintext, 'base64'));
    });

    test('returns ciphertext with correct length, nonces, and encrypted contentKey on sixKiloBytes plaintext.', async (): Promise<void> => {
      randomMock.mockReturnValueOnce(mockedRandomStrings.headerNonce);
      randomMock.mockReturnValueOnce(mockedRandomStrings.contentKey);
      randomMock.mockReturnValueOnce(mockedRandomStrings.chunk1Nonce);
      randomMock.mockReturnValueOnce(mockedRandomStrings.chunk2Nonce);
      randomMock.mockReturnValueOnce(mockedRandomStrings.chunk3Nonce);

      const encryptedContent =
        await encryptContent({ content: Buffer.from(plaintexts.sixKiloBytes, 'utf8'), masterKey, contentId: 'plain2' });

      assert.that(encryptedContent.length).is.equalTo(10_384);
      assert.that(encryptedContent.slice(0, 12)).is.equalTo(Buffer.from(mockedRandomStrings.headerNonce, 'binary'));
      assert.that(encryptedContent.slice(12, 60)).is.equalTo(Buffer.from(expectedEncryptedContentKeyForSixKiloBytesPlaintext, 'base64'));
      assert.that(encryptedContent.slice(60, 72)).is.equalTo(Buffer.from(mockedRandomStrings.chunk1Nonce, 'binary'));
      assert.that(encryptedContent.slice(4_184, 4_196)).is.equalTo(Buffer.from(mockedRandomStrings.chunk2Nonce, 'binary'));
      assert.that(encryptedContent.slice(8_308, 8_320)).is.equalTo(Buffer.from(mockedRandomStrings.chunk3Nonce, 'binary'));
    });

    test('returns ciphertext with correct length on empty plaintext.', async (): Promise<void> => {
      randomMock.mockReturnValueOnce(mockedRandomStrings.headerNonce);
      randomMock.mockReturnValueOnce(mockedRandomStrings.contentKey);
      randomMock.mockReturnValueOnce(mockedRandomStrings.chunk1Nonce);

      const encryptedContent =
        await encryptContent({ content: Buffer.from(plaintexts.empty, 'utf8'), masterKey, contentId: 'plain3' });

      assert.that(encryptedContent.length).is.equalTo(60);
    });

    test('decrypts ciphertext of tenChars plaintext.', async (): Promise<void> => {
      const decrypted =
        decryptContent({ encryptedContent: Buffer.from(ecpectedEncryptedContentForTenCharsPlaintext, 'base64'), masterKey, contentId: 'plain1' });

      assert.that(decrypted).is.equalTo(Buffer.from(plaintexts.tenChars, 'utf8'));
    });

    test('encrypts and decrypts back, using random values, plaintext of 4.232 bytes.', async (): Promise<void> => {
      const randomMasterKey = await getRandomBuffer({ length: 32 });
      const content = await getRandomBuffer({ length: 4_232 });

      const encryptedContent = await encryptContent({ content, masterKey: randomMasterKey, contentId: 'id' });
      const decryptedContent = decryptContent({ encryptedContent, masterKey: randomMasterKey, contentId: 'id' });

      assert.that(decryptedContent).is.equalTo(content);
    });

    test('encrypts and decrypts back, using random values, empty plaintext.', async (): Promise<void> => {
      const randomMasterKey = await getRandomBuffer({ length: 32 });
      const content = Buffer.from('', 'binary');

      const encryptedContent = await encryptContent({ content, masterKey: randomMasterKey, contentId: 'id' });
      const decryptedContent = decryptContent({ encryptedContent, masterKey: randomMasterKey, contentId: 'id' });

      assert.that(decryptedContent).is.equalTo(content);
    });
  });

  describe('error cases', (): void => {
    test('throws unauthenticHeader exception on swapped contents.', async (): Promise<void> => {
      const encryptedContent = Buffer.from(ecpectedEncryptedContentForTenCharsPlaintext, 'base64');
      let exception = new Error('function did not throw an exception!');

      try {
        decryptContent({ encryptedContent, masterKey, contentId: 'wronId' });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception.message).is.equalTo(unauthenticHeaderException.message);
    });

    test('throws unauthenticHeader exception on extendedContent.', async (): Promise<void> => {
      const randomMasterKey = await getRandomBuffer({ length: 32 });
      const content = await getRandomBuffer({ length: chunkSize });
      const encryptedContent = await encryptContent({ content, masterKey: randomMasterKey, contentId: 'id' });
      let exception = new Error('function did not throw an exception!');
      const extension = encryptedContent.slice(60, encryptedContent.length);
      const extended = Buffer.concat([ encryptedContent, extension ]);

      try {
        decryptContent({ encryptedContent: extended, masterKey: randomMasterKey, contentId: 'id' });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception.message).is.equalTo(unauthenticHeaderException.message);
    });

    test('throws unauthenticHeader exception if encryptedKey was tampared with.', async (): Promise<void> => {
      let encryptedContent = Buffer.from(ecpectedEncryptedContentForTenCharsPlaintext, 'base64');
      let exception = new Error('function did not throw an exception!');

      // Tampers with the second bit of the first ciphertext byte
      encryptedContent = tamperHeader(encryptedContent);

      try {
        decryptContent({ encryptedContent, masterKey, contentId: 'id' });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception.message).is.equalTo(unauthenticHeaderException.message);
    });

    test('throws unauthenticChunk exception on swapped chunks between contents.', async (): Promise<void> => {
      const randomMasterKey = await getRandomBuffer({ length: 32 });
      const content1 = await getRandomBuffer({ length: 10 });
      const content2 = await getRandomBuffer({ length: 10 });
      const encryptedContent1 = await encryptContent({ content: content1, masterKey: randomMasterKey, contentId: 'id1' });
      const encryptedContent2 = await encryptContent({ content: content2, masterKey: randomMasterKey, contentId: 'id2' });
      const header = encryptedContent1.slice(0, 60);
      const chunk2 = encryptedContent2.slice(60, encryptedContent2.length);
      const swappedEncryptedContent = Buffer.concat([ header, chunk2 ]);
      let exception = new Error('function did not throw an exception!');

      try {
        decryptContent({ encryptedContent: swappedEncryptedContent, masterKey: randomMasterKey, contentId: 'id1' });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception.message).is.equalTo(unauthenticChunkException(1).message);
    });

    test('throws unauthenticChunk exception on intra-content swapped chunks.', async (): Promise<void> => {
      const randomMasterKey = await getRandomBuffer({ length: 32 });
      const content = await getRandomBuffer({ length: 2 * chunkSize });
      const encryptedContent = await encryptContent({ content, masterKey: randomMasterKey, contentId: 'id' });
      const header = encryptedContent.slice(0, 60);
      const chunk1 = encryptedContent.slice(60, 60 + chunkSize + 28);
      const chunk2 = encryptedContent.slice(60 + chunkSize + 28, encryptedContent.length);
      const swappedEncryptedContent = Buffer.concat([ header, chunk2, chunk1 ]);
      let exception = new Error('function did not throw an exception!');

      try {
        decryptContent({ encryptedContent: swappedEncryptedContent, masterKey: randomMasterKey, contentId: 'id' });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception.message).is.equalTo(unauthenticChunkException(1).message);
    });

    test('throws unauthenticChunk1 exception if chunk1 was tampared with.', async (): Promise<void> => {
      const randomMasterKey = await getRandomBuffer({ length: 32 });
      const content = await getRandomBuffer({ length: 2 * chunkSize });
      let encryptedContent = await encryptContent({ content, masterKey: randomMasterKey, contentId: 'id' });
      let exception = new Error('function did not throw an exception!');

      // Tampers with the second bit of the first byte of chunk 1
      encryptedContent = tamperChunk1(encryptedContent);

      try {
        decryptContent({ encryptedContent, masterKey: randomMasterKey, contentId: 'id' });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception.message).is.equalTo(unauthenticChunkException(1).message);
    });

    test('throws unauthenticChunk2 exception if chunk2 was tampared with.', async (): Promise<void> => {
      const randomMasterKey = await getRandomBuffer({ length: 32 });
      const content = await getRandomBuffer({ length: 2 * chunkSize });
      let encryptedContent = await encryptContent({ content, masterKey: randomMasterKey, contentId: 'id' });
      let exception = new Error('function did not throw an exception!');

      // Tampers with the second bit of the first byte of chunk 2
      encryptedContent = tamperChunk2(encryptedContent);

      try {
        decryptContent({ encryptedContent, masterKey: randomMasterKey, contentId: 'id' });
      } catch (ex: unknown) {
        exception = ex as Error;
      }

      assert.that(exception).is.not.null();
      assert.that(exception.message).is.equalTo(unauthenticChunkException(2).message);
    });
  });
});
