import { Buffer } from 'buffer';
import { getRandomBuffer } from '../core/random';
import { aes256gcmDecrypt, aes256gcmEncrypt } from '../core/aes256gcm';

const unauthenticExceptionCommonSentence = 'Most likely this means that an attacker has tampered with your content.';
const unauthenticHeaderException = new Error(`Unauthentic header. ${unauthenticExceptionCommonSentence}`);
const unauthenticChunkException = (chunk: number): Error => new Error(`Unauthentic chunk ${chunk}. ${unauthenticExceptionCommonSentence}`);

// 4 KiB chunkSize
const chunkSize = 4 * 1_024;

const split = (input: Buffer, partSize: number): Buffer[] => {
  const output: Buffer[] = [];

  for (let i = 0; i < input.length / partSize; i++) {
    const begin = partSize * i;
    const end = Math.min(partSize * (i + 1), input.length);

    output[i] = input.slice(begin, end);
  }

  return output;
};

const splitChunks = (input: Buffer): Buffer[] => split(input, chunkSize);

const splitEncryptedChunks = (input: Buffer): Buffer[] => split(input, chunkSize + 16 + 12);

const splitEncrypted = (input: Buffer): Buffer[] => {
  const headerNonce = input.slice(0, 12);
  const encryptedContentKey = input.slice(12, 60);
  const encryptedChunks = splitEncryptedChunks(input.slice(60, input.length));

  return [ headerNonce, encryptedContentKey, ...encryptedChunks ];
};

const encryptChunk = async (chunk: Buffer, contentKey: Buffer, contentId: string, chunkIndex: number): Promise<Buffer> => {
  const chunkNonce = await getRandomBuffer({ length: 12 });
  const associatedString = `${contentId}__${chunkIndex}`;
  const associated = Buffer.from(associatedString, 'utf8');
  const encryptedChunk = aes256gcmEncrypt({ plain: chunk, key: contentKey, iv: chunkNonce, associated });

  return Buffer.concat([ chunkNonce, encryptedChunk ]);
};

const decryptChunk = (encryptedChunk: Buffer, contentKey: Buffer, contentId: string, chunkIndex: number): Buffer => {
  const chunkNonce = encryptedChunk.slice(0, 12);
  const encryptedContent = encryptedChunk.slice(12, encryptedChunk.length);
  const associatedString = `${contentId}__${chunkIndex}`;
  const associated = Buffer.from(associatedString, 'utf8');

  try {
    return aes256gcmDecrypt({ cipherAndTag: encryptedContent, key: contentKey, iv: chunkNonce, associated });
  } catch {
    throw unauthenticChunkException(chunkIndex + 1);
  }
};

const encryptContent = async ({ content, masterKey, contentId }: {
  content: Buffer; masterKey: Buffer; contentId: string; }): Promise<Buffer> => {
  const chunkCount = Math.ceil(content.length / chunkSize);
  const headerNonce = await getRandomBuffer({ length: 12 });
  const contentKey = await getRandomBuffer({ length: 32 });
  const associatedString = `${contentId}_${chunkCount}`;
  const associated = Buffer.from(associatedString, 'utf8');
  const encryptedContentKey = aes256gcmEncrypt({ plain: contentKey, key: masterKey, iv: headerNonce, associated });

  const chunks = splitChunks(content);
  const encryptedChunks: Buffer[] = [];

  for (const [ chunkIndex, chunk ] of chunks.entries()) {
    const encryptedChunk = await encryptChunk(chunk, contentKey, contentId, chunkIndex);

    encryptedChunks.push(encryptedChunk);
  }

  return Buffer.concat([ headerNonce, encryptedContentKey, ...encryptedChunks ]);
};

const decryptContent = ({ encryptedContent, masterKey, contentId }: {
  encryptedContent: Buffer; masterKey: Buffer; contentId: string; }): Buffer => {
  const [ headerNonce, encryptedContentKey, ...encryptedChunks ] = splitEncrypted(encryptedContent);
  const associatedString = `${contentId}_${encryptedChunks.length}`;
  const associated = Buffer.from(associatedString, 'utf8');
  let contentKey: Buffer;

  try {
    contentKey = aes256gcmDecrypt({ cipherAndTag: encryptedContentKey, key: masterKey, iv: headerNonce, associated });
  } catch {
    throw unauthenticHeaderException;
  }

  const chunks: Buffer[] = [];

  for (const [ chunkIndex, encryptedChunk ] of encryptedChunks.entries()) {
    const chunk = decryptChunk(encryptedChunk, contentKey, contentId, chunkIndex);

    chunks.push(chunk);
  }

  return Buffer.concat(chunks);
};

export { chunkSize, encryptContent, decryptContent, unauthenticChunkException, unauthenticHeaderException };
