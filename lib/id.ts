import { v4 as uuidV4 } from 'uuid';

const createId = function (): string {
  return uuidV4();
};

export { createId };
