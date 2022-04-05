import { createHmac } from '../core/hmac';
import { IndexItem } from '../../index/indexItems/indexItem';

const unauthenticException = (id: string): Error => new Error(`Index Item with id ${id} is not authentic.`);

const updateIndexItemHmac = ({ indexItem, key }: { indexItem: IndexItem; key: Buffer }): void => {
  // eslint-disable-next-line prefer-const
  let { hmac, ...dataObject } = indexItem;
  const data = JSON.stringify(dataObject);

  hmac = createHmac({ data, key });

  // eslint-disable-next-line no-param-reassign
  indexItem.hmac = hmac;
};

const checkIndexItemIntegrity = ({ indexItem, key }: { indexItem: IndexItem; key: Buffer }): void => {
  const { hmac, ...dataObject } = indexItem;
  const data = JSON.stringify(dataObject);

  const actualHmac = createHmac({ data, key });

  if (actualHmac !== hmac) {
    throw unauthenticException(dataObject.id);
  }
};

export { checkIndexItemIntegrity, updateIndexItemHmac, unauthenticException };
