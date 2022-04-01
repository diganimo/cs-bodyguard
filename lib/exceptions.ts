const noSuchIndexItemException = function ({ id }: { id: string }): Error {
  return new Error(`Error: Index item with id ${id} does not exist`);
};

export { noSuchIndexItemException };
