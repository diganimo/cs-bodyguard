const noSuchIndexItemException = function ({ id }: { id: string }): Error {
  return new Error(`Error: Index item with id ${id} does not exist`);
};

const unauthenticException = function (): Error {
  return new Error('Error: Unauthentic Object detected');
};

const invalidCryptoInputLengthException = function ({ input, lengthGiven, lengthExpected }: {
  input: string;
  lengthGiven: number;
  lengthExpected: number;
}): Error {
  return new Error(`Error: invalid crypto input. ${input} was expected to be ${lengthExpected} bytes long, but length is ${lengthGiven}.`);
};

const tooShortCryptoInputException = function ({ input, lengthGiven, lengthAtLeastExpected }: {
  input: string;
  lengthGiven: number;
  lengthAtLeastExpected: number;
}): Error {
  return new Error(`Error: invalid crypto input. ${input} was expected to be at least ${lengthAtLeastExpected} bytes long, but length is ${lengthGiven}.`);
};

export { noSuchIndexItemException, unauthenticException, invalidCryptoInputLengthException, tooShortCryptoInputException };
