import { assert } from 'assertthat';
import { createScryptHash } from '../../lib/crypto/scrypt';

// We are using the test vectors provided by scrypt-js (Repository; renamed props, first 3 vectors)
// https://github.com/ricmoo/scrypt-js/blob/master/test/test-vectors.json
const testVectors = [
  {
    data: '',
    salt: '',
    cpuFactor: 16,
    parallism: 1,
    memoryFactor: 1,
    keyLength: 64,
    derivedKeyExpected: '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906'
  },
  {
    data: '70617373776f7264',
    salt: '4e61436c',
    cpuFactor: 1_024,
    parallism: 16,
    memoryFactor: 8,
    keyLength: 64,
    derivedKeyExpected: 'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640'
  },
  {
    data: '706c656173656c65746d65696e',
    salt: '536f6469756d43686c6f72696465',
    cpuFactor: 16_384,
    parallism: 1,
    memoryFactor: 8,
    keyLength: 64,
    derivedKeyExpected: '7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887'
  }
];

const lengthMapping = [
  {
    givenLength: 9,
    resultingLength: 9
  },
  {
    givenLength: 8,
    resultingLength: 8
  },
  {
    givenLength: 7,
    resultingLength: 8
  },
  {
    givenLength: 1,
    resultingLength: 8
  },
  {
    givenLength: 0,
    resultingLength: 8
  },
  {
    givenLength: -1,
    resultingLength: 8
  },
  {
    givenLength: -9,
    resultingLength: 8
  }
];

describe('Scrypt', (): void => {
  describe('normal cases', (): void => {
    for (const [ index, vector ] of testVectors.entries()) {
      test(`returns correct scrypt-key, using test vector ${index + 1}`, async (): Promise<void> => {
        const { data, salt, cpuFactor, memoryFactor, parallism, keyLength, derivedKeyExpected } = vector;
        const dataBuffer = Buffer.from(data, 'hex');
        const saltBuffer = Buffer.from(salt, 'hex');
        const derivedKeyExpectedBuffer = Buffer.from(derivedKeyExpected, 'hex');

        const derivedKey = await createScryptHash({ data: dataBuffer, salt: saltBuffer, cpuFactor, memoryFactor, parallism, keyLength });

        assert.that(derivedKey).is.equalTo(derivedKeyExpectedBuffer);
      });
    }
  });

  describe('error cases (desired key length too small)', (): void => {
    for (const { givenLength, resultingLength } of lengthMapping) {
      test(`returns ${resultingLength} byte scrypt-key on desired key length ${givenLength}`, async (): Promise<void> => {
        const vector = { ...testVectors[0], keyLength: givenLength };
        const { data, salt, cpuFactor, memoryFactor, parallism, keyLength } = vector;
        const dataBuffer = Buffer.from(data, 'hex');
        const saltBuffer = Buffer.from(salt, 'hex');

        const derivedKey = await createScryptHash({ data: dataBuffer, salt: saltBuffer, cpuFactor, memoryFactor, parallism, keyLength });

        assert.that(derivedKey.length).is.equalTo(resultingLength);
      });
    }
  });
});
