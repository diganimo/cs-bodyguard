# diamory-common
Common lib for [diamory](https://diamory.com/). \
It's very specific, but if it suites your needs, feel free to use it for your projects, \
fulfilling the [license conditions](LICENSE.txt).

### Included algorithms/protocols/schemes
* AES-256-GCM
* AES-KEY-WRAP
* SCRYPT pbkdf
* HMAC

## Security Architecture / Crypto Concept
[Full Security Architecture documentation](https://TBD.TBD (to be defined))

For short:
* Contents will be encrypted with random content key, using AES-256 in GCM mode of operation.
* Content keys will be encrypted with the master encryption key, using AES-256 in GCM mode of operation.
* Authenticity and integrity of index will be checked with the master hmac key, using HMAC.
* master encryption key and master hmac key will be wrapped with the password key, using aes-key-wrap.
* The password key will be derived, using scrypt.

## Installation
```bash
npm install diamory-common
```

## QA
For code analyses and automatic tests, run:
```bash
npm run qa
```

### Tests only
For automatic tests only, run:
```bash
npm run test
```

## Build
Build with:
```bash
npm run build
```

## Import
Note: replace ```{...}``` with the destructure syntax for the parts you want to import (```{init, unlock}``` for example).

* For project whichs targets the browser:
  ```js
  import {...} from 'diamory-common/browser';
  ```
* For project whichs targets mobile apps, using react-native:
  ```js
  import {...} from 'diamory-common/native';
  ```

## Usage
The code examples assume mobile app as target. Just change ```/native``` to ```/browser``` to use for for apps targeting browsers.

### API
TBD