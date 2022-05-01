# vault

TBD

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
* Authenticity and integrity of metadata will be checked with the master hmac key, using HMAC.
* master encryption key and master hmac key will be wrapped with the password key, using aes-key-wrap.
* The password key will be derived, using scrypt.

## Installation
```bash
npm install wault
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
TBD

## Usage
TBD

### API
TBD
