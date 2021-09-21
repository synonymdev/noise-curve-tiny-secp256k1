# noise-curve-secp256k1

Js `secp256k1` elliptic curve module for [`noise-handshake`](https://github.com/chm-diederichs/noise-handshake)

## Usage

```js
import { secp256k1 } from 'noise-curve-tiny-secp';
import Noise from 'noise-handshake';

const handshake = new Noise(pattern, initiator, staticKeyPair, {
  curve: secp256k1,
});
```

## API

#### constants

`DHLEN` = 32
`PKLEN` = 64
`SKLEN` = 32
`ALG` = 'secp256k1'

#### `generateKeyPair([privKey])`

Generate a new keypair, optionally pass in a preexisting `privKey`. Return value is of the form:

```
{
  publicKey,
  secretKey
}
```

#### `generateSeedKeyPair(seed)`

Generate a new keypair from a `seed`. Return value is of the form:

```
{
  publicKey,
  secretKey
}
```

#### `dh(pk, lsk)`

Perform DH between `pk` and `lsk` and return the result.
