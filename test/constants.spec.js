import test from 'ava'
import { secp256k1 } from '../src/index.js'
import secp256k1Native from 'noise-curve-secp'

test('constants exports', (t) => {
  delete secp256k1.generateKeyPair
  delete secp256k1.generateSeedKeyPair
  delete secp256k1.dh

  t.deepEqual(
    { ...secp256k1 },
    {
      DHLEN: 32,
      PKLEN: 33,
      SKLEN: 32,
      ALG: 'secp256k1',
      name: 'secp256k1'
    }
  )

  delete secp256k1Native.generateKeyPair
  delete secp256k1Native.dh

  t.deepEqual({ ...secp256k1 }, { ...secp256k1Native })
})
