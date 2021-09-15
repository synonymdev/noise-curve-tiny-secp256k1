import test from 'ava'
import { secp256k1 } from '../src/index.js'

test('generate a keypair from seed', (t) => {
  t.deepEqual(secp256k1.generateSeedKeyPair('hello world!'), {
    publicKey: Buffer.from(
      '0236b72e9e1afa1235049717838e50560b49e9c3982eeff1128eaae564fb064a70',
      'hex'
    ),
    secretKey: Buffer.from(
      '7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9',
      'hex'
    )
  })

  t.deepEqual(
    secp256k1.generateSeedKeyPair(Buffer.from('hello world!')),
    secp256k1.generateSeedKeyPair('hello world!')
  )
})
