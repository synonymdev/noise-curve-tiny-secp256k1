import test from 'ava'
import secpNative from 'noise-curve-secp'
import { secp256k1 } from '../src/index.js'

test('generate a keypair with a privkey', (t) => {
  const privKey = Buffer.from(
    '5a4f8a7485dc40f2ee5d0c9ab2b559b5601be31993dc9714739999214bf2fd6d',
    'hex'
  )

  const nativeKP = secpNative.generateKeyPair(privKey)
  const tinyKP = secp256k1.generateKeyPair(privKey)

  t.deepEqual(tinyKP.secretKey, privKey)
  t.deepEqual(
    tinyKP.publicKey.toString('hex'),
    '033fac7d8493971a496906727f72675b3bb8b1dd2bf244e15d2aa98a1f4f409fdb'
  )
  t.deepEqual(tinyKP, nativeKP)
})

test('generate a keypair without', (t) => {
  const tinyKP = secp256k1.generateKeyPair()
  const nativeKP = secpNative.generateKeyPair(tinyKP.secretKey)

  t.deepEqual(tinyKP, nativeKP)
})

test('throws an error on invalid privkey', (t) => {
  const nativeKP = secpNative.generateKeyPair()

  t.throws(() => secp256k1.generateKeyPair(nativeKP.publicKey), {
    message: 'Invalid privkey',
    instanceOf: Error
  })
})
