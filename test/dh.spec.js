import test from 'ava'
import secpNative from 'noise-curve-secp'
import { secp256k1 } from '../src/index.js'

test('dh', (t) => {
  const localPrivKey = Buffer.from(
    '5a4f8a7485dc40f2ee5d0c9ab2b559b5601be31993dc9714739999214bf2fd6d',
    'hex'
  )

  const remotePrivKey = Buffer.from(
    'dfee58a7ec0cfa946acd2bdc5cbd975bbe817f804a67953c2b67085f8e7ff356',
    'hex'
  )

  const A = secp256k1.generateKeyPair(localPrivKey)
  const B = secp256k1.generateKeyPair(remotePrivKey)

  const output = secpNative.dh(B.publicKey, A.secretKey)

  t.deepEqual(output, secpNative.dh(A.publicKey, B.secretKey))

  t.deepEqual(
    secp256k1.dh(B.publicKey, A.secretKey),
    secp256k1.dh(A.publicKey, B.secretKey)
  )

  t.deepEqual(secp256k1.dh(A.publicKey, B.secretKey), output)
})

test('throw error on invalid arguments', (t) => {
  const A = secp256k1.generateKeyPair()
  t.throws(() => secp256k1.dh(A.secretKey, A.secretKey), {
    message: 'Expected Point',
    instanceOf: Error
  })

  t.throws(() => secp256k1.dh(A.publicKey, A.publicKey), {
    message: 'Expected Tweak',
    instanceOf: Error
  })
})
