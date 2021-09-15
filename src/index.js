import { createHash, randomBytes } from 'crypto'
import * as secp from 'tiny-secp256k1'

/**
 * @typedef {{
 *  publicKey: Buffer;
 *  secretKey: Buffer;
 * }} KeyPair
 */

const DHLEN = 32
const PKLEN = 33
const SKLEN = 32

/**
 * Generate a new keypair, optionally pass in a preexisting `privKey`.
 * @param {Buffer} [privKey] Optional pregenerated private key
 * @returns {KeyPair}
 */
const generateKeyPair = (privKey) => {
  if (privKey && !secp.isPrivate(privKey)) throw new Error('Invalid privkey')

  const secretKey = privKey || randomBytes(SKLEN)

  return {
    secretKey,
    publicKey: secp.pointFromScalar(secretKey, true)
  }
}

/**
 * Generate a new keypair from `seed`.
 * @param {string | Buffer} seed
 * @returns {KeyPair}
 */
function generateSeedKeyPair (seed) {
  const secretKey = createHash('sha256').update(seed).digest()

  return generateKeyPair(secretKey)
}

/**
 * Perform DH between `pk` and `lsk` and return the result.
 * @param {Buffer} pk Remote publicKey
 * @param {Buffer} lsk Local secretKey
 * @returns {Buffer}
 */
function dh (pk, lsk) {
  if (!secp.isPoint(pk)) throw new Error('Invalid remote publicKey')
  if (!secp.isPrivate(lsk)) throw new Error('Invalid local secretKey')

  return createHash('sha256').update(secp.pointMultiply(pk, lsk)).digest()
}

/**
 * @type {{
 *  DHLEN: number;
 *  PKLEN: number;
 *  SKLEN: number;
 *  ALG: string;
 *  name: string;
 *  generateKeyPair: (privKey?: Buffer) => KeyPair
 *  generateSeedKeyPair: (seed: string | Buffer) => KeyPair
 *  dh: (pk: Buffer, lsk: Buffer) => Buffer
 * }}
 */
export const secp256k1 = {
  DHLEN,
  PKLEN,
  SKLEN,
  ALG: 'secp256k1',
  name: 'secp256k1',
  generateKeyPair,
  generateSeedKeyPair,
  dh
}
