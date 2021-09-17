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
const generateSeedKeyPair = (seed) =>
  generateKeyPair(createHash('sha256').update(seed).digest())

/**
 * Perform DH between `pk` and `lsk` and return the result.
 * @param {Buffer} pk Remote publicKey
 * @param {Buffer} lsk Local secretKey
 * @returns {Buffer}
 */
const dh = (pk, lsk) =>
  createHash('sha256')
    // Coercing `pk` to Buffer
    // Noise-handshake uses `buffer.subarray` on pk before passing it here.
    // In browsers `buffer.subarray` can return a Uint8Array that isn't an
    //  instance of `Buffer`.
    // In `pointMultiply`, an `isPoint(pk)` will be performed which verify
    //  `Buffer.isBuffer(pk)` which would return false and throws an error.
    .update(secp.pointMultiply(Buffer.from(pk), lsk))
    .digest()

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
