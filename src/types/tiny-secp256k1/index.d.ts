declare module 'tiny-secp256k1' {
  function isPrivate(Buffer): boolean;
  function isPoint(Buffer): boolean;
  function pointMultiply(point: Buffer, tweak: Buffer): Buffer;
  function pointFromScalar(secretKey: Buffer, b: boolean);
  Buffer;
}
