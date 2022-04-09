const SHA256 = require('crypto-js/sha256');
const uuidV1 = require('uuid');
const EC = require('elliptic').ec;
// Elliptic has many curve cypto and we can can ec class with the one we want to use by passing it as string.
// secp256k1 is used by bitcoin. Generated gen-key pair.
const ec = new EC('secp256k1');

class ChainUtil {
  static genKeyPair() {
    return ec.genKeyPair();
  }

  static id() {
    return uuidV1.v1();
  }

  static hash(data) {
    return SHA256(JSON.stringify(data)).toString();
  }

  static verifySignature(publicKey, signature, dataHash) {
    return ec.keyFromPublic(publicKey, 'hex').verify(dataHash, signature);
  }
}

module.exports = ChainUtil;