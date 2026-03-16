import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';

function publicKeyToAddress(publicKey: Uint8Array): string {
  const hash = keccak_256(publicKey.slice(1));
  const addressBytes = hash.slice(-20);
  return '0x' + Buffer.from(addressBytes).toString('hex');
}

function hashPersonalMessage(message: string): Uint8Array {
  const messageBytes = new TextEncoder().encode(message);
  const prefix = `\x19Ethereum Signed Message:\n${messageBytes.length}`;
  const prefixBytes = new TextEncoder().encode(prefix);
  const combined = new Uint8Array(prefixBytes.length + messageBytes.length);
  combined.set(prefixBytes);
  combined.set(messageBytes, prefixBytes.length);
  return keccak_256(combined);
}

export function privateKeyToAccount(privateKey?: Uint8Array) {
  const privKey = privateKey ?? secp256k1.utils.randomPrivateKey();
  const pubKey = secp256k1.getPublicKey(privKey, false);
  const address = publicKeyToAddress(pubKey);

  const signMessage = (message: string): string => {
    const hash = hashPersonalMessage(message);
    const sig = secp256k1.sign(hash, privKey);
    const r = sig.r.toString(16).padStart(64, '0');
    const s = sig.s.toString(16).padStart(64, '0');
    const v = (sig.recovery + 27).toString(16).padStart(2, '0');
    return '0x' + r + s + v;
  };

  return { address, signMessage };
}
