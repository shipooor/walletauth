import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import type { Verifier } from '../types.js';

// EVM personal_sign prefix: "\x19Ethereum Signed Message:\n" + message length
function hashPersonalMessage(message: string): Uint8Array {
  const messageBytes = new TextEncoder().encode(message);
  const prefix = `\x19Ethereum Signed Message:\n${messageBytes.length}`;
  const prefixBytes = new TextEncoder().encode(prefix);
  const combined = new Uint8Array(prefixBytes.length + messageBytes.length);
  combined.set(prefixBytes);
  combined.set(messageBytes, prefixBytes.length);
  return keccak_256(combined);
}

function publicKeyToAddress(publicKey: Uint8Array): string {
  // Remove the 0x04 prefix (uncompressed key marker), hash, take last 20 bytes
  const hash = keccak_256(publicKey.slice(1));
  const addressBytes = hash.slice(-20);
  return '0x' + Buffer.from(addressBytes).toString('hex');
}

/**
 * EVM signature verifier (Ethereum, Arbitrum, Base, Polygon, etc.).
 *
 * Verifies `personal_sign` (EIP-191) signatures using secp256k1 ecrecover.
 * Accepts signatures with or without `0x` prefix. Address comparison is case-insensitive.
 *
 * @param address - EVM address (`0x...`, 42 chars).
 * @param message - The nonce string that was signed.
 * @param signature - Hex signature: `0x` + r(32B) + s(32B) + v(1B) = 132 chars.
 */
export const evm: Verifier = (address, message, signature) => {
  try {
    const hash = hashPersonalMessage(message);

    // Parse signature: 0x + r(32 bytes) + s(32 bytes) + v(1 byte) = 0x + 130 hex chars
    const sig = signature.startsWith('0x') ? signature.slice(2) : signature;
    if (sig.length !== 130) return false;

    const r = BigInt('0x' + sig.slice(0, 64));
    const s = BigInt('0x' + sig.slice(64, 128));
    const v = parseInt(sig.slice(128, 130), 16);

    // v is 27 or 28 (legacy) or 0 or 1 (raw recovery id)
    const recovery = v >= 27 ? v - 27 : v;
    if (recovery !== 0 && recovery !== 1) return false;

    const sigObj = new secp256k1.Signature(r, s, recovery);
    const recovered = sigObj.recoverPublicKey(hash);
    const recoveredAddress = publicKeyToAddress(recovered.toRawBytes(false));

    return recoveredAddress.toLowerCase() === address.toLowerCase();
  } catch {
    return false;
  }
};
