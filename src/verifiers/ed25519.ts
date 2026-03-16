import { createPublicKey, verify } from 'node:crypto';
import type { Verifier } from '../types.js';

// Fixed DER prefix for Ed25519 SPKI public keys (12 bytes)
const ED25519_DER_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function decodeBase58(input: string): Buffer {
  const bytes: number[] = [];
  for (const char of input) {
    const idx = BASE58_ALPHABET.indexOf(char);
    if (idx === -1) throw new Error('Invalid base58 character');
    let carry = idx;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  bytes.reverse();
  // Leading '1's in base58 = leading zero bytes
  let leadingZeros = 0;
  for (const char of input) {
    if (char !== '1') break;
    leadingZeros++;
  }
  const result = new Uint8Array(leadingZeros + bytes.length);
  // First leadingZeros bytes are already 0, copy computed bytes after
  result.set(bytes, leadingZeros);
  return Buffer.from(result);
}

function parsePublicKey(address: string): Buffer | null {
  try {
    // Hex-encoded 32-byte key (64 hex chars)
    if (/^[0-9a-fA-F]{64}$/.test(address)) {
      return Buffer.from(address, 'hex');
    }
    // Base58-encoded (Solana addresses: 32-44 chars from base58 alphabet)
    if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address)) {
      const decoded = decodeBase58(address);
      if (decoded.length === 32) return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Ed25519 signature verifier (Solana, raw ed25519 keypairs).
 *
 * Accepts addresses as base58 (Solana, 32-44 chars) or hex (64 chars).
 * Accepts signatures as hex (128 chars), base58 (Solana convention), or base64.
 * Uses Node.js built-in `crypto` — zero external dependencies.
 *
 * @param address - Public key as base58 (Solana) or hex string.
 * @param message - The nonce string that was signed.
 * @param signature - 64-byte signature in hex, base58, or base64 encoding.
 */
export const ed25519: Verifier = (address, message, signature) => {
  try {
    const publicKeyRaw = parsePublicKey(address);
    if (!publicKeyRaw || publicKeyRaw.length !== 32) return false;

    // Signature: hex (128 chars), base58 (Solana convention), or base64
    let sigBuffer: Buffer;
    if (/^[0-9a-fA-F]{128}$/.test(signature)) {
      sigBuffer = Buffer.from(signature, 'hex');
    } else if (/^[1-9A-HJ-NP-Za-km-z]{1,90}$/.test(signature)) {
      // Could be base58 — decode and validate length, fall back to base64
      const decoded = decodeBase58(signature);
      if (decoded.length === 64) {
        sigBuffer = decoded;
      } else {
        sigBuffer = Buffer.from(signature, 'base64');
      }
    } else {
      sigBuffer = Buffer.from(signature, 'base64');
    }
    if (sigBuffer.length !== 64) return false;

    // Wrap raw public key in DER/SPKI format for Node.js crypto
    const derKey = Buffer.concat([ED25519_DER_PREFIX, publicKeyRaw]);
    const keyObject = createPublicKey({
      key: derKey,
      format: 'der',
      type: 'spki',
    });

    return verify(null, Buffer.from(message), keyObject, sigBuffer);
  } catch {
    return false;
  }
};
