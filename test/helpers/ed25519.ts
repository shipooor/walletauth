import { generateKeyPairSync, sign } from 'node:crypto';
import type { KeyObject } from 'node:crypto';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function encodeBase58(buffer: Buffer): string {
  const digits: number[] = [];
  for (const byte of buffer) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let result = '';
  // Leading zeros
  for (const byte of buffer) {
    if (byte !== 0) break;
    result += '1';
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }
  return result;
}

export function generateEd25519Keypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');

  // Export raw 32-byte public key
  const pubRaw = publicKey.export({ type: 'spki', format: 'der' });
  // DER SPKI for ed25519: 12-byte prefix + 32-byte key
  const pubBytes = Buffer.from(pubRaw.subarray(12));
  const hexAddress = pubBytes.toString('hex');
  const base58Address = encodeBase58(pubBytes);

  return { address: hexAddress, base58Address, privateKey };
}

export function signEd25519(message: string, privateKey: KeyObject): string {
  const sig = sign(null, Buffer.from(message), privateKey);
  return sig.toString('hex');
}

export function signEd25519Base58(message: string, privateKey: KeyObject): string {
  const sig = sign(null, Buffer.from(message), privateKey);
  return encodeBase58(Buffer.from(sig));
}
