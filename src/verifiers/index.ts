import { evm } from './evm.js';
import { ed25519 } from './ed25519.js';

export const verifiers = {
  /**
   * EVM signature verifier (Ethereum, Arbitrum, Base, Polygon, etc.).
   * Verifies `personal_sign` (EIP-191) signatures using secp256k1 ecrecover.
   */
  evm,
  /**
   * Ed25519 signature verifier (Solana, raw ed25519 keypairs).
   * Accepts addresses as base58 or hex. Signatures as hex, base58, or base64.
   */
  ed25519,
};
