import { parseAndVerifyChallenge } from './challenge.js';
import type { Verifier } from './types.js';

/**
 * Verify a wallet signature against an HMAC-signed challenge.
 *
 * Checks that the challenge is authentic (HMAC), not expired, and that the
 * wallet signature is valid for the nonce embedded in the challenge.
 *
 * @param address - Wallet address claiming ownership.
 * @param signature - Wallet signature over the nonce.
 * @param challenge - Opaque challenge blob from {@link createChallenge}.
 * @param secret - Same server secret used in `createChallenge`.
 * @param verifier - A {@link Verifier} or array of verifiers (tried in order, first `true` wins).
 * @returns `true` if the signature is valid, `false` otherwise. Never throws.
 */
export async function verifySignature(
  address: string,
  signature: string,
  challenge: string,
  secret: string,
  verifier: Verifier | Verifier[],
): Promise<boolean> {
  try {
    // Verify HMAC challenge
    const payload = parseAndVerifyChallenge(challenge, secret);
    if (!payload) return false;

    // Verify address matches
    if (payload.address.toLowerCase() !== address.toLowerCase()) return false;

    // Try verifier(s)
    const verifierList = Array.isArray(verifier) ? verifier : [verifier];
    for (const v of verifierList) {
      try {
        const result = await v(address, payload.nonce, signature);
        if (result) return true;
      } catch {
        // Verifier threw — try next
      }
    }

    return false;
  } catch {
    return false;
  }
}
