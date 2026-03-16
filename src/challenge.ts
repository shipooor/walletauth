import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { ChallengeOptions, ChallengeResult } from './types.js';
import { assertSecret } from './secret.js';

const DEFAULT_EXPIRES_IN = 5 * 60 * 1000; // 5 minutes

interface ChallengePayload {
  address: string;
  nonce: string;
  exp: number;
}

function sign(payload: ChallengePayload, secret: string): string {
  const data = JSON.stringify(payload);
  const mac = createHmac('sha256', secret).update(data).digest('base64url');
  const encoded = Buffer.from(data).toString('base64url');
  return `${encoded}.${mac}`;
}

export function parseAndVerifyChallenge(
  challenge: string,
  secret: string,
): ChallengePayload | null {
  const dotIndex = challenge.indexOf('.');
  if (dotIndex === -1) return null;

  const encoded = challenge.slice(0, dotIndex);
  const mac = challenge.slice(dotIndex + 1);

  let data: string;
  try {
    data = Buffer.from(encoded, 'base64url').toString();
  } catch {
    return null;
  }

  const expectedMac = createHmac('sha256', secret).update(data).digest('base64url');

  // Constant-time comparison to prevent timing attacks
  const a = Buffer.from(mac);
  const b = Buffer.from(expectedMac);
  if (a.length !== b.length) return null;
  if (!timingSafeEqual(a, b)) return null;

  try {
    const payload: ChallengePayload = JSON.parse(data);
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

/**
 * Generate a stateless HMAC-signed challenge for wallet authentication.
 *
 * @param address - Wallet address (EVM `0x...` or Solana base58)
 * @param secret - Server secret (min 16 chars). Use `WALLETAUTH_SECRET` env var.
 * @param options - Optional. `expiresIn`: challenge TTL in ms (default 5 min).
 * @returns `{ nonce, challenge, expiresAt }` — send all three to the client.
 *   The client signs `nonce` and sends back `{ address, signature, challenge }`.
 * @throws If secret is too short or expiresIn is not a finite number.
 */
export function createChallenge(
  address: string,
  secret: string,
  options?: ChallengeOptions,
): ChallengeResult {
  assertSecret(secret);
  const expiresIn = options?.expiresIn ?? DEFAULT_EXPIRES_IN;
  if (!Number.isFinite(expiresIn)) {
    throw new Error('expiresIn must be a finite number');
  }
  const nonce = randomBytes(32).toString('hex');
  const exp = Date.now() + expiresIn;

  const payload: ChallengePayload = { address, nonce, exp };
  const challenge = sign(payload, secret);

  return { nonce, challenge, expiresAt: exp };
}
