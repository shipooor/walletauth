import { SignJWT, jwtVerify } from 'jose';
import type { TokenOptions, TokenPayload } from './types.js';
import { assertSecret } from './secret.js';

const DEFAULT_EXPIRES_IN = '1h';

/**
 * Issue a JWT for an authenticated wallet address.
 *
 * Call this after {@link verifySignature} returns `true`.
 *
 * @param address - Verified wallet address to embed in the token.
 * @param secret - Server secret (min 16 chars). Same as used for challenges.
 * @param options - Optional. `expiresIn`: JWT lifetime string (default `'1h'`). Examples: `'30m'`, `'2h'`, `'7d'`.
 * @returns Signed JWT string. Send to the client as a Bearer token.
 * @throws If secret is too short.
 */
export async function issueToken(
  address: string,
  secret: string,
  options?: TokenOptions,
): Promise<string> {
  assertSecret(secret);
  const secretKey = new TextEncoder().encode(secret);
  const expiresIn = options?.expiresIn ?? DEFAULT_EXPIRES_IN;

  return new SignJWT({ address })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(secretKey);
}

/**
 * Validate a JWT and extract the wallet address.
 *
 * Use this in auth middleware to protect routes.
 *
 * @param token - JWT string from the `Authorization: Bearer <token>` header.
 * @param secret - Same server secret used in `issueToken`.
 * @returns `{ address, iat, exp }` if valid, `null` otherwise. Never throws.
 */
export async function validateToken(
  token: string,
  secret: string,
): Promise<TokenPayload | null> {
  try {
    const secretKey = new TextEncoder().encode(secret);
    const { payload } = await jwtVerify(token, secretKey, { algorithms: ['HS256'] });

    if (typeof payload.address !== 'string') return null;
    if (typeof payload.iat !== 'number') return null;
    if (typeof payload.exp !== 'number') return null;

    return {
      address: payload.address,
      iat: payload.iat,
      exp: payload.exp,
    };
  } catch {
    return null;
  }
}
