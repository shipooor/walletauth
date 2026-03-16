import { describe, it, expect } from 'vitest';
import { SignJWT } from 'jose';
import { issueToken, validateToken } from '../src/token.js';

const SECRET = 'test-secret-key-for-walletauth';
const ADDRESS = '0x1234567890abcdef1234567890abcdef12345678';

describe('issueToken', () => {
  it('returns a JWT string', async () => {
    const token = await issueToken(ADDRESS, SECRET);
    expect(typeof token).toBe('string');
    // JWT has 3 parts separated by dots
    expect(token.split('.').length).toBe(3);
  });
});

describe('validateToken', () => {
  it('validates a valid token and returns address', async () => {
    const token = await issueToken(ADDRESS, SECRET);
    const payload = await validateToken(token, SECRET);
    expect(payload).not.toBeNull();
    expect(payload!.address).toBe(ADDRESS);
    expect(typeof payload!.iat).toBe('number');
    expect(typeof payload!.exp).toBe('number');
  });

  it('rejects token with wrong secret', async () => {
    const token = await issueToken(ADDRESS, SECRET);
    const payload = await validateToken(token, 'wrong-secret');
    expect(payload).toBeNull();
  });

  it('rejects tampered token', async () => {
    const token = await issueToken(ADDRESS, SECRET);
    const tampered = token.slice(0, -4) + 'xxxx';
    const payload = await validateToken(tampered, SECRET);
    expect(payload).toBeNull();
  });

  it('rejects garbage input', async () => {
    expect(await validateToken('', SECRET)).toBeNull();
    expect(await validateToken('not-a-jwt', SECRET)).toBeNull();
  });

  it('respects custom expiresIn', async () => {
    const token = await issueToken(ADDRESS, SECRET, { expiresIn: '2h' });
    const payload = await validateToken(token, SECRET);
    expect(payload).not.toBeNull();
    // exp should be ~2 hours from now
    const twoHours = 2 * 60 * 60;
    const diff = payload!.exp - payload!.iat;
    expect(diff).toBeGreaterThanOrEqual(twoHours - 5);
    expect(diff).toBeLessThanOrEqual(twoHours + 5);
  });

  it('rejects JWT without exp claim', async () => {
    const secretKey = new TextEncoder().encode(SECRET);
    const token = await new SignJWT({ address: ADDRESS })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .sign(secretKey);
    expect(await validateToken(token, SECRET)).toBeNull();
  });

  it('rejects JWT without iat claim', async () => {
    const secretKey = new TextEncoder().encode(SECRET);
    const token = await new SignJWT({ address: ADDRESS })
      .setProtectedHeader({ alg: 'HS256' })
      .setExpirationTime('1h')
      .sign(secretKey);
    expect(await validateToken(token, SECRET)).toBeNull();
  });

  it('rejects JWT without address claim', async () => {
    const secretKey = new TextEncoder().encode(SECRET);
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(secretKey);
    expect(await validateToken(token, SECRET)).toBeNull();
  });

  it('returns null (not throws) for undefined input', async () => {
    // @ts-expect-error testing runtime safety with invalid types
    expect(await validateToken(undefined, SECRET)).toBeNull();
  });
});
