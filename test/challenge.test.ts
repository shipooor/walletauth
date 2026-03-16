import { describe, it, expect } from 'vitest';
import { createChallenge } from '../src/challenge.js';
import { parseAndVerifyChallenge } from '../src/challenge.js';

const SECRET = 'test-secret-key-for-walletauth';
const ADDRESS = '0x1234567890abcdef1234567890abcdef12345678';

describe('createChallenge', () => {
  it('returns nonce, challenge, and expiresAt', () => {
    const result = createChallenge(ADDRESS, SECRET);
    expect(result).toHaveProperty('nonce');
    expect(result).toHaveProperty('challenge');
    expect(result).toHaveProperty('expiresAt');
    expect(typeof result.nonce).toBe('string');
    expect(typeof result.challenge).toBe('string');
    expect(typeof result.expiresAt).toBe('number');
  });

  it('generates unique nonces', () => {
    const a = createChallenge(ADDRESS, SECRET);
    const b = createChallenge(ADDRESS, SECRET);
    expect(a.nonce).not.toBe(b.nonce);
  });

  it('challenge contains a dot separator', () => {
    const result = createChallenge(ADDRESS, SECRET);
    expect(result.challenge).toContain('.');
  });

  it('defaults to 5 minute expiry', () => {
    const before = Date.now();
    const result = createChallenge(ADDRESS, SECRET);
    const fiveMinutes = 5 * 60 * 1000;
    expect(result.expiresAt).toBeGreaterThanOrEqual(before + fiveMinutes - 100);
    expect(result.expiresAt).toBeLessThanOrEqual(before + fiveMinutes + 100);
  });

  it('respects custom expiresIn', () => {
    const before = Date.now();
    const result = createChallenge(ADDRESS, SECRET, { expiresIn: 60_000 });
    expect(result.expiresAt).toBeGreaterThanOrEqual(before + 59_000);
    expect(result.expiresAt).toBeLessThanOrEqual(before + 61_000);
  });

  it('throws on NaN expiresIn', () => {
    expect(() => createChallenge(ADDRESS, SECRET, { expiresIn: NaN })).toThrow('finite');
  });

  it('throws on Infinity expiresIn', () => {
    expect(() => createChallenge(ADDRESS, SECRET, { expiresIn: Infinity })).toThrow('finite');
    expect(() => createChallenge(ADDRESS, SECRET, { expiresIn: -Infinity })).toThrow('finite');
  });
});

describe('parseAndVerifyChallenge', () => {
  it('verifies a valid challenge', () => {
    const { challenge } = createChallenge(ADDRESS, SECRET);
    const payload = parseAndVerifyChallenge(challenge, SECRET);
    expect(payload).not.toBeNull();
    expect(payload!.address).toBe(ADDRESS);
    expect(typeof payload!.nonce).toBe('string');
  });

  it('rejects tampered challenge', () => {
    const { challenge } = createChallenge(ADDRESS, SECRET);
    const tampered = challenge.slice(0, -4) + 'xxxx';
    expect(parseAndVerifyChallenge(tampered, SECRET)).toBeNull();
  });

  it('rejects wrong secret', () => {
    const { challenge } = createChallenge(ADDRESS, SECRET);
    expect(parseAndVerifyChallenge(challenge, 'wrong-secret')).toBeNull();
  });

  it('rejects expired challenge', () => {
    const { challenge } = createChallenge(ADDRESS, SECRET, { expiresIn: -1000 });
    expect(parseAndVerifyChallenge(challenge, SECRET)).toBeNull();
  });

  it('rejects malformed input', () => {
    expect(parseAndVerifyChallenge('', SECRET)).toBeNull();
    expect(parseAndVerifyChallenge('nodot', SECRET)).toBeNull();
    expect(parseAndVerifyChallenge('bad.data', SECRET)).toBeNull();
  });
});
