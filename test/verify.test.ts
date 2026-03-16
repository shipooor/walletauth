import { describe, it, expect } from 'vitest';
import { createChallenge } from '../src/challenge.js';
import { verifySignature } from '../src/verify.js';
import type { Verifier } from '../src/types.js';

const SECRET = 'test-secret-key-for-walletauth';
const ADDRESS = '0xaabbccdd';

// Mock verifier that always passes
const alwaysTrue: Verifier = () => true;
// Mock verifier that always fails
const alwaysFalse: Verifier = () => false;
// Mock async verifier
const asyncTrue: Verifier = () => Promise.resolve(true);
// Mock verifier that throws
const throwingVerifier: Verifier = () => { throw new Error('boom'); };

describe('verifySignature', () => {
  it('passes with valid challenge and passing verifier', async () => {
    const { challenge } = createChallenge(ADDRESS, SECRET);
    const result = await verifySignature(ADDRESS, 'any-sig', challenge, SECRET, alwaysTrue);
    expect(result).toBe(true);
  });

  it('fails with failing verifier', async () => {
    const { challenge } = createChallenge(ADDRESS, SECRET);
    const result = await verifySignature(ADDRESS, 'any-sig', challenge, SECRET, alwaysFalse);
    expect(result).toBe(false);
  });

  it('fails with tampered challenge', async () => {
    const { challenge } = createChallenge(ADDRESS, SECRET);
    const tampered = challenge.slice(0, -4) + 'xxxx';
    const result = await verifySignature(ADDRESS, 'any-sig', tampered, SECRET, alwaysTrue);
    expect(result).toBe(false);
  });

  it('fails with wrong address', async () => {
    const { challenge } = createChallenge(ADDRESS, SECRET);
    const result = await verifySignature('0xdifferent', 'any-sig', challenge, SECRET, alwaysTrue);
    expect(result).toBe(false);
  });

  it('fails with wrong secret', async () => {
    const { challenge } = createChallenge(ADDRESS, SECRET);
    const result = await verifySignature(ADDRESS, 'any-sig', challenge, 'wrong-secret', alwaysTrue);
    expect(result).toBe(false);
  });

  it('supports async verifiers', async () => {
    const { challenge } = createChallenge(ADDRESS, SECRET);
    const result = await verifySignature(ADDRESS, 'any-sig', challenge, SECRET, asyncTrue);
    expect(result).toBe(true);
  });

  it('tries multiple verifiers and passes on first match', async () => {
    const { challenge } = createChallenge(ADDRESS, SECRET);
    const result = await verifySignature(
      ADDRESS, 'any-sig', challenge, SECRET,
      [alwaysFalse, asyncTrue, alwaysFalse],
    );
    expect(result).toBe(true);
  });

  it('fails when all verifiers in array fail', async () => {
    const { challenge } = createChallenge(ADDRESS, SECRET);
    const result = await verifySignature(
      ADDRESS, 'any-sig', challenge, SECRET,
      [alwaysFalse, alwaysFalse],
    );
    expect(result).toBe(false);
  });

  it('handles throwing verifier gracefully', async () => {
    const { challenge } = createChallenge(ADDRESS, SECRET);
    const result = await verifySignature(
      ADDRESS, 'any-sig', challenge, SECRET,
      [throwingVerifier, alwaysTrue],
    );
    expect(result).toBe(true);
  });

  it('case-insensitive address comparison', async () => {
    const { challenge } = createChallenge('0xAABBCCDD', SECRET);
    const result = await verifySignature('0xaabbccdd', 'any-sig', challenge, SECRET, alwaysTrue);
    expect(result).toBe(true);
  });

  it('returns false (not throws) for undefined/null inputs', async () => {
    const { challenge } = createChallenge(ADDRESS, SECRET);
    // @ts-expect-error testing runtime safety with invalid types
    expect(await verifySignature(undefined, 'sig', challenge, SECRET, alwaysTrue)).toBe(false);
    // @ts-expect-error testing runtime safety with invalid types
    expect(await verifySignature(ADDRESS, 'sig', undefined, SECRET, alwaysTrue)).toBe(false);
    // @ts-expect-error testing runtime safety with invalid types
    expect(await verifySignature(ADDRESS, 'sig', null, SECRET, alwaysTrue)).toBe(false);
    // @ts-expect-error testing runtime safety with invalid types
    expect(await verifySignature(null, null, null, null, alwaysTrue)).toBe(false);
  });
});
