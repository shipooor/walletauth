import { describe, it, expect } from 'vitest';
import { createChallenge, verifySignature, issueToken, validateToken, verifiers } from '../src/index.js';
import { privateKeyToAccount } from './helpers/evm.js';
import { generateEd25519Keypair, signEd25519 } from './helpers/ed25519.js';

const SECRET = 'integration-test-secret-walletauth';

describe('full flow: EVM', () => {
  it('challenge → sign → verify → JWT → validate', async () => {
    const { address, signMessage } = privateKeyToAccount();

    // 1. Server creates challenge
    const { nonce, challenge, expiresAt } = createChallenge(address, SECRET);
    expect(expiresAt).toBeGreaterThan(Date.now());

    // 2. Client signs the nonce
    const signature = signMessage(nonce);

    // 3. Server verifies
    const valid = await verifySignature(address, signature, challenge, SECRET, verifiers.evm);
    expect(valid).toBe(true);

    // 4. Server issues JWT
    const token = await issueToken(address, SECRET);

    // 5. Server validates JWT on subsequent requests
    const payload = await validateToken(token, SECRET);
    expect(payload).not.toBeNull();
    expect(payload!.address).toBe(address);
  });
});

describe('full flow: ed25519', () => {
  it('challenge → sign → verify → JWT → validate', async () => {
    const { address, privateKey } = generateEd25519Keypair();

    // 1. Server creates challenge
    const { nonce, challenge } = createChallenge(address, SECRET);

    // 2. Client signs the nonce
    const signature = signEd25519(nonce, privateKey);

    // 3. Server verifies
    const valid = await verifySignature(address, signature, challenge, SECRET, verifiers.ed25519);
    expect(valid).toBe(true);

    // 4. Server issues JWT
    const token = await issueToken(address, SECRET);

    // 5. Server validates JWT
    const payload = await validateToken(token, SECRET);
    expect(payload).not.toBeNull();
    expect(payload!.address).toBe(address);
  });
});

describe('full flow: Solana (base58)', () => {
  it('challenge → sign → verify → JWT → validate', async () => {
    const { base58Address, privateKey } = generateEd25519Keypair();

    const { nonce, challenge } = createChallenge(base58Address, SECRET);
    const signature = signEd25519(nonce, privateKey);

    const valid = await verifySignature(base58Address, signature, challenge, SECRET, verifiers.ed25519);
    expect(valid).toBe(true);

    const token = await issueToken(base58Address, SECRET);
    const payload = await validateToken(token, SECRET);
    expect(payload).not.toBeNull();
    expect(payload!.address).toBe(base58Address);
  });
});

describe('full flow: multi-chain', () => {
  it('auto-detects EVM verifier from array', async () => {
    const { address, signMessage } = privateKeyToAccount();
    const { challenge, nonce } = createChallenge(address, SECRET);
    const signature = signMessage(nonce);

    const valid = await verifySignature(
      address, signature, challenge, SECRET,
      [verifiers.evm, verifiers.ed25519],
    );
    expect(valid).toBe(true);
  });

  it('auto-detects ed25519 verifier from array', async () => {
    const { address, privateKey } = generateEd25519Keypair();
    const { challenge, nonce } = createChallenge(address, SECRET);
    const signature = signEd25519(nonce, privateKey);

    const valid = await verifySignature(
      address, signature, challenge, SECRET,
      [verifiers.evm, verifiers.ed25519],
    );
    expect(valid).toBe(true);
  });
});

describe('security', () => {
  it('rejects challenge replay with different address', async () => {
    const { address: addr1, signMessage } = privateKeyToAccount();
    const { address: addr2 } = privateKeyToAccount();
    const { challenge, nonce } = createChallenge(addr1, SECRET);
    const signature = signMessage(nonce);

    // Try to use addr1's challenge with addr2
    const valid = await verifySignature(addr2, signature, challenge, SECRET, verifiers.evm);
    expect(valid).toBe(false);
  });

  it('rejects expired challenge', async () => {
    const { address, signMessage } = privateKeyToAccount();
    const { challenge, nonce } = createChallenge(address, SECRET, { expiresIn: -1000 });
    const signature = signMessage(nonce);

    const valid = await verifySignature(address, signature, challenge, SECRET, verifiers.evm);
    expect(valid).toBe(false);
  });

  it('rejects challenge signed with wrong server secret', async () => {
    const { address, signMessage } = privateKeyToAccount();
    const { challenge, nonce } = createChallenge(address, 'server-secret-one-1');
    const signature = signMessage(nonce);

    const valid = await verifySignature(address, signature, challenge, 'server-secret-two-2', verifiers.evm);
    expect(valid).toBe(false);
  });

  it('throws on empty secret', () => {
    const { address } = privateKeyToAccount();
    expect(() => createChallenge(address, '')).toThrow();
    expect(() => createChallenge(address, 'short')).toThrow();
  });

  it('throws on short secret for issueToken', async () => {
    const { address } = privateKeyToAccount();
    await expect(issueToken(address, '')).rejects.toThrow();
    await expect(issueToken(address, 'short')).rejects.toThrow();
  });
});
