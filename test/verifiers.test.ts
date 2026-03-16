import { describe, it, expect } from 'vitest';
import { privateKeyToAccount } from './helpers/evm.js';
import { generateEd25519Keypair, signEd25519, signEd25519Base58 } from './helpers/ed25519.js';
import { verifiers } from '../src/verifiers/index.js';

describe('verifiers.evm', () => {
  it('verifies a valid EVM signature', () => {
    const { address, signMessage } = privateKeyToAccount();
    const message = 'test-nonce-12345';
    const signature = signMessage(message);
    expect(verifiers.evm(address, message, signature)).toBe(true);
  });

  it('rejects wrong message', () => {
    const { address, signMessage } = privateKeyToAccount();
    const signature = signMessage('correct-message');
    expect(verifiers.evm(address, 'wrong-message', signature)).toBe(false);
  });

  it('rejects wrong address', () => {
    const { signMessage } = privateKeyToAccount();
    const signature = signMessage('test-message');
    expect(verifiers.evm('0x0000000000000000000000000000000000000000', 'test-message', signature)).toBe(false);
  });

  it('rejects invalid signature', () => {
    const { address } = privateKeyToAccount();
    expect(verifiers.evm(address, 'test', 'invalid')).toBe(false);
    expect(verifiers.evm(address, 'test', '0x' + '00'.repeat(65))).toBe(false);
  });

  it('handles 0x prefix in signature', () => {
    const { address, signMessage } = privateKeyToAccount();
    const message = 'test-nonce';
    const signature = signMessage(message);
    // Should work with or without 0x
    const withoutPrefix = signature.startsWith('0x') ? signature.slice(2) : signature;
    expect(verifiers.evm(address, message, '0x' + withoutPrefix)).toBe(true);
  });
});

describe('verifiers.ed25519', () => {
  it('verifies a valid ed25519 signature', () => {
    const { address, privateKey } = generateEd25519Keypair();
    const message = 'test-nonce-12345';
    const signature = signEd25519(message, privateKey);
    expect(verifiers.ed25519(address, message, signature)).toBe(true);
  });

  it('rejects wrong message', () => {
    const { address, privateKey } = generateEd25519Keypair();
    const signature = signEd25519('correct-message', privateKey);
    expect(verifiers.ed25519(address, 'wrong-message', signature)).toBe(false);
  });

  it('rejects wrong address (public key)', () => {
    const { privateKey } = generateEd25519Keypair();
    const { address: otherAddress } = generateEd25519Keypair();
    const signature = signEd25519('test-message', privateKey);
    expect(verifiers.ed25519(otherAddress, 'test-message', signature)).toBe(false);
  });

  it('verifies with base58 address (Solana format)', () => {
    const { base58Address, privateKey } = generateEd25519Keypair();
    const message = 'test-nonce-solana';
    const signature = signEd25519(message, privateKey);
    expect(verifiers.ed25519(base58Address, message, signature)).toBe(true);
  });

  it('rejects wrong base58 address', () => {
    const { privateKey } = generateEd25519Keypair();
    const { base58Address: otherBase58 } = generateEd25519Keypair();
    const signature = signEd25519('test-message', privateKey);
    expect(verifiers.ed25519(otherBase58, 'test-message', signature)).toBe(false);
  });

  it('verifies with base58-encoded signature (Solana convention)', () => {
    const { base58Address, privateKey } = generateEd25519Keypair();
    const message = 'test-nonce-solana-sig';
    const signature = signEd25519Base58(message, privateKey);
    expect(verifiers.ed25519(base58Address, message, signature)).toBe(true);
  });

  it('full Solana style: base58 address + base58 signature', () => {
    const { base58Address, privateKey } = generateEd25519Keypair();
    const message = 'solana-full-flow';
    const signature = signEd25519Base58(message, privateKey);
    expect(verifiers.ed25519(base58Address, message, signature)).toBe(true);
  });

  it('rejects invalid inputs', () => {
    expect(verifiers.ed25519('not-hex', 'test', 'not-sig')).toBe(false);
    expect(verifiers.ed25519('aa'.repeat(32), 'test', 'bad')).toBe(false);
  });
});
