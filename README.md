# @walletauth/server

Your wallet is your API key. Agent-native auth for APIs.

## What

Lightweight, framework-agnostic auth library that replaces API keys with wallet signatures.
Zero config for agents. Full control for API owners.

```
Agent has wallet → requests challenge → signs nonce → gets JWT → calls API
No registration. No API keys. No rotation.
```

## Why

| Problem | Wallet Auth |
|---|---|
| API keys are manual (generate, copy, rotate) | Wallet = identity, automatic |
| One key = all agents (no granularity) | Each agent = own wallet = own identity |
| Keys leak, get stolen, expire | Private key never leaves the agent |
| Auth0/OAuth2 designed for humans | Agent-native, no human in the loop |

## How it works

```
┌─────────────────────────────────┐
│  AI Agent (any framework)       │
│  Has a wallet / keypair         │
└──────────┬──────────────────────┘
           │ 1. POST /auth/challenge { address }
           │ 2. Server returns { nonce, challenge, expiresAt }
           │ 3. Agent signs nonce with private key
           │ 4. POST /auth/verify { address, signature, challenge }
           │ 5. Server verifies HMAC + wallet signature → JWT
           ↓
┌──────────────────────────────────┐
│  Your API + @walletauth/server   │
│                                   │
│  ├─ Stateless challenge/verify   │
│  ├─ HMAC-signed challenges       │
│  ├─ Signature verification       │
│  └─ JWT issuance & validation    │
└───────────────────────────────────┘
```

### Stateless by design

Challenges are HMAC-signed — the server verifies its own signature on return. No nonce storage, no database, no Redis. Truly stateless.

## Install

```bash
npm install @walletauth/server
```

## Core API

Pure functions. No framework dependency. Use with Express, NestJS, Fastify, Hono, or anything else.

```typescript
import {
  createChallenge,
  verifySignature,
  issueToken,
  validateToken,
  verifiers,
} from '@walletauth/server';
```

| Function | Description |
|---|---|
| `createChallenge(address, secret)` | Generate a stateless HMAC-signed challenge |
| `verifySignature(address, signature, challenge, secret, verifier)` | Verify HMAC + wallet signature. **async** |
| `issueToken(address, secret, options?)` | Issue a JWT for the verified address. **async** |
| `validateToken(token, secret)` | Validate JWT, return `{ address }` or `null`. **async** |
| `verifiers.evm` | EVM signature verifier (secp256k1) |
| `verifiers.ed25519` | Ed25519 verifier (Solana, raw keys) |

> `verifySignature`, `issueToken`, and `validateToken` return Promises — always `await` them.

## Built-in verifiers

All chains supported in one lightweight package (~7KB ESM). No ethers.js, no heavy deps.

| Chain | Verifier | Crypto | Dep |
|---|---|---|---|
| EVM (Ethereum, Arbitrum, Base, etc.) | `verifiers.evm` | secp256k1 + keccak256 | `@noble/curves` + `@noble/hashes` |
| Solana | `verifiers.ed25519` | ed25519 | Node.js built-in `crypto` |
| Raw ed25519 keypair | `verifiers.ed25519` | ed25519 | Node.js built-in `crypto` |
| Custom | `(addr, msg, sig) => boolean \| Promise<boolean>` | Any | Bring your own |

Multiple verifiers supported — pass an array for multi-chain APIs:

```typescript
verifySignature(address, signature, challenge, secret, [verifiers.evm, verifiers.ed25519])
```

Each verifier is tried in order. First `true` wins. Cryptographically safe — a secp256k1 signature can't accidentally pass ed25519 verification.

## Usage: Express

```typescript
import express from 'express';
import { createChallenge, verifySignature, issueToken, validateToken, verifiers } from '@walletauth/server';

const app = express();
app.use(express.json());

const SECRET = process.env.WALLETAUTH_SECRET; // Used for both HMAC challenges and JWT signing

// Step 1: Agent requests a challenge
app.post('/auth/challenge', (req, res) => {
  const challenge = createChallenge(req.body.address, SECRET);
  res.json(challenge);  // { nonce, challenge, expiresAt }
});

// Step 2: Agent signs nonce and sends back
app.post('/auth/verify', async (req, res) => {
  const { address, signature, challenge } = req.body;
  const valid = await verifySignature(address, signature, challenge, SECRET, verifiers.evm);
  if (!valid) return res.status(401).json({ error: 'Invalid signature' });

  const token = await issueToken(address, SECRET);
  res.json({ token });
});

// Middleware: protect routes
async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  const payload = await validateToken(token, SECRET);
  if (!payload) return res.status(401).json({ error: 'Invalid token' });
  req.wallet = payload.address;
  next();
}

// Protected route
app.get('/api/data', authMiddleware, (req, res) => {
  res.json({ wallet: req.wallet, data: '...' });
});
```

## Usage: NestJS

```typescript
import { Injectable, CanActivate, ExecutionContext, createParamDecorator } from '@nestjs/common';
import { validateToken } from '@walletauth/server';

@Injectable()
export class WalletAuthGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = request.headers.authorization?.split(' ')[1];
    const payload = await validateToken(token, process.env.WALLETAUTH_SECRET);
    if (!payload) return false;
    request.wallet = payload.address;
    return true;
  }
}

export const WalletAddress = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => ctx.switchToHttp().getRequest().wallet,
);

// Usage in controller:
// @UseGuards(WalletAuthGuard)
// @Get('data')
// getData(@WalletAddress() wallet: string) { ... }
```

## Usage: Client (any wallet)

```typescript
// EVM wallet (MetaMask, WDK, Coinbase CDP, etc.)
const res = await fetch('/auth/challenge', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ address: wallet.address }),
}).then(r => r.json());

const signature = await wallet.signMessage(res.nonce);

const { token } = await fetch('/auth/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ address: wallet.address, signature, challenge: res.challenge }),
}).then(r => r.json());

// Use token for all subsequent requests
fetch('/api/data', { headers: { Authorization: `Bearer ${token}` } });
```

```typescript
// Solana wallet (Phantom, etc.)
import bs58 from 'bs58'; // already available via @solana/web3.js
const sigBytes = await phantom.signMessage(new TextEncoder().encode(res.nonce));
const signature = bs58.encode(sigBytes);
```

```typescript
// Raw ed25519 keypair (no blockchain needed)
import { sign } from 'crypto';
const sigBytes = sign(null, Buffer.from(res.nonce), privateKey);
const signature = sigBytes.toString('hex');
```

## Wire format

### Challenge response (server → client)

```json
{
  "nonce": "a1b2c3d4e5f6...",
  "challenge": "BASE64_HMAC_SIGNED_BLOB",
  "expiresAt": 1710500000000
}
```

- `nonce` — the message the client must sign with their wallet
- `challenge` — opaque HMAC-signed blob (client stores and sends back as-is)
- `expiresAt` — expiration timestamp (informational for the client)

### Verify request (client → server)

```json
{
  "address": "0x1234...",
  "signature": "0xabcd...",
  "challenge": "BASE64_HMAC_SIGNED_BLOB"
}
```

The client never needs to send the nonce separately — it's embedded in the challenge blob.

## Framework adapters (planned)

Core is framework-agnostic. Optional adapter packages may be published if needed:

| Package | Status |
|---|---|
| `@walletauth/server` | Core library (pure functions + verifiers) |
| `@walletauth/express` | Planned — Express middleware wrapper |
| `@walletauth/nestjs` | Planned — Guard + decorator |
| `@walletauth/fastify` | Planned — Fastify plugin |

## Size

| | @walletauth/server | ethers.js (for verifyMessage) |
|---|---|---|
| Library size | ~7KB ESM | 500KB+ |
| Runtime deps | 3 (`@noble/curves`, `@noble/hashes`, `jose`) | Everything bundled |
| EVM verify | `@noble/curves` + `@noble/hashes` | Full ethers bundle |
| ed25519 verify | Node.js built-in `crypto` | Not included |

Same underlying crypto (`@noble/*`), minimal surface area.

## Security notes

- **HTTPS required**: Always deploy behind HTTPS. Challenges, signatures, and JWTs are sent in plaintext over HTTP — an attacker on the network can intercept them.
- **Single secret (v1)**: One secret for both HMAC challenges and JWT signing. Both use HMAC-SHA256, which is a PRF — safe for key reuse. The payloads are structurally different (challenge JSON vs JWT claims), so there's no confusion risk. Separate secrets can be supported in a future version.
- **One secret per service**: If you run multiple APIs, use a different `WALLETAUTH_SECRET` for each. JWTs signed by one service are valid on any service that shares the same secret.
- **Secret rotation**: Changing `WALLETAUTH_SECRET` instantly invalidates all existing JWTs and pending challenges. Plan rotation during low-traffic windows. For graceful rotation, validate against both old and new secrets during a transition period.
- **Challenge expiration**: Default 5 minutes. Configurable via options.
- **Replay window**: Within the challenge TTL, a captured `{ address, signature, challenge }` request can be replayed to obtain a JWT. HTTPS prevents interception. For strict one-time use, implement nonce tracking at the application level.
- **JWT revocation**: Stateless JWTs cannot be revoked before expiry. If an agent is compromised, you must either rotate the secret (invalidates all tokens) or maintain a blocklist at the application level. Use short JWT expiry (`1h` default) to limit exposure.
- **No rate limiting built-in**: Rate limiting is the API owner's responsibility. The challenge endpoint is unauthenticated — protect it with your framework's middleware (express-rate-limit, @nestjs/throttler, etc.).

## Generating a secret

```bash
openssl rand -base64 32
```

Minimum 16 characters. Store in environment variables, never in code.

```bash
export WALLETAUTH_SECRET="your-generated-secret-here"
```

## Debugging

All verification functions return `false` or `null` on failure without revealing the reason. This is intentional — error details could leak information to attackers.

Common issues when auth fails:

| Symptom | Check |
|---|---|
| `verifySignature` returns `false` | Is the challenge expired? (default 5 min TTL) |
| `verifySignature` returns `false` | Is the correct verifier used? (evm vs ed25519) |
| `verifySignature` returns `false` | Does the address match between challenge and verify? |
| `verifySignature` returns `false` | Is the client signing the `nonce` string, not the `challenge` blob? |
| `validateToken` returns `null` | Is the JWT expired? |
| `validateToken` returns `null` | Is the same secret used for issuing and validating? |
| `assertSecret` throws | Secret must be at least 16 characters |

## Related

- [SIWE (EIP-4361)](https://docs.siwe.xyz/) — session-based, human-facing login
- [ERC-8128](https://eips.ethereum.org/EIPS/eip-8128) — per-request HTTP signing (draft)
- [x402](https://www.x402.org/) — payment auth protocol (complementary)
