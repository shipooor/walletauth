export type Verifier = (
  address: string,
  message: string,
  signature: string,
) => boolean | Promise<boolean>;

export interface ChallengeResult {
  nonce: string;
  challenge: string;
  expiresAt: number;
}

export interface ChallengeOptions {
  expiresIn?: number; // milliseconds, default 5 minutes
}

export interface TokenOptions {
  expiresIn?: string; // e.g. '1h', '7d', default '1h'
}

export interface TokenPayload {
  address: string;
  iat: number;
  exp: number;
}
