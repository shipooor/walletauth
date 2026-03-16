const MIN_SECRET_LENGTH = 16;

export function assertSecret(secret: string): void {
  if (!secret || secret.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `WALLETAUTH_SECRET must be at least ${MIN_SECRET_LENGTH} characters`,
    );
  }
}
