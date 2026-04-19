export type Polynomial = number[];

export const MLDSA_Q = 8380417;
export const MLDSA_N = 256;
export const MLDSA_LEVEL = 'ML-DSA-65';

export function normalizeCoeff(value: number, modulus: number = MLDSA_Q): number {
  const reduced = value % modulus;
  return reduced < 0 ? reduced + modulus : reduced;
}

export function centeredCoeff(value: number, modulus: number = MLDSA_Q): number {
  const normalized = normalizeCoeff(value, modulus);
  return normalized > modulus / 2 ? normalized - modulus : normalized;
}

function requireCrypto(): Crypto {
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new Error('Secure randomness is unavailable in this environment.');
  }
  return crypto;
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  requireCrypto().getRandomValues(out);
  return out;
}

export function randomIntBelow(maxExclusive: number): number {
  if (!Number.isInteger(maxExclusive) || maxExclusive <= 0 || maxExclusive > 0x1_0000_0000) {
    throw new Error(`Invalid range for randomIntBelow: ${maxExclusive}`);
  }
  const maxUint32PlusOne = 0x1_0000_0000;
  const limit = maxUint32PlusOne - (maxUint32PlusOne % maxExclusive);
  const sample = new Uint32Array(1);
  do {
    requireCrypto().getRandomValues(sample);
  } while (sample[0] >= limit);
  return sample[0] % maxExclusive;
}

export function randomSmallInt(maxAbs: number): number {
  return randomIntBelow((maxAbs * 2) + 1) - maxAbs;
}

export function randomPolynomial(
  degree: number = MLDSA_N,
  modulus: number = MLDSA_Q,
): Polynomial {
  return Array.from({ length: degree }, () => randomIntBelow(modulus));
}

export function randomSmallPolynomial(
  degree: number = MLDSA_N,
  maxAbs: number = 4,
  modulus: number = MLDSA_Q,
): Polynomial {
  return Array.from({ length: degree }, () => normalizeCoeff(randomSmallInt(maxAbs), modulus));
}

export function addPolynomials(
  left: Polynomial,
  right: Polynomial,
  modulus: number = MLDSA_Q,
): Polynomial {
  if (left.length !== right.length) {
    throw new Error('Polynomial length mismatch');
  }
  return left.map((coeff, index) => normalizeCoeff(coeff + right[index], modulus));
}

export function subtractPolynomials(
  left: Polynomial,
  right: Polynomial,
  modulus: number = MLDSA_Q,
): Polynomial {
  if (left.length !== right.length) {
    throw new Error('Polynomial length mismatch');
  }
  return left.map((coeff, index) => normalizeCoeff(coeff - right[index], modulus));
}

export function maxInfinityNorm(poly: Polynomial, modulus: number = MLDSA_Q): number {
  return poly.reduce((max, coeff) => {
    const centered = Math.abs(centeredCoeff(coeff, modulus));
    return centered > max ? centered : max;
  }, 0);
}

export function splitByteShares(secret: Uint8Array): {
  serverShare: Uint8Array;
  phoneShare: Uint8Array;
} {
  const phoneShare = randomBytes(secret.length);
  const serverShare = new Uint8Array(secret.length);
  for (let i = 0; i < secret.length; i += 1) {
    serverShare[i] = (secret[i] - phoneShare[i] + 256) % 256;
  }
  return { serverShare, phoneShare };
}

export function reconstructByteShares(
  serverShare: Uint8Array,
  phoneShare: Uint8Array,
): Uint8Array {
  if (serverShare.length !== phoneShare.length) {
    throw new Error('Byte-share length mismatch');
  }
  const out = new Uint8Array(serverShare.length);
  for (let i = 0; i < serverShare.length; i += 1) {
    out[i] = (serverShare[i] + phoneShare[i]) % 256;
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array, maxLength: number = bytes.length): string {
  const slice = bytes.slice(0, maxLength);
  return Array.from(slice, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function encodeText(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}
