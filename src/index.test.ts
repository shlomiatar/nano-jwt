import { test, expect } from 'bun:test';

// Global TextDecoder and TextEncoder instances
const [dec, enc] = [new TextDecoder(), new TextEncoder()];

// Helper functions from the provided code
const b64uToU8 = (s: string) => new Uint8Array(atob(s.replace(/-/g, '+').replace(/_/g, '/')).split('').map(c => c.charCodeAt(0)));
const b64uToJson = (s: string) => JSON.parse(dec.decode(b64uToU8(s)));

// Additional helper functions for signing
const jsonToB64u = (obj: any): string => {
  const jsonStr = JSON.stringify(obj);
  const u8 = enc.encode(jsonStr);
  const b64 = btoa(String.fromCharCode(...u8));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const u8ToB64u = (u8: Uint8Array): string => {
  const b64 = btoa(String.fromCharCode(...u8));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

import { jwt } from '.';

// Signing function to generate test tokens
async function sign(payload: any, algorithm: 'HS256' | 'HS512', secret: string): Promise<string> {
  const header = { alg: algorithm, typ: 'JWT' };
  const headerB64 = jsonToB64u(header);
  const payloadB64 = jsonToB64u(payload);
  const data = `${headerB64}.${payloadB64}`;
  const dataU8 = enc.encode(data);
  const hash = `SHA-${algorithm.substring(2)}`;
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, dataU8);
  const signatureB64 = u8ToB64u(new Uint8Array(signature));
  return `${data}.${signatureB64}`;
}

// Common secret for tests
const secret = 'mysecret';

// Test Cases
test('valid HS256 token', async () => {
  const jwtVerifier = jwt(secret, 'HS256');
  const payload = { sub: '123', exp: Math.floor(Date.now() / 1000) + 3600 };
  const token = await sign(payload, 'HS256', secret);
  const [isValid, result] = await jwtVerifier.verify(token);
  expect(isValid).toBe(true);
  expect(result).toEqual(payload);
});

test('valid HS512 token', async () => {
  const jwtVerifier = jwt(secret, 'HS512');
  const payload = { sub: '123', exp: Math.floor(Date.now() / 1000) + 3600 };
  const token = await sign(payload, 'HS512', secret);
  const [isValid, result] = await jwtVerifier.verify(token);
  expect(isValid).toBe(true);
  expect(result).toEqual(payload);
});

test('invalid signature', async () => {
  const jwtVerifier = jwt(secret, 'HS256');
  const payload = { sub: '123', exp: Math.floor(Date.now() / 1000) + 3600 };
  const token = await sign(payload, 'HS256', 'wrongsecret');
  const [isValid, result] = await jwtVerifier.verify(token);
  expect(isValid).toBe(false);
  expect(result).toEqual({ error: 'bad_signature' });
});

test('expired token', async () => {
  const jwtVerifier = jwt(secret, 'HS256');
  const payload = { sub: '123', exp: Math.floor(Date.now() / 1000) - 1 };
  const token = await sign(payload, 'HS256', secret);
  const [isValid, result] = await jwtVerifier.verify(token);
  expect(isValid).toBe(false);
  expect(result).toEqual({ error: 'expired' });
});

test('unsupported algorithm', async () => {
  const jwtVerifier = jwt(secret, 'HS256');
  const payload = { sub: '123' };
  const token = await sign(payload, 'HS512', secret); // Signed with HS512, verifier expects HS256
  const [isValid, result] = await jwtVerifier.verify(token);
  expect(isValid).toBe(false);
  expect(result).toEqual({ error: 'unsupported_algorithm' });
});

test('invalid token format', async () => {
  const jwtVerifier = jwt(secret, 'HS256');
  const invalidToken1 = 'header.payload'; // Missing signature
  const [isValid1, result1] = await jwtVerifier.verify(invalidToken1);
  expect(isValid1).toBe(false);
  expect(result1).toEqual({ error: 'invalid_format' });

  const invalidToken2 = 'header.payload.signature.extra'; // Too many parts
  const [isValid2, result2] = await jwtVerifier.verify(invalidToken2);
  expect(isValid2).toBe(false);
  expect(result2).toEqual({ error: 'invalid_format' });
});

test('malformed header', async () => {
  const jwtVerifier = jwt(secret, 'HS256');
  const malformedHeader = btoa('not json').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const payloadB64 = jsonToB64u({ sub: '123' });
  const signatureB64 = 'signature'; // Dummy signature
  const malformedToken = `${malformedHeader}.${payloadB64}.${signatureB64}`;
  const [isValid, result] = await jwtVerifier.verify(malformedToken);
  expect(isValid).toBe(false);
  expect(result).toEqual({ error: 'verification_failed' });
});

test('malformed payload', async () => {
  const jwtVerifier = jwt(secret, 'HS256');
  const headerB64 = jsonToB64u({ alg: 'HS256', typ: 'JWT' });
  const malformedPayload = btoa('not json').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const signatureB64 = 'signature'; // Dummy signature
  const malformedPayloadToken = `${headerB64}.${malformedPayload}.${signatureB64}`;
  const [isValid, result] = await jwtVerifier.verify(malformedPayloadToken);
  expect(isValid).toBe(false);
  expect(result).toEqual({ error: 'verification_failed' });
});

test('token with no expiration', async () => {
  const jwtVerifier = jwt(secret, 'HS256');
  const payload = { sub: '123' };
  const token = await sign(payload, 'HS256', secret);
  const [isValid, result] = await jwtVerifier.verify(token);
  expect(isValid).toBe(true);
  expect(result).toEqual(payload);
});


test('jwt.io default test vectors', async () => {
  const jwtVerifier = jwt("a-string-secret-at-least-256-bits-long", 'HS256');
  const tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"
  const [isValid, result] = await jwtVerifier.verify(tok);
  expect(isValid).toBe(true);
  expect(result).toEqual({ sub: '1234567890', name: 'John Doe', admin: true, iat: 1516239022 });
});