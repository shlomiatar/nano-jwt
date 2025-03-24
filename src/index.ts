const [dec, enc] = [new TextDecoder(), new TextEncoder()];
const b64uToU8 = (s: string) => new Uint8Array(atob(s.replace(/-/g, '+').replace(/_/g, '/')).split('').map(c => c.charCodeAt(0)));
const b64uToJson = (s: string) => JSON.parse(dec.decode(b64uToU8(s)));

export const jwt = (secret: string, alg: 'HS256' | 'HS512') => {
    let _key: CryptoKey;
    const hash = `SHA-${alg.substring(2)}`;

    return {
      verify: async <T extends object>(token: string): Promise<[boolean, T | { error: string }]> => {
        try {
          _key = _key ?? await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash }, false, ['verify'])
          const [enc_alg, enc_payload, enc_sign, ...rest] = token.split('.');
          if (!enc_alg || !enc_payload || !enc_sign || rest.length) return [false, { error: 'invalid_format' }];
          if (b64uToJson(enc_alg).alg != alg) return [false, { error: 'unsupported_algorithm' }];
          if (!await crypto.subtle.verify('HMAC',_key, b64uToU8(enc_sign), enc.encode(`${enc_alg}.${enc_payload}`))) return [false, { error: 'bad_signature' }];
          const payload = b64uToJson(enc_payload);
          if (payload.exp && Date.now() >= payload.exp * 1000) return [false, { error: 'expired' }];
          return [true, payload as T];
        } catch {
          return [false, { error: 'verification_failed' }];
        }
      }
    }
};