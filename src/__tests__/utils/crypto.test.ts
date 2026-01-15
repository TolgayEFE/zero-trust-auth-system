import {
  generateSecureRandom,
  generateUUID,
  generatePKCEChallenge,
  verifyPKCEChallenge,
  generateSessionId,
  hashPassword,
  verifyPassword,
  signData,
  verifySignature,
  encryptData,
  decryptData,
  generateRequestSignature,
  verifyRequestSignature,
} from '../../utils/crypto';

describe('Cryptography Utilities', () => {
  describe('generateSecureRandom', () => {
    it('should generate random string of specified length', () => {
      const random = generateSecureRandom(32);
      expect(typeof random).toBe('string');
      expect(random.length).toBeGreaterThan(0);
    });

    it('should generate unique strings', () => {
      const random1 = generateSecureRandom(32);
      const random2 = generateSecureRandom(32);
      expect(random1).not.toBe(random2);
    });

    it('should be URL-safe', () => {
      const random = generateSecureRandom(100);
      // base64url should not contain +, /, or =
      expect(random).not.toMatch(/[+/=]/);
    });
  });

  describe('generateUUID', () => {
    it('should generate valid UUID v4', () => {
      const uuid = generateUUID();
      const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      expect(uuid).toMatch(uuidRegex);
    });

    it('should generate unique UUIDs', () => {
      const uuid1 = generateUUID();
      const uuid2 = generateUUID();
      expect(uuid1).not.toBe(uuid2);
    });
  });

  describe('PKCE Challenge', () => {
    it('should generate valid PKCE challenge', () => {
      const challenge = generatePKCEChallenge();

      expect(challenge).toHaveProperty('codeVerifier');
      expect(challenge).toHaveProperty('codeChallenge');
      expect(challenge).toHaveProperty('codeChallengeMethod');
      expect(challenge.codeChallengeMethod).toBe('S256');
    });

    it('should verify valid PKCE challenge', () => {
      const challenge = generatePKCEChallenge();
      const isValid = verifyPKCEChallenge(
        challenge.codeVerifier,
        challenge.codeChallenge,
        challenge.codeChallengeMethod
      );
      expect(isValid).toBe(true);
    });

    it('should reject invalid PKCE challenge', () => {
      const challenge = generatePKCEChallenge();
      const isValid = verifyPKCEChallenge(
        'wrong-verifier',
        challenge.codeChallenge,
        challenge.codeChallengeMethod
      );
      expect(isValid).toBe(false);
    });

    it('should handle plain method', () => {
      const verifier = 'test-verifier';
      const isValid = verifyPKCEChallenge(verifier, verifier, 'plain');
      expect(isValid).toBe(true);
    });
  });

  describe('generateSessionId', () => {
    it('should generate session ID with prefix', () => {
      const sessionId = generateSessionId();
      expect(sessionId).toMatch(/^sess_/);
    });

    it('should generate unique session IDs', () => {
      const session1 = generateSessionId();
      const session2 = generateSessionId();
      expect(session1).not.toBe(session2);
    });
  });

  describe('Password Hashing', () => {
    it('should hash password', async () => {
      const password = 'SecurePassword123!';
      const hash = await hashPassword(password);

      expect(hash).toBeTruthy();
      expect(hash).not.toBe(password);
      expect(hash).toContain(':');
    });

    it('should verify correct password', async () => {
      const password = 'SecurePassword123!';
      const hash = await hashPassword(password);

      const isValid = await verifyPassword(password, hash);
      expect(isValid).toBe(true);
    });

    it('should reject incorrect password', async () => {
      const password = 'SecurePassword123!';
      const hash = await hashPassword(password);

      const isValid = await verifyPassword('WrongPassword', hash);
      expect(isValid).toBe(false);
    });

    it('should generate different hashes for same password', async () => {
      const password = 'SecurePassword123!';
      const hash1 = await hashPassword(password);
      const hash2 = await hashPassword(password);

      expect(hash1).not.toBe(hash2);
    });

    it('should handle invalid hash format', async () => {
      const isValid = await verifyPassword('password', 'invalid-hash');
      expect(isValid).toBe(false);
    });
  });

  describe('HMAC Signing', () => {
    it('should sign data', () => {
      const data = 'test-data';
      const secret = 'test-secret';

      const signature = signData(data, secret);
      expect(signature).toBeTruthy();
      expect(typeof signature).toBe('string');
    });

    it('should verify valid signature', () => {
      const data = 'test-data';
      const secret = 'test-secret';

      const signature = signData(data, secret);
      const isValid = verifySignature(data, signature, secret);
      expect(isValid).toBe(true);
    });

    it('should reject invalid signature', () => {
      const data = 'test-data';
      const secret = 'test-secret';

      const signature = signData(data, secret);
      const isValid = verifySignature('different-data', signature, secret);
      expect(isValid).toBe(false);
    });

    it('should reject signature with wrong secret', () => {
      const data = 'test-data';
      const signature = signData(data, 'secret1');
      const isValid = verifySignature(data, signature, 'secret2');
      expect(isValid).toBe(false);
    });
  });

  describe('AES Encryption', () => {
    it('should encrypt and decrypt data', () => {
      const plaintext = 'Sensitive data to encrypt';
      const key = 'encryption-key-32-chars-long!!';

      const encrypted = encryptData(plaintext, key);
      expect(encrypted).not.toBe(plaintext);

      const decrypted = decryptData(encrypted, key);
      expect(decrypted).toBe(plaintext);
    });

    it('should produce different ciphertext for same plaintext', () => {
      const plaintext = 'Test data';
      const key = 'test-key';

      const encrypted1 = encryptData(plaintext, key);
      const encrypted2 = encryptData(plaintext, key);

      expect(encrypted1).not.toBe(encrypted2);
    });

    it('should fail with wrong key', () => {
      const plaintext = 'Secret message';
      const encrypted = encryptData(plaintext, 'correct-key');

      expect(() => {
        decryptData(encrypted, 'wrong-key');
      }).toThrow();
    });

    it('should handle special characters', () => {
      const plaintext = '{"user": "test", "password": "p@ssw0rd!#$%"}';
      const key = 'test-key';

      const encrypted = encryptData(plaintext, key);
      const decrypted = decryptData(encrypted, key);

      expect(decrypted).toBe(plaintext);
    });
  });

  describe('Request Signature', () => {
    it('should generate valid request signature', () => {
      const method = 'POST';
      const path = '/api/users';
      const timestamp = Date.now();
      const body = '{"name": "test"}';
      const secret = 'request-secret';

      const signature = generateRequestSignature(method, path, timestamp, body, secret);
      expect(signature).toBeTruthy();
    });

    it('should verify valid request signature', () => {
      const method = 'POST';
      const path = '/api/users';
      const timestamp = Date.now();
      const body = '{"name": "test"}';
      const secret = 'request-secret';

      const signature = generateRequestSignature(method, path, timestamp, body, secret);
      const isValid = verifyRequestSignature(method, path, timestamp, body, signature, secret);

      expect(isValid).toBe(true);
    });

    it('should reject signature with expired timestamp', () => {
      const method = 'POST';
      const path = '/api/users';
      const oldTimestamp = Date.now() - 600000; // 10 minutes ago
      const body = '{"name": "test"}';
      const secret = 'request-secret';

      const signature = generateRequestSignature(method, path, oldTimestamp, body, secret);
      const isValid = verifyRequestSignature(
        method,
        path,
        oldTimestamp,
        body,
        signature,
        secret,
        300000 // 5 minute max age
      );

      expect(isValid).toBe(false);
    });

    it('should reject tampered request', () => {
      const method = 'POST';
      const path = '/api/users';
      const timestamp = Date.now();
      const body = '{"name": "test"}';
      const secret = 'request-secret';

      const signature = generateRequestSignature(method, path, timestamp, body, secret);
      const isValid = verifyRequestSignature(
        method,
        path,
        timestamp,
        '{"name": "hacked"}',
        signature,
        secret
      );

      expect(isValid).toBe(false);
    });
  });
});
