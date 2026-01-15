import crypto from 'crypto';
import { PKCEChallenge } from '../types';

/**
 * Generate a cryptographically secure random string
 */
export const generateSecureRandom = (length: number = 32): string => {
  return crypto.randomBytes(length).toString('base64url');
};

/**
 * Generate a UUID v4
 */
export const generateUUID = (): string => {
  return crypto.randomUUID();
};

/**
 * Generate PKCE code verifier and challenge
 */
export const generatePKCEChallenge = (length: number = 128): PKCEChallenge => {
  // Generate code verifier (43-128 characters)
  const codeVerifier = generateSecureRandom(Math.min(Math.max(length, 43), 128));

  // Generate code challenge using S256 method
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: 'S256',
  };
};

/**
 * Verify PKCE code challenge
 */
export const verifyPKCEChallenge = (
  codeVerifier: string,
  codeChallenge: string,
  method: 'S256' | 'plain' = 'S256'
): boolean => {
  if (method === 'plain') {
    return codeVerifier === codeChallenge;
  }

  const computedChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  return computedChallenge === codeChallenge;
};

/**
 * Generate a secure session ID
 */
export const generateSessionId = (): string => {
  return `sess_${generateSecureRandom(32)}`;
};

/**
 * Generate a secure state parameter for OAuth
 */
export const generateOAuthState = (): string => {
  return generateSecureRandom(32);
};

/**
 * Generate a nonce for OIDC
 */
export const generateNonce = (): string => {
  return generateSecureRandom(24);
};

/**
 * Hash a password using bcrypt-compatible method
 */
export const hashPassword = (password: string, rounds: number = 12): Promise<string> => {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) reject(err);
      resolve(`${salt}:${derivedKey.toString('hex')}`);
    });
  });
};

/**
 * Verify a password hash
 */
export const verifyPassword = (password: string, hash: string): Promise<boolean> => {
  return new Promise((resolve, reject) => {
    const [salt, key] = hash.split(':');
    if (!salt || !key) {
      resolve(false);
      return;
    }
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) reject(err);
      resolve(crypto.timingSafeEqual(Buffer.from(key, 'hex'), derivedKey));
    });
  });
};

/**
 * Generate a device fingerprint
 */
export const generateDeviceFingerprint = (
  userAgent: string,
  ip: string,
  additionalData?: Record<string, string>
): string => {
  const data = {
    userAgent,
    ip,
    ...additionalData,
  };

  return crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
};

/**
 * Sign data with HMAC
 */
export const signData = (data: string, secret: string): string => {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
};

/**
 * Verify HMAC signature
 */
export const verifySignature = (data: string, signature: string, secret: string): boolean => {
  const expectedSignature = signData(data, secret);
  return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expectedSignature, 'hex'));
};

/**
 * Encrypt data using AES-256-GCM
 */
export const encryptData = (data: string, key: string): string => {
  const iv = crypto.randomBytes(12);
  const keyBuffer = crypto.scryptSync(key, 'salt', 32);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);

  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
};

/**
 * Decrypt data using AES-256-GCM
 */
export const decryptData = (encryptedData: string, key: string): string => {
  const parts = encryptedData.split(':');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted data format');
  }

  const [ivHex, authTagHex, encrypted] = parts;
  const iv = Buffer.from(ivHex!, 'hex');
  const authTag = Buffer.from(authTagHex!, 'hex');
  const keyBuffer = crypto.scryptSync(key, 'salt', 32);

  const decipher = crypto.createDecipheriv('aes-256-gcm', keyBuffer, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encrypted!, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
};

/**
 * Generate a request signature for inter-service communication
 */
export const generateRequestSignature = (
  method: string,
  path: string,
  timestamp: number,
  body: string,
  secret: string
): string => {
  const payload = `${method}|${path}|${timestamp}|${body}`;
  return signData(payload, secret);
};

/**
 * Verify request signature
 */
export const verifyRequestSignature = (
  method: string,
  path: string,
  timestamp: number,
  body: string,
  signature: string,
  secret: string,
  maxAgeMs: number = 300000 // 5 minutes
): boolean => {
  // Check timestamp freshness
  const now = Date.now();
  if (Math.abs(now - timestamp) > maxAgeMs) {
    return false;
  }

  const payload = `${method}|${path}|${timestamp}|${body}`;
  return verifySignature(payload, signature, secret);
};
