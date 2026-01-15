import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { randomBytes } from 'crypto';
import { hashPassword, verifyPassword } from '../utils/crypto';
import { logger } from '../utils/logger';

/**
 * MFA Service - Handles TOTP generation, verification, and backup codes
 */

const MFA_ISSUER = 'Zero-Trust Auth';
const BACKUP_CODE_LENGTH = 8;
const BACKUP_CODE_COUNT = 8;

/**
 * Generate a new MFA secret for a user
 */
export const generateMFASecret = (email: string): speakeasy.GeneratedSecret => {
  const secret = speakeasy.generateSecret({
    name: `${MFA_ISSUER} (${email})`,
    issuer: MFA_ISSUER,
    length: 32,
  });

  logger.debug({ email }, 'MFA secret generated');
  return secret;
};

/**
 * Generate QR code data URL for authenticator apps
 */
export const generateQRCodeDataURL = async (
  secret: string,
  email: string
): Promise<string> => {
  const otpauthUrl = speakeasy.otpauthURL({
    secret,
    label: email,
    issuer: MFA_ISSUER,
    encoding: 'base32',
  });

  try {
    const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl);
    logger.debug({ email }, 'QR code generated');
    return qrCodeDataUrl;
  } catch (error) {
    logger.error({ error, email }, 'Failed to generate QR code');
    throw new Error('Failed to generate QR code');
  }
};

/**
 * Verify a TOTP token
 */
export const verifyTOTP = (secret: string, token: string): boolean => {
  const verified = speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token,
    window: 2, // Allow 2 time steps before/after for clock drift
  });

  logger.debug({ verified, tokenLength: token.length }, 'TOTP verification attempt');
  return verified;
};

/**
 * Generate backup codes for account recovery
 */
export const generateBackupCodes = (): string[] => {
  const codes: string[] = [];

  for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
    const code = randomBytes(BACKUP_CODE_LENGTH / 2)
      .toString('hex')
      .toUpperCase()
      .match(/.{1,4}/g)
      ?.join('-') || '';
    codes.push(code);
  }

  logger.debug({ count: codes.length }, 'Backup codes generated');
  return codes;
};

/**
 * Hash backup codes before storage
 */
export const hashBackupCodes = async (codes: string[]): Promise<string[]> => {
  const hashedCodes = await Promise.all(
    codes.map(code => hashPassword(code))
  );

  logger.debug({ count: hashedCodes.length }, 'Backup codes hashed');
  return hashedCodes;
};

/**
 * Validate a backup code against stored hashed codes
 */
export const validateBackupCode = async (
  hashedCodes: string[],
  inputCode: string
): Promise<{ valid: boolean; usedIndex: number }> => {
  for (let i = 0; i < hashedCodes.length; i++) {
    const hashedCode = hashedCodes[i];
    if (!hashedCode) continue;
    const isValid = await verifyPassword(inputCode, hashedCode);
    if (isValid) {
      logger.info({ codeIndex: i }, 'Backup code validated successfully');
      return { valid: true, usedIndex: i };
    }
  }

  logger.warn('Backup code validation failed');
  return { valid: false, usedIndex: -1 };
};

/**
 * Remove a used backup code from the array
 */
export const removeUsedBackupCode = (
  hashedCodes: string[],
  usedIndex: number
): string[] => {
  if (usedIndex < 0 || usedIndex >= hashedCodes.length) {
    return hashedCodes;
  }

  const updatedCodes = [...hashedCodes];
  updatedCodes.splice(usedIndex, 1);

  logger.debug(
    { usedIndex, remaining: updatedCodes.length },
    'Backup code removed after use'
  );

  return updatedCodes;
};

/**
 * Check if backup codes are running low
 */
export const areBackupCodesLow = (codes: string[]): boolean => {
  const threshold = 3;
  return codes.length <= threshold;
};

export default {
  generateMFASecret,
  generateQRCodeDataURL,
  verifyTOTP,
  generateBackupCodes,
  hashBackupCodes,
  validateBackupCode,
  removeUsedBackupCode,
  areBackupCodesLow,
};
