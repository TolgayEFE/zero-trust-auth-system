#!/usr/bin/env ts-node

import dotenv from 'dotenv';
import { scrypt, randomBytes } from 'crypto';
import { promisify } from 'util';
import { db } from '../src/db/connection';
import { userRepository } from '../src/db/repositories/UserRepository';
import { auditRepository } from '../src/db/repositories/AuditRepository';
import { v4 as uuidv4 } from 'uuid';

// Load env
dotenv.config();

const scryptAsync = promisify(scrypt);

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const MONGODB_DB_NAME = process.env.MONGODB_DB_NAME || 'zero-trust-auth';

async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString('hex');
  const derivedKey = (await scryptAsync(password, salt, 64)) as Buffer;
  return `${salt}:${derivedKey.toString('hex')}`;
}

async function seed() {
  console.log('Start database seeding...\n');

  try {
    // Connect to MongoDB
    console.log(`Connect to MongoDB at ${MONGODB_URI}...`);
    await db.connect(MONGODB_URI, MONGODB_DB_NAME);
    console.log('Connected to MongoDB\n');

    // Check existing data
    const existingUser = await userRepository.findByEmail('test@example.com');
    if (existingUser) {
      console.log('Warning: database already seeded. Skip.\n');
      return;
    }

    console.log('Create test users...\n');

    // Create test user
    console.log('  Create test user (test@example.com)...');
    const testPasswordHash = await hashPassword('password123');
    const testUser = await userRepository.create({
      email: 'test@example.com',
      username: 'testuser',
      passwordHash: testPasswordHash,
      roles: ['user'],
      permissions: ['read:own', 'write:own'],
    });
    console.log(`  Test user created (ID: ${testUser._id})`);

    // Create admin user
    console.log('  Create admin user (admin@example.com)...');
    const adminPasswordHash = await hashPassword('admin123');
    const adminUser = await userRepository.create({
      email: 'admin@example.com',
      username: 'admin',
      passwordHash: adminPasswordHash,
      roles: ['admin', 'user'],
      permissions: ['read:own', 'write:own', 'read:all', 'write:all', 'delete:all'],
    });
    console.log(`  Admin user created (ID: ${adminUser._id})`);

    // Create sample user
    console.log('  Create sample user (alice@example.com)...');
    const alicePasswordHash = await hashPassword('alice123');
    const aliceUser = await userRepository.create({
      email: 'alice@example.com',
      username: 'alice',
      passwordHash: alicePasswordHash,
      roles: ['user'],
      permissions: ['read:own', 'write:own'],
    });
    console.log(`  Sample user created (ID: ${aliceUser._id})\n`);

    // Create sample audit logs
    console.log('Create sample audit logs...\n');

    const sampleAuditLogs = [
      {
        auditId: uuidv4(),
        requestId: uuidv4(),
        userId: testUser._id,
        action: 'register',
        resource: '/auth/register',
        outcome: 'success' as const,
        metadata: {
          email: testUser.email,
          username: testUser.username,
        },
      },
      {
        auditId: uuidv4(),
        requestId: uuidv4(),
        userId: adminUser._id,
        action: 'register',
        resource: '/auth/register',
        outcome: 'success' as const,
        metadata: {
          email: adminUser.email,
          username: adminUser.username,
        },
      },
      {
        auditId: uuidv4(),
        requestId: uuidv4(),
        userId: testUser._id,
        action: 'authenticate',
        resource: '/auth/login',
        outcome: 'success' as const,
        metadata: {
          email: testUser.email,
        },
      },
    ];

    for (const auditData of sampleAuditLogs) {
      await auditRepository.create(auditData);
    }

    console.log(`  Created ${sampleAuditLogs.length} audit log entries\n`);

    console.log('Seeding done.\n');

    console.log('Summary:');
    console.log('  Users created: 3');
    console.log('    - test@example.com / password123 (role: user)');
    console.log('    - admin@example.com / admin123 (role: admin)');
    console.log('    - alice@example.com / alice123 (role: user)');
    console.log(`  Audit logs created: ${sampleAuditLogs.length}`);
    console.log('\nDatabase is ready.\n');

  } catch (error) {
    console.error('Seeding failed:', error);
    process.exit(1);
  } finally {
    // Close connection
    await db.disconnect();
    process.exit(0);
  }
}

// Run seed
seed();
