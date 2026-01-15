#!/usr/bin/env ts-node

import dotenv from 'dotenv';
import { db } from '../src/db/connection';
import { User } from '../src/db/models/User';
import { Session } from '../src/db/models/Session';
import { BlacklistedToken } from '../src/db/models/BlacklistedToken';
import { AuditLog } from '../src/db/models/AuditLog';

// Load env
dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const MONGODB_DB_NAME = process.env.MONGODB_DB_NAME || 'zero-trust-auth';

async function migrate() {
  console.log('Starting database migration...\n');

  try {
    // Connect to MongoDB
    console.log(`Connecting to MongoDB at ${MONGODB_URI}...`);
    await db.connect(MONGODB_URI, MONGODB_DB_NAME);
    console.log('Connected to MongoDB\n');

    // Check database health
    console.log('Checking database health...');
    const pingTime = await db.ping();
    console.log(`Database is healthy (ping: ${pingTime}ms)\n`);

    // Create indexes
    console.log('Creating indexes...');

    console.log('  - Creating User indexes...');
    await User.createIndexes();

    console.log('  - Creating Session indexes...');
    await Session.createIndexes();

    console.log('  - Creating BlacklistedToken indexes...');
    await BlacklistedToken.createIndexes();

    console.log('  - Creating AuditLog indexes...');
    await AuditLog.createIndexes();

    console.log('All indexes created\n');

    // Validate collections
    console.log('Validating collections...');
    const dbConnection = db.getConnection().connection.db;
    if (dbConnection) {
      const collections = await dbConnection.listCollections().toArray();
      const collectionNames = collections.map(c => c.name);

      console.log(`  Found ${collections.length} collections:`);
      collectionNames.forEach(name => console.log(`    - ${name}`));
      console.log();

      // Get database stats
      console.log('Database statistics:');
      const stats = await dbConnection.stats();
      console.log(`  - Database: ${stats.db}`);
      console.log(`  - Collections: ${stats.collections}`);
      console.log(`  - Data Size: ${(stats.dataSize / 1024 / 1024).toFixed(2)} MB`);
      console.log(`  - Storage Size: ${(stats.storageSize / 1024 / 1024).toFixed(2)} MB`);
      console.log();
    } else {
      console.warn('  Warning: unable to validate collections - database not ready');
    }

    console.log('Migration completed.');
    console.log('\nDatabase is ready.\n');

  } catch (error) {
    console.error('Migration failed:', error);
    process.exit(1);
  } finally {
    // Close connection
    await db.disconnect();
    process.exit(0);
  }
}

// Run migration
migrate();
