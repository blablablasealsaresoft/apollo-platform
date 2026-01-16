/**
 * Test Data Generator for Apollo Platform
 * Generates realistic test data for all testing scenarios
 */

import { faker } from '@faker-js/faker';
import * as crypto from 'crypto';

// User Roles
export enum UserRole {
  ADMIN = 'ADMIN',
  SUPERVISOR = 'SUPERVISOR',
  ANALYST = 'ANALYST',
  INVESTIGATOR = 'INVESTIGATOR',
  VIEWER = 'VIEWER',
}

// Clearance Levels
export enum ClearanceLevel {
  UNCLASSIFIED = 'UNCLASSIFIED',
  CONFIDENTIAL = 'CONFIDENTIAL',
  SECRET = 'SECRET',
  TOP_SECRET = 'TOP_SECRET',
}

// Investigation Priority
export enum Priority {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

// Investigation Status
export enum InvestigationStatus {
  DRAFT = 'DRAFT',
  ACTIVE = 'ACTIVE',
  UNDER_REVIEW = 'UNDER_REVIEW',
  SUSPENDED = 'SUSPENDED',
  CLOSED = 'CLOSED',
}

// Target Type
export enum TargetType {
  PERSON = 'PERSON',
  ORGANIZATION = 'ORGANIZATION',
  VEHICLE = 'VEHICLE',
  LOCATION = 'LOCATION',
  DIGITAL_ASSET = 'DIGITAL_ASSET',
}

// Evidence Type
export enum EvidenceType {
  DOCUMENT = 'DOCUMENT',
  IMAGE = 'IMAGE',
  VIDEO = 'VIDEO',
  AUDIO = 'AUDIO',
  FINANCIAL_DOCUMENT = 'FINANCIAL_DOCUMENT',
  COMMUNICATION = 'COMMUNICATION',
  DIGITAL_EVIDENCE = 'DIGITAL_EVIDENCE',
}

/**
 * Generate mock user
 */
export function generateUser(overrides?: Partial<any>) {
  return {
    id: faker.string.uuid(),
    email: faker.internet.email(),
    firstName: faker.person.firstName(),
    lastName: faker.person.lastName(),
    role: faker.helpers.enumValue(UserRole),
    department: faker.helpers.arrayElement([
      'INVESTIGATIONS',
      'INTELLIGENCE',
      'OPERATIONS',
      'ADMINISTRATION',
      'TECHNICAL',
    ]),
    clearanceLevel: faker.helpers.enumValue(ClearanceLevel),
    badge: faker.string.alphanumeric(8).toUpperCase(),
    phone: faker.phone.number(),
    createdAt: faker.date.past(),
    lastLogin: faker.date.recent(),
    isActive: true,
    ...overrides,
  };
}

/**
 * Generate mock investigation
 */
export function generateInvestigation(overrides?: Partial<any>) {
  const year = new Date().getFullYear();
  const caseNum = faker.number.int({ min: 1, max: 9999 }).toString().padStart(4, '0');

  return {
    id: faker.string.uuid(),
    caseNumber: `CASE-${year}-${caseNum}`,
    title: faker.helpers.arrayElement([
      'Cryptocurrency Fraud Investigation',
      'Money Laundering Operation',
      'Identity Theft Ring',
      'Organized Crime Syndicate',
      'International Drug Trafficking',
      'Cybercrime Investigation',
      'Human Trafficking Network',
      'Financial Fraud Scheme',
    ]),
    description: faker.lorem.paragraph(),
    priority: faker.helpers.enumValue(Priority),
    status: faker.helpers.enumValue(InvestigationStatus),
    classification: faker.helpers.enumValue(ClearanceLevel),
    leadInvestigator: faker.person.fullName(),
    assignedAnalysts: Array.from({ length: faker.number.int({ min: 1, max: 5 }) }, () =>
      faker.person.fullName()
    ),
    startDate: faker.date.past(),
    expectedCloseDate: faker.date.future(),
    actualCloseDate: null,
    tags: faker.helpers.arrayElements(
      ['cryptocurrency', 'fraud', 'money-laundering', 'organized-crime', 'cybercrime'],
      { min: 1, max: 3 }
    ),
    createdAt: faker.date.past(),
    updatedAt: faker.date.recent(),
    ...overrides,
  };
}

/**
 * Generate mock target/suspect
 */
export function generateTarget(overrides?: Partial<any>) {
  return {
    id: faker.string.uuid(),
    investigationId: faker.string.uuid(),
    name: faker.person.fullName(),
    aliases: Array.from({ length: faker.number.int({ min: 0, max: 3 }) }, () =>
      faker.person.fullName()
    ),
    type: TargetType.PERSON,
    riskLevel: faker.helpers.enumValue(Priority),
    dateOfBirth: faker.date.birthdate({ min: 18, max: 80, mode: 'age' }),
    nationality: faker.location.country(),
    knownAddresses: Array.from({ length: faker.number.int({ min: 1, max: 3 }) }, () => ({
      street: faker.location.streetAddress(),
      city: faker.location.city(),
      state: faker.location.state(),
      country: faker.location.country(),
      zipCode: faker.location.zipCode(),
    })),
    phoneNumbers: Array.from({ length: faker.number.int({ min: 1, max: 3 }) }, () =>
      faker.phone.number()
    ),
    emailAddresses: Array.from({ length: faker.number.int({ min: 1, max: 3 }) }, () =>
      faker.internet.email()
    ),
    cryptoWallets: Array.from({ length: faker.number.int({ min: 0, max: 5 }) }, () => ({
      type: faker.helpers.arrayElement(['Bitcoin', 'Ethereum', 'Monero', 'Tether']),
      address: faker.string.alphanumeric(40),
    })),
    knownAssociates: Array.from({ length: faker.number.int({ min: 0, max: 5 }) }, () =>
      faker.person.fullName()
    ),
    notes: faker.lorem.paragraph(),
    status: faker.helpers.arrayElement(['ACTIVE', 'AT_LARGE', 'APPREHENDED', 'DECEASED']),
    lastKnownLocation: {
      latitude: faker.location.latitude(),
      longitude: faker.location.longitude(),
      city: faker.location.city(),
      timestamp: faker.date.recent(),
    },
    createdAt: faker.date.past(),
    updatedAt: faker.date.recent(),
    ...overrides,
  };
}

/**
 * Generate mock evidence
 */
export function generateEvidence(overrides?: Partial<any>) {
  return {
    id: faker.string.uuid(),
    investigationId: faker.string.uuid(),
    type: faker.helpers.enumValue(EvidenceType),
    filename: `${faker.system.fileName()}.${faker.helpers.arrayElement(['pdf', 'jpg', 'png', 'mp4', 'doc'])}`,
    originalFilename: faker.system.fileName(),
    description: faker.lorem.sentence(),
    fileSize: faker.number.int({ min: 1024, max: 10485760 }), // 1KB to 10MB
    mimeType: faker.system.mimeType(),
    hash: crypto.randomBytes(32).toString('hex'),
    uploadedBy: faker.person.fullName(),
    uploadedAt: faker.date.recent(),
    metadata: {
      captureDate: faker.date.recent(),
      location: faker.location.city(),
      device: faker.helpers.arrayElement(['Camera', 'Phone', 'Scanner', 'Computer']),
    },
    tags: faker.helpers.arrayElements(
      ['financial', 'communication', 'surveillance', 'forensic', 'digital'],
      { min: 1, max: 3 }
    ),
    classification: faker.helpers.enumValue(ClearanceLevel),
    chainOfCustody: [
      {
        action: 'UPLOADED',
        by: faker.person.fullName(),
        timestamp: faker.date.recent(),
      },
    ],
    ...overrides,
  };
}

/**
 * Generate mock blockchain transaction
 */
export function generateBlockchainTransaction(overrides?: Partial<any>) {
  return {
    id: faker.string.uuid(),
    txHash: faker.string.alphanumeric(64),
    blockchain: faker.helpers.arrayElement(['Bitcoin', 'Ethereum', 'Monero', 'Litecoin']),
    fromAddress: faker.string.alphanumeric(40),
    toAddress: faker.string.alphanumeric(40),
    amount: faker.number.float({ min: 0.001, max: 1000, precision: 0.00000001 }),
    amountUSD: faker.number.float({ min: 1, max: 50000, precision: 0.01 }),
    fee: faker.number.float({ min: 0.0001, max: 0.1, precision: 0.00000001 }),
    confirmations: faker.number.int({ min: 0, max: 100 }),
    blockHeight: faker.number.int({ min: 700000, max: 800000 }),
    timestamp: faker.date.recent(),
    suspicious: faker.datatype.boolean(),
    riskScore: faker.number.float({ min: 0, max: 1, precision: 0.01 }),
    tags: faker.helpers.arrayElements(['mixer', 'exchange', 'darknet', 'gambling'], {
      min: 0,
      max: 2,
    }),
    ...overrides,
  };
}

/**
 * Generate mock facial recognition match
 */
export function generateFacialRecognitionMatch(overrides?: Partial<any>) {
  return {
    id: faker.string.uuid(),
    targetId: faker.string.uuid(),
    cameraId: faker.string.alphanumeric(10),
    location: {
      name: faker.location.street(),
      city: faker.location.city(),
      country: faker.location.country(),
      latitude: faker.location.latitude(),
      longitude: faker.location.longitude(),
    },
    timestamp: faker.date.recent(),
    confidence: faker.number.float({ min: 0.85, max: 0.99, precision: 0.01 }),
    imageUrl: faker.image.url(),
    faceCoordinates: {
      x: faker.number.int({ min: 0, max: 1920 }),
      y: faker.number.int({ min: 0, max: 1080 }),
      width: faker.number.int({ min: 100, max: 300 }),
      height: faker.number.int({ min: 100, max: 300 }),
    },
    alertSent: faker.datatype.boolean(),
    reviewedBy: faker.person.fullName(),
    reviewedAt: faker.date.recent(),
    confirmed: faker.datatype.boolean(),
    ...overrides,
  };
}

/**
 * Generate batch test data
 */
export function generateTestDataset() {
  const users = Array.from({ length: 20 }, () => generateUser());
  const investigations = Array.from({ length: 50 }, () => generateInvestigation());
  const targets = investigations.flatMap((inv) =>
    Array.from({ length: faker.number.int({ min: 1, max: 5 }) }, () =>
      generateTarget({ investigationId: inv.id })
    )
  );
  const evidence = investigations.flatMap((inv) =>
    Array.from({ length: faker.number.int({ min: 2, max: 10 }) }, () =>
      generateEvidence({ investigationId: inv.id })
    )
  );
  const transactions = targets.flatMap((target) =>
    Array.from({ length: faker.number.int({ min: 5, max: 20 }) }, () =>
      generateBlockchainTransaction()
    )
  );
  const facialMatches = targets.flatMap((target) =>
    Array.from({ length: faker.number.int({ min: 0, max: 3 }) }, () =>
      generateFacialRecognitionMatch({ targetId: target.id })
    )
  );

  return {
    users,
    investigations,
    targets,
    evidence,
    transactions,
    facialMatches,
  };
}

/**
 * Export test dataset to JSON
 */
export function exportTestDataset(filepath: string): void {
  const dataset = generateTestDataset();
  const fs = require('fs');
  fs.writeFileSync(filepath, JSON.stringify(dataset, null, 2));
  console.log(`Test dataset exported to ${filepath}`);
}
