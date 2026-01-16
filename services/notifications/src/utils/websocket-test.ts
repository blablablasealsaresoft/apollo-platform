/**
 * Apollo Platform - WebSocket Test Utilities
 * Use this module to test and debug WebSocket event publishing
 *
 * Usage:
 * npx ts-node src/utils/websocket-test.ts [command]
 *
 * Commands:
 *   alert:critical   - Send a critical test alert
 *   alert:warning    - Send a warning test alert
 *   surveillance     - Send a test surveillance match
 *   blockchain       - Send a test blockchain transaction
 *   investigation    - Send a test investigation update
 *   operation        - Send a test operation status
 *   notification     - Send a test user notification
 *   stress           - Run stress test (100 events)
 */

import { redis } from '@apollo/shared';

// Redis channels
const CHANNELS = {
  ALERTS: 'events:alerts',
  SURVEILLANCE: 'events:surveillance',
  BLOCKCHAIN: 'events:blockchain',
  INVESTIGATIONS: 'events:investigations',
  OPERATIONS: 'events:operations',
  NOTIFICATIONS: 'events:notifications',
};

// Generate a random ID
const generateId = () => `test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

// Test data generators
const testAlerts = {
  critical: () => ({
    id: generateId(),
    type: 'security',
    severity: 'critical',
    title: 'CRITICAL: Test Alert',
    message: 'This is a critical test alert from the WebSocket test utility. Immediate action required.',
    source: 'websocket-test',
    actionRequired: true,
    relatedEntity: {
      type: 'target',
      id: 'target-001',
      name: 'Test Target',
    },
    location: {
      latitude: 42.3601,
      longitude: -71.0589,
      address: 'Boston, MA',
    },
    timestamp: new Date().toISOString(),
  }),
  warning: () => ({
    id: generateId(),
    type: 'intelligence',
    severity: 'warning',
    title: 'Warning: Test Alert',
    message: 'This is a warning test alert. Review when convenient.',
    source: 'websocket-test',
    actionRequired: false,
    timestamp: new Date().toISOString(),
  }),
  info: () => ({
    id: generateId(),
    type: 'system',
    severity: 'info',
    title: 'Info: Test Alert',
    message: 'This is an informational test alert.',
    source: 'websocket-test',
    actionRequired: false,
    timestamp: new Date().toISOString(),
  }),
};

const testSurveillanceMatch = () => ({
  matchId: generateId(),
  targetId: 'target-ruja-001',
  targetName: 'Ruja Ignatova',
  confidence: 0.87 + Math.random() * 0.12, // 87-99%
  sourceType: 'camera',
  sourceId: 'cam-dubai-001',
  sourceName: 'Dubai Marina Camera #47',
  imageUrl: 'https://example.com/surveillance/capture-001.jpg',
  timestamp: new Date().toISOString(),
  location: {
    latitude: 25.0657,
    longitude: 55.1313,
    address: 'Dubai Marina, UAE',
    venue: 'Marina Mall',
  },
  metadata: {
    cameraId: 'CCTV-DXB-M47',
    feedName: 'Dubai Marina Feed',
    ageEstimate: 44,
    disguiseDetected: false,
  },
});

const testBlockchainTransaction = () => ({
  transactionHash: `0x${generateId()}${generateId()}`,
  blockchain: 'ethereum',
  fromAddress: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
  toAddress: '0x9e8BAF21449eB5C59AF0831b5c4f1A3dA6a0A7E8',
  value: Math.random() * 100,
  currency: 'ETH',
  usdValue: Math.random() * 200000,
  timestamp: new Date().toISOString(),
  blockNumber: 18500000 + Math.floor(Math.random() * 1000),
  confirmations: Math.floor(Math.random() * 12),
  flags: Math.random() > 0.5 ? ['high_value', 'known_wallet'] : [],
  riskScore: Math.floor(Math.random() * 100),
  mixerDetected: Math.random() > 0.8,
  exchangeDetected: Math.random() > 0.5 ? { name: 'Binance', type: 'cex' as const } : undefined,
});

const testInvestigationUpdate = () => ({
  investigationId: 'inv-001',
  caseNumber: 'APOLLO-2024-001',
  title: 'OneCoin Investigation',
  updateType: 'evidence',
  newValue: { evidenceId: generateId(), type: 'document', title: 'New financial record discovered' },
  updatedBy: {
    id: 'user-001',
    name: 'Test Analyst',
  },
  timestamp: new Date().toISOString(),
  summary: 'New evidence has been added to the investigation.',
  teamMemberIds: ['user-001', 'user-002'],
});

const testOperationStatus = () => ({
  operationId: 'op-001',
  operationName: 'Operation Goldfish',
  codename: 'GOLDFISH',
  status: 'in_progress' as const,
  previousStatus: 'approved',
  updatedBy: {
    id: 'user-001',
    name: 'Field Commander',
  },
  timestamp: new Date().toISOString(),
  location: {
    latitude: 48.8566,
    longitude: 2.3522,
    address: 'Paris, France',
  },
  notes: 'Field team deployed. Surveillance established.',
  teamMemberIds: ['user-001', 'user-002', 'user-003'],
});

const testNotification = () => ({
  userId: 'user-001',
  type: 'message',
  title: 'Test Notification',
  message: 'This is a test notification from the WebSocket test utility.',
  actionUrl: '/dashboard',
});

// Publish to Redis
async function publish(channel: string, data: any): Promise<void> {
  await redis.publish(channel, JSON.stringify(data));
  console.log(`Published to ${channel}:`, JSON.stringify(data, null, 2));
}

// Commands
async function sendCriticalAlert(): Promise<void> {
  await publish(CHANNELS.ALERTS, testAlerts.critical());
}

async function sendWarningAlert(): Promise<void> {
  await publish(CHANNELS.ALERTS, testAlerts.warning());
}

async function sendSurveillanceMatch(): Promise<void> {
  await publish(CHANNELS.SURVEILLANCE, testSurveillanceMatch());
}

async function sendBlockchainTransaction(): Promise<void> {
  await publish(CHANNELS.BLOCKCHAIN, testBlockchainTransaction());
}

async function sendInvestigationUpdate(): Promise<void> {
  await publish(CHANNELS.INVESTIGATIONS, testInvestigationUpdate());
}

async function sendOperationStatus(): Promise<void> {
  await publish(CHANNELS.OPERATIONS, testOperationStatus());
}

async function sendNotification(): Promise<void> {
  await publish(CHANNELS.NOTIFICATIONS, testNotification());
}

async function stressTest(): Promise<void> {
  console.log('Starting stress test: 100 events...');
  const promises: Promise<void>[] = [];

  for (let i = 0; i < 25; i++) {
    promises.push(publish(CHANNELS.ALERTS, testAlerts.info()));
    promises.push(publish(CHANNELS.SURVEILLANCE, testSurveillanceMatch()));
    promises.push(publish(CHANNELS.BLOCKCHAIN, testBlockchainTransaction()));
    promises.push(publish(CHANNELS.NOTIFICATIONS, testNotification()));
  }

  await Promise.all(promises);
  console.log('Stress test complete: 100 events sent');
}

async function interactiveMode(): Promise<void> {
  const readline = await import('readline');
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  console.log('\nApollo WebSocket Test Utility - Interactive Mode');
  console.log('================================================');
  console.log('Commands:');
  console.log('  1. alert:critical  - Send critical alert');
  console.log('  2. alert:warning   - Send warning alert');
  console.log('  3. surveillance    - Send surveillance match');
  console.log('  4. blockchain      - Send blockchain transaction');
  console.log('  5. investigation   - Send investigation update');
  console.log('  6. operation       - Send operation status');
  console.log('  7. notification    - Send user notification');
  console.log('  8. stress          - Run stress test (100 events)');
  console.log('  9. exit            - Exit');
  console.log('');

  const question = (prompt: string): Promise<string> => {
    return new Promise((resolve) => {
      rl.question(prompt, resolve);
    });
  };

  while (true) {
    const cmd = await question('Enter command: ');

    try {
      switch (cmd.trim().toLowerCase()) {
        case '1':
        case 'alert:critical':
          await sendCriticalAlert();
          break;
        case '2':
        case 'alert:warning':
          await sendWarningAlert();
          break;
        case '3':
        case 'surveillance':
          await sendSurveillanceMatch();
          break;
        case '4':
        case 'blockchain':
          await sendBlockchainTransaction();
          break;
        case '5':
        case 'investigation':
          await sendInvestigationUpdate();
          break;
        case '6':
        case 'operation':
          await sendOperationStatus();
          break;
        case '7':
        case 'notification':
          await sendNotification();
          break;
        case '8':
        case 'stress':
          await stressTest();
          break;
        case '9':
        case 'exit':
        case 'quit':
          console.log('Goodbye!');
          rl.close();
          process.exit(0);
        default:
          console.log('Unknown command. Try again.');
      }
    } catch (error) {
      console.error('Error:', error);
    }
  }
}

// Main execution
async function main(): Promise<void> {
  try {
    await redis.connect();
    console.log('Connected to Redis');

    const args = process.argv.slice(2);

    if (args.length === 0) {
      await interactiveMode();
    } else {
      const cmd = args[0].toLowerCase();

      switch (cmd) {
        case 'alert:critical':
          await sendCriticalAlert();
          break;
        case 'alert:warning':
          await sendWarningAlert();
          break;
        case 'surveillance':
          await sendSurveillanceMatch();
          break;
        case 'blockchain':
          await sendBlockchainTransaction();
          break;
        case 'investigation':
          await sendInvestigationUpdate();
          break;
        case 'operation':
          await sendOperationStatus();
          break;
        case 'notification':
          await sendNotification();
          break;
        case 'stress':
          await stressTest();
          break;
        default:
          console.log(`Unknown command: ${cmd}`);
          console.log('Available commands: alert:critical, alert:warning, surveillance, blockchain, investigation, operation, notification, stress');
      }
    }

    await redis.disconnect();
  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

// Export functions for programmatic use
export {
  sendCriticalAlert,
  sendWarningAlert,
  sendSurveillanceMatch,
  sendBlockchainTransaction,
  sendInvestigationUpdate,
  sendOperationStatus,
  sendNotification,
  stressTest,
  testAlerts,
  testSurveillanceMatch,
  testBlockchainTransaction,
  testInvestigationUpdate,
  testOperationStatus,
  testNotification,
};

// Run if called directly
if (require.main === module) {
  main().catch(console.error);
}
