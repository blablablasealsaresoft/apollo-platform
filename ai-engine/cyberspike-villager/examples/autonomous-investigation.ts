/**
 * Autonomous Investigation Example
 *
 * Demonstrates complete autonomous crypto crime investigation.
 * AI handles everything from reconnaissance to prosecution report.
 *
 * @example
 */

import { AIC2Controller } from '../core/ai-c2-controller';
import { CryptoCrimeHunter } from '../modules/crypto-crime-hunter';
import { PredatorTracker } from '../modules/predator-tracker';

/**
 * Example 1: Autonomous Crypto Exchange Investigation
 *
 * AI automatically:
 * - Discovers infrastructure
 * - Finds vulnerabilities
 * - Gains authorized access
 * - Extracts evidence
 * - Generates report
 */
async function cryptoExchangeInvestigation() {
  console.log('=== Autonomous Crypto Exchange Investigation ===\n');

  const cryptoHunter = new CryptoCrimeHunter();

  // Simple natural language command - AI does the rest
  const results = await cryptoHunter.investigate(
    'suspect-exchange.com',
    'WARRANT-2026-001',
    'full'  // Complete investigation
  );

  console.log('\n=== Investigation Results ===');
  console.log(`Infrastructure Discovered: ${results.infrastructure.subdomains.length} subdomains`);
  console.log(`Vulnerabilities Found: ${results.vulnerabilities.length}`);
  console.log(`Wallets Identified: ${results.wallets.length}`);
  console.log(`Operators Identified: ${results.operators.length}`);
  console.log(`Evidence Collected: ${results.evidence.length} items`);
  console.log(`\nReport: ${results.report}`);

  return results;
}

/**
 * Example 2: Natural Language Command
 *
 * Give AI a high-level objective, it figures out everything else.
 */
async function naturalLanguageOperation() {
  console.log('=== Natural Language Operation ===\n');

  const aiController = new AIC2Controller();

  const result = await aiController.executeNaturalLanguageCommand({
    command: `
      Investigate suspect-crypto-platform.com for evidence of money laundering.
      Gain admin access if possible, extract user database and transaction logs.
      Trace cryptocurrency flows to identify operators.
      Generate prosecution-ready report with chain of custody.
    `,
    authorization: 'COURT-ORDER-2026-001',
    mission: 'cryptocurrency-crime',
    preserveEvidence: true,
    priority: 'HIGH'
  });

  console.log('\n=== Operation Results ===');
  console.log(`Success: ${result.success}`);
  console.log(`Phases Completed: ${result.phasesCompleted.length}`);
  console.log(`Evidence Collected: ${result.evidence.length}`);
  console.log(`Adaptations Made: ${result.adaptations.length}`);

  if (result.defenseDetected.length > 0) {
    console.log(`\nDefenses Detected: ${result.defenseDetected.length}`);
    result.defenseDetected.forEach(defense => {
      console.log(`  - ${defense.type} (confidence: ${defense.confidence}%)`);
    });
  }

  console.log(`\nReport Summary:`);
  console.log(result.report.summary);

  return result;
}

/**
 * Example 3: Multi-Stage Operation
 *
 * Complex operation with multiple objectives.
 */
async function multiStageOperation() {
  console.log('=== Multi-Stage Criminal Investigation ===\n');

  const aiController = new AIC2Controller();

  const result = await aiController.executeNaturalLanguageCommand({
    command: `
      MULTI-STAGE OPERATION:

      Stage 1: Infrastructure Mapping
      - Map complete infrastructure of suspect-exchange.com
      - Identify all subdomains, services, and technologies
      - Find cloud services and CDN usage

      Stage 2: Vulnerability Analysis
      - Use BugTrace-AI for comprehensive security analysis
      - Identify exploitable vulnerabilities
      - Prioritize by severity and exploitability

      Stage 3: Authorized Exploitation
      - Check subdomain takeover opportunities with dnsReaper
      - Gain admin access using identified vulnerabilities
      - Maintain OPSEC and avoid detection

      Stage 4: Evidence Collection
      - Extract complete user database
      - Collect wallet private keys
      - Retrieve transaction logs
      - Capture admin communications

      Stage 5: Transaction Tracing
      - Trace all cryptocurrency transactions
      - Identify wallet owners
      - Map money flow network
      - Find real-world operators

      Stage 6: Operator Identification
      - Cross-reference wallet data with OSINT
      - Identify real-world identities
      - Locate physical addresses
      - Build prosecution profiles

      Stage 7: Evidence Preservation
      - Preserve all evidence with strict chain of custody
      - Encrypt sensitive data
      - Generate integrity checksums
      - Create audit trail

      Stage 8: Report Generation
      - Generate executive summary
      - Create detailed timeline
      - Compile evidence catalog
      - Prepare prosecution package
    `,
    authorization: 'FEDERAL-WARRANT-2026-001',
    mission: 'cryptocurrency-crime',
    timeLimit: '48h',
    preserveEvidence: true,
    priority: 'CRITICAL'
  });

  console.log('\n=== Multi-Stage Operation Results ===');
  console.log(`Overall Success: ${result.success}`);
  console.log(`Stages Completed: ${result.phasesCompleted.length}/8`);
  console.log(`Total Evidence: ${result.evidence.length} items`);
  console.log(`Execution Time: ${result.timeline.length} events`);

  console.log('\n=== Execution Timeline ===');
  result.timeline.forEach((event, index) => {
    console.log(`${index + 1}. ${event.timestamp.toISOString()} - ${event.action} (${event.result})`);
  });

  return result;
}

/**
 * Example 4: Predator Hunting Operation
 *
 * Critical priority operation to rescue victims.
 */
async function predatorHuntingOperation() {
  console.log('=== CRITICAL: Predator Hunting Operation ===\n');

  const predatorTracker = new PredatorTracker();

  const results = await predatorTracker.hunt({
    target: {
      username: 'suspect_user_123',
      platform: 'suspicious-chat-site.com',
      authorization: 'EMERGENCY-WARRANT-2026-001'
    },
    priority: 'CRITICAL'
  });

  console.log('\n=== Operation Results ===');
  console.log(`Platform Access: ${results.platformAccess ? 'GRANTED' : 'FAILED'}`);
  console.log(`Victims Identified: ${results.victimsIdentified.length}`);
  console.log(`Perpetrators Identified: ${results.perpetrators.length}`);
  console.log(`Communications Collected: ${results.communications.length}`);
  console.log(`Evidence Items: ${results.evidence.length}`);

  if (results.urgentActions.length > 0) {
    console.log('\n⚠️  URGENT ACTIONS REQUIRED:');
    results.urgentActions.forEach(action => {
      console.log(`  ❗ ${action}`);
    });
  }

  console.log(`\nReport: ${results.report}`);

  return results;
}

/**
 * Example 5: Adaptive Evasion
 *
 * Demonstrates AI adapting to defensive measures.
 */
async function adaptiveEvasionExample() {
  console.log('=== Adaptive Evasion Example ===\n');

  const aiController = new AIC2Controller();

  // Operation that encounters defenses
  const result = await aiController.executeNaturalLanguageCommand({
    command: `
      Investigate high-security-exchange.com (expects heavy defenses).

      Requirements:
      - Maximum OPSEC
      - Evade WAF, IDS, EDR
      - Adapt tactics if detected
      - Preserve evidence before burn if compromised
    `,
    authorization: 'WARRANT-2026-001',
    mission: 'cryptocurrency-crime',
    preserveEvidence: true,
    priority: 'HIGH'
  });

  console.log('\n=== Adaptive Evasion Results ===');
  console.log(`Defenses Encountered: ${result.defenseDetected.length}`);

  result.defenseDetected.forEach(defense => {
    console.log(`\nDefense: ${defense.type}`);
    console.log(`Confidence: ${defense.confidence}%`);
    console.log(`Indicators: ${defense.indicators.join(', ')}`);
  });

  console.log(`\nAdaptations Made: ${result.adaptations.length}`);
  result.adaptations.forEach(adaptation => {
    console.log(`\nTrigger: ${adaptation.trigger}`);
    console.log(`Original: ${adaptation.original}`);
    console.log(`Adapted: ${adaptation.adapted}`);
    console.log(`Success: ${adaptation.success ? 'Yes' : 'No'}`);
  });

  return result;
}

/**
 * Example 6: Supervised Mode
 *
 * AI proposes actions, waits for approval.
 */
async function supervisedOperation() {
  console.log('=== Supervised Operation Mode ===\n');

  const aiController = new AIC2Controller();

  // In supervised mode, AI would request approval for critical actions
  // This is simplified for demonstration

  console.log('AI Planning: Analyzing target...');
  console.log('AI Planning: Reconnaissance plan ready');
  console.log('  - BBOT recursive scan');
  console.log('  - SubHunterX rapid enumeration');
  console.log('  - CloudRecon certificate intelligence');
  console.log('\n[Operator: Approve? (yes)] yes');

  console.log('\nAI Executing: Reconnaissance...');
  console.log('AI Planning: Vulnerability analysis plan ready');
  console.log('  - BugTrace-AI deep scan');
  console.log('  - Nuclei template scanning');
  console.log('\n[Operator: Approve? (yes)] yes');

  console.log('\nAI Executing: Vulnerability analysis...');
  console.log('AI Planning: Exploitation plan ready');
  console.log('  ⚠️  Requires authorization for exploitation');
  console.log('  - SQL injection in admin panel');
  console.log('  - Subdomain takeover opportunity');
  console.log('\n[Operator: Approve exploitation? (yes/no)] yes');

  console.log('\nAI Executing: Authorized exploitation...');
  console.log('Operation complete!');
}

/**
 * Main execution
 */
async function main() {
  console.log('╔════════════════════════════════════════════════════╗');
  console.log('║   Cyberspike Villager - Autonomous Operations     ║');
  console.log('║   World\'s First AI-Native C2 Framework            ║');
  console.log('╚════════════════════════════════════════════════════╝\n');

  try {
    // Run example (uncomment one)

    // Example 1: Crypto investigation
    // await cryptoExchangeInvestigation();

    // Example 2: Natural language
    // await naturalLanguageOperation();

    // Example 3: Multi-stage operation
    // await multiStageOperation();

    // Example 4: Predator hunting
    // await predatorHuntingOperation();

    // Example 5: Adaptive evasion
    // await adaptiveEvasionExample();

    // Example 6: Supervised mode
    await supervisedOperation();

  } catch (error: any) {
    console.error('\n❌ Operation failed:', error.message);
    console.error(error.stack);
  }
}

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}

export {
  cryptoExchangeInvestigation,
  naturalLanguageOperation,
  multiStageOperation,
  predatorHuntingOperation,
  adaptiveEvasionExample,
  supervisedOperation
};
