/**
 * Example: AI Autonomously Uses 1000+ APIs
 *
 * This demonstrates how Cyberspike Villager AI can autonomously:
 * 1. Browse 1000+ API registry
 * 2. Select relevant APIs for mission
 * 3. Execute APIs in parallel
 * 4. Correlate results
 * 5. Generate intelligence reports
 * 6. Feed to Apollo fusion center
 *
 * @elite-engineering
 */

import { apiOrchestrator } from '../apollo-integration/api-orchestrator';

/**
 * Example 1: Simple Autonomous Investigation
 *
 * AI figures out which APIs to use - human just provides objective
 */
async function example1_SimpleInvestigation() {
  console.log('\n=== Example 1: Simple Autonomous Investigation ===\n');

  // Human provides only the objective
  // AI does EVERYTHING else
  const report = await apiOrchestrator.autonomousInvestigation(
    "Find everything about OneCoin cryptocurrency and Ruja Ignatova"
  );

  console.log('\nInvestigation Results:');
  console.log(JSON.stringify(report, null, 2));

  // AI automatically:
  // - Selected relevant APIs (crypto, gov, social, geo, etc.)
  // - Called all APIs in parallel
  // - Processed responses
  // - Correlated data
  // - Generated intelligence report
  // - Fed to Apollo fusion center
}

/**
 * Example 2: Mission-Specific Investigation
 *
 * AI uses mission context to prioritize APIs
 */
async function example2_MissionSpecific() {
  console.log('\n=== Example 2: Mission-Specific Investigation ===\n');

  const report = await apiOrchestrator.autonomousInvestigation(
    "Track recent OneCoin-related cryptocurrency movements and suspicious transactions",
    {
      mission: 'ignatova_hunt',
      priority: 'critical',
      categories: ['cryptocurrency', 'finance', 'government']
    }
  );

  console.log(`\nAPIs Used: ${report.apisUsed}`);
  console.log(`Findings: ${report.intelligence.findings.length}`);
  console.log(`Confidence: ${(report.intelligence.confidence * 100).toFixed(1)}%`);
}

/**
 * Example 3: Multi-Domain Intelligence Gathering
 *
 * AI gathers intelligence across multiple domains simultaneously
 */
async function example3_MultiDomain() {
  console.log('\n=== Example 3: Multi-Domain Intelligence ===\n');

  const report = await apiOrchestrator.autonomousInvestigation(
    `Comprehensive intelligence gathering on Ruja Ignatova:
     - Current location intelligence from IP tracking
     - Cryptocurrency activity monitoring
     - Social media mentions and discussions
     - Government database checks (FBI, Interpol)
     - Financial market activities
     - Transportation tracking (flights, yachts)`,
    {
      mission: 'ignatova_hunt',
      priority: 'critical'
    }
  );

  // AI selects APIs across all relevant categories
  console.log('\nCategories Covered:');
  const categories = new Set(
    report.rawResults.map(r => r.category)
  );
  categories.forEach(cat => console.log(`  - ${cat}`));

  console.log(`\nTotal Intelligence Sources: ${report.apisUsed}`);
}

/**
 * Example 4: Continuous Monitoring Deployment
 *
 * Deploy 24/7 autonomous monitoring using multiple APIs
 */
async function example4_ContinuousMonitoring() {
  console.log('\n=== Example 4: Deploy Continuous Monitoring ===\n');

  // Deploy continuous monitoring for Ignatova hunt
  await apiOrchestrator.deployContinuousMonitoring('ignatova_hunt', {
    frequency: 60, // Check every 60 seconds
    alertThreshold: 0.8, // Alert on high-confidence findings
    autoResponse: true // Automatically respond to alerts
  });

  console.log('✅ Continuous monitoring deployed');
  console.log('📡 Monitoring 20+ APIs every 60 seconds');
  console.log('🚨 Auto-alerts enabled');
  console.log('🤖 AI autonomous response enabled');

  // AI will now continuously:
  // - Monitor APIs every 60 seconds
  // - Detect changes and new intelligence
  // - Generate alerts on significant findings
  // - Automatically respond to critical alerts
  // - Feed all intelligence to Apollo fusion center
}

/**
 * Example 5: Keyword-Based Monitoring
 *
 * Monitor for specific keywords across 1000+ APIs
 */
async function example5_KeywordMonitoring() {
  console.log('\n=== Example 5: Keyword-Based Monitoring ===\n');

  const report = await apiOrchestrator.autonomousInvestigation(
    "Monitor all sources for mentions of: onecoin, ruja ignatova, cryptoqueen, ponzi scheme",
    {
      keywords: ['onecoin', 'ruja ignatova', 'cryptoqueen', 'ponzi', 'pyramid scheme'],
      priority: 'high'
    }
  );

  console.log('\nKeyword Hits:');
  report.intelligence.findings.forEach((finding: any) => {
    if (finding.keywords) {
      console.log(`  [${finding.source}] ${finding.keywords.join(', ')}`);
    }
  });
}

/**
 * Example 6: Geographic Intelligence Focus
 *
 * Focus on geolocation and movement tracking
 */
async function example6_GeoIntelligence() {
  console.log('\n=== Example 6: Geographic Intelligence ===\n');

  const report = await apiOrchestrator.autonomousInvestigation(
    "Track all IP addresses and locations associated with OneCoin network",
    {
      categories: ['geolocation', 'transportation'],
      priority: 'critical'
    }
  );

  console.log('\nHigh-Confidence Locations:');
  report.intelligence.findings
    .filter((f: any) => f.type === 'location' && f.confidence > 0.8)
    .forEach((f: any) => {
      console.log(`  📍 ${f.location} (${(f.confidence * 100).toFixed(1)}% confidence)`);
      console.log(`     Action: ${f.recommended_action || 'Monitor'}`);
    });
}

/**
 * Example 7: Real-World Complete Investigation
 *
 * This is how Apollo would actually use the system in production
 */
async function example7_ProductionUsage() {
  console.log('\n=== Example 7: Production Investigation ===\n');
  console.log('🎯 MISSION: Hunt for Ruja Ignatova\n');

  // Step 1: Initial intelligence sweep
  console.log('Step 1: Initial intelligence sweep across all sources...');
  const initialReport = await apiOrchestrator.autonomousInvestigation(
    "Comprehensive intelligence sweep on Ruja Ignatova and OneCoin network",
    {
      mission: 'ignatova_hunt',
      priority: 'critical'
    }
  );

  console.log(`✅ Initial sweep complete: ${initialReport.intelligence.findings.length} findings`);

  // Step 2: Deploy continuous monitoring
  console.log('\nStep 2: Deploying continuous monitoring...');
  await apiOrchestrator.deployContinuousMonitoring('ignatova_hunt', {
    frequency: 60,
    alertThreshold: 0.8,
    autoResponse: true
  });

  console.log('✅ Continuous monitoring active');

  // Step 3: Set up alert handlers
  console.log('\nStep 3: Alert handlers configured');
  console.log('  - High-confidence location → Deploy surveillance');
  console.log('  - Large crypto transaction → Investigate');
  console.log('  - FBI status update → Immediate review');
  console.log('  - Social media sighting → Verify and track');

  console.log('\n🚀 System fully operational and autonomous!');
  console.log('📊 Intelligence flows continuously to Apollo fusion center');
  console.log('🤖 AI handles all API selection and execution');
  console.log('⚡ Zero human intervention required');
}

/**
 * Main execution
 */
async function main() {
  console.log('\n' + '='.repeat(80));
  console.log('     APOLLO PLATFORM - PUBLIC APIS INTEGRATION');
  console.log('     AI-Powered Autonomous Intelligence Gathering');
  console.log('='.repeat(80));

  // Run examples
  try {
    await example1_SimpleInvestigation();
    await example2_MissionSpecific();
    await example3_MultiDomain();
    await example4_ContinuousMonitoring();
    await example5_KeywordMonitoring();
    await example6_GeoIntelligence();
    await example7_ProductionUsage();

  } catch (error) {
    console.error('Error:', error);
  }

  console.log('\n' + '='.repeat(80));
  console.log('Examples complete!');
  console.log('='.repeat(80) + '\n');
}

// Run if executed directly
if (require.main === module) {
  main();
}

export {
  example1_SimpleInvestigation,
  example2_MissionSpecific,
  example3_MultiDomain,
  example4_ContinuousMonitoring,
  example5_KeywordMonitoring,
  example6_GeoIntelligence,
  example7_ProductionUsage
};
