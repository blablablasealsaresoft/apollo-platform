/**
 * BugTrace-AI Example: Crypto Exchange Analysis
 *
 * Comprehensive security analysis of a cryptocurrency exchange platform.
 * This example demonstrates how to use BugTrace-AI for Apollo's crypto crime investigations.
 *
 * @module examples/crypto-exchange-analysis
 * @author Apollo Platform
 */

import { AIOrchestrator } from '../src/core/ai-orchestrator';
import { URLAnalyzer } from '../src/analyzers/url-analysis';
import { PayloadForge } from '../src/payload/payload-forge';
import { ReportGenerator } from '../src/utils/report-generator';

/**
 * Analyze a suspected criminal cryptocurrency exchange
 */
export async function analyzeCryptoExchange(url: string) {
  console.log('═══════════════════════════════════════════════════════');
  console.log('   CRYPTO EXCHANGE SECURITY ANALYSIS');
  console.log('═══════════════════════════════════════════════════════');
  console.log(`Target: ${url}`);
  console.log('Mission: Identify vulnerabilities for authorized law enforcement action\n');

  // Initialize BugTrace-AI with recommended settings
  const orchestrator = new AIOrchestrator({
    provider: 'google',
    model: 'gemini-flash'
  });

  // Step 1: Comprehensive vulnerability analysis
  console.log('[Step 1/5] Running multi-persona vulnerability analysis...');
  const analysisResult = await orchestrator.analyze(
    {
      url,
      focus: [
        'authentication',
        'wallet-manipulation',
        'admin-access',
        'database-exposure',
        'api-vulnerabilities'
      ],
      context: 'Cryptocurrency exchange platform - suspected illegal operations'
    },
    {
      depth: 5,  // Use all 5 personas for maximum accuracy
      enableConsolidation: true,
      enableDeepAnalysis: true,
      model: {
        provider: 'google',
        model: 'gemini-flash'
      }
    }
  );

  // Step 2: URL/Endpoint analysis
  console.log('\n[Step 2/5] Performing DAST analysis...');
  const urlAnalyzer = new URLAnalyzer();
  const dastResult = await urlAnalyzer.analyze({
    url,
    mode: 'active',  // Active scanning for comprehensive testing
    depth: 20,
    focus: [
      'authentication bypass',
      'SQL injection',
      'admin panel access',
      'wallet API vulnerabilities'
    ]
  });

  // Step 3: Generate exploitation payloads
  console.log('\n[Step 3/5] Generating exploitation payloads...');
  const payloadForge = new PayloadForge();

  const sqliPayloads = payloadForge.generate({
    type: 'sqli',
    base: "' OR '1'='1",
    target: 'ModSecurity',  // Common WAF on crypto exchanges
    variations: 20
  });

  const xssPayloads = payloadForge.generate({
    type: 'xss',
    target: 'Cloudflare',
    variations: 15
  });

  // Step 4: Identify critical attack paths
  console.log('\n[Step 4/5] Identifying exploitation paths...');
  const criticalFindings = analysisResult.findings.filter(
    f => f.severity === 'critical' || f.severity === 'high'
  );

  const attackPaths = criticalFindings.map(finding => ({
    vulnerability: finding.title,
    severity: finding.severity,
    exploitation: finding.exploitation,
    poc: finding.poc,
    impact: finding.impact,
    // Prioritize findings that enable:
    // 1. Admin access
    // 2. Database compromise
    // 3. Wallet manipulation
    priority: calculatePriority(finding)
  })).sort((a, b) => b.priority - a.priority);

  // Step 5: Generate comprehensive report
  console.log('\n[Step 5/5] Generating mission report...');
  const reportGenerator = new ReportGenerator();
  const report = reportGenerator.generate(analysisResult, 'markdown');
  const executiveSummary = reportGenerator.generateExecutiveSummary(analysisResult);

  // Compile results for Apollo Platform
  const missionResults = {
    target: url,
    timestamp: new Date().toISOString(),
    summary: executiveSummary,
    vulnerabilities: {
      total: analysisResult.summary.totalFindings,
      critical: analysisResult.summary.criticalCount,
      high: analysisResult.summary.highCount,
      breakdown: analysisResult.findings
    },
    attackPaths: attackPaths.slice(0, 5),  // Top 5 attack vectors
    exploitationTools: {
      sqliPayloads: sqliPayloads.length,
      xssPayloads: xssPayloads.length
    },
    recommendations: generateRecommendations(analysisResult),
    fullReport: report
  };

  console.log('\n═══════════════════════════════════════════════════════');
  console.log('   ANALYSIS COMPLETE');
  console.log('═══════════════════════════════════════════════════════');
  console.log(`Total Vulnerabilities: ${missionResults.vulnerabilities.total}`);
  console.log(`Critical: ${missionResults.vulnerabilities.critical}`);
  console.log(`High: ${missionResults.vulnerabilities.high}`);
  console.log(`Top Attack Paths: ${missionResults.attackPaths.length}`);
  console.log('═══════════════════════════════════════════════════════\n');

  return missionResults;
}

/**
 * Calculate priority score for law enforcement action
 */
function calculatePriority(finding: any): number {
  let score = 0;

  // Severity weight
  if (finding.severity === 'critical') score += 100;
  else if (finding.severity === 'high') score += 50;
  else if (finding.severity === 'medium') score += 25;

  // Impact weight
  if (finding.title.toLowerCase().includes('admin')) score += 50;
  if (finding.title.toLowerCase().includes('database')) score += 40;
  if (finding.title.toLowerCase().includes('wallet')) score += 45;
  if (finding.title.toLowerCase().includes('authentication')) score += 40;
  if (finding.title.toLowerCase().includes('sql')) score += 35;

  // Confidence weight
  score += (finding.confidence / 10);

  return score;
}

/**
 * Generate operational recommendations for law enforcement
 */
function generateRecommendations(result: any): string[] {
  const recommendations: string[] = [];

  if (result.summary.criticalCount > 0) {
    recommendations.push('IMMEDIATE ACTION: Critical vulnerabilities found - coordinate with legal team for warrant');
    recommendations.push('Prioritize admin panel access vulnerabilities for evidence collection');
  }

  if (result.findings.some((f: any) => f.title.toLowerCase().includes('sql injection'))) {
    recommendations.push('Database access possible - prepare data extraction tools');
    recommendations.push('Coordinate with digital forensics team for evidence preservation');
  }

  if (result.findings.some((f: any) => f.title.toLowerCase().includes('authentication'))) {
    recommendations.push('Authentication bypass identified - prepare for authorized account access');
  }

  recommendations.push('Document all findings with chain of custody procedures');
  recommendations.push('Prepare technical briefing for prosecution team');
  recommendations.push('Coordinate with blockchain analysis team for asset tracing');

  return recommendations;
}

/**
 * Example usage
 */
export async function main() {
  const targetUrl = 'https://suspected-crypto-exchange.onion';

  try {
    const results = await analyzeCryptoExchange(targetUrl);

    // Save results
    console.log('Mission results ready for Apollo intelligence fusion.');
    console.log('Evidence preservation protocols activated.');

    return results;
  } catch (error) {
    console.error('Analysis failed:', error);
    throw error;
  }
}

// Run if executed directly
if (require.main === module) {
  main().catch(console.error);
}
