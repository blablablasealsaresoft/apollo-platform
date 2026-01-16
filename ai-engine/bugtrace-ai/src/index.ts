/**
 * BugTrace-AI - AI-Powered Vulnerability Analysis Suite
 *
 * Main entry point for the BugTrace-AI vulnerability analysis engine.
 *
 * @module @apollo/bugtrace-ai
 * @author Apollo Platform
 * @version 0.1.0
 */

// Core exports
export { AIOrchestrator } from './core/ai-orchestrator';
export { PersonaManager } from './core/persona-manager';
export { ConsolidationEngine } from './core/consolidation-engine';
export { DeepAnalysis } from './core/deep-analysis';

// Analyzer exports
export { WebSecAgent } from './analyzers/websec-agent';
export { URLAnalyzer } from './analyzers/url-analysis';
export { CodeAnalyzer } from './analyzers/code-analysis';
export { SecurityHeadersAnalyzer } from './analyzers/security-headers';
export { DOMXSSPathfinder } from './analyzers/dom-xss-pathfinder';
export { JWTAuditor } from './analyzers/jwt-auditor';
export { PrivEscPathfinder } from './analyzers/privesc-pathfinder';
export { FileUploadAuditor } from './analyzers/file-upload-auditor';

// Reconnaissance exports
export { JSReconnaissance } from './reconnaissance/js-reconnaissance';
export { URLListFinder } from './reconnaissance/url-list-finder';
export { SubdomainFinder } from './reconnaissance/subdomain-finder';

// Payload exports
export { PayloadForge } from './payload/payload-forge';
export { SSTIForge } from './payload/ssti-forge';
export { OOBHelper } from './payload/oob-helper';

// Model exports
export { ModelConfigManager } from './models/model-config';
export { GeminiModels } from './models/gemini-models';
export { ClaudeModels } from './models/claude-models';

// Utility exports
export { Obfuscator } from './utils/obfuscation';
export { VulnerabilityDatabase } from './utils/vulnerability-db';
export { ReportGenerator } from './utils/report-generator';

// Type exports
export type {
  AnalysisTarget,
  AnalysisOptions,
  AnalysisResult,
  VulnerabilityFinding,
  PersonaAnalysisResult
} from './core/ai-orchestrator';

export type {
  Persona
} from './core/persona-manager';

export type {
  AIModel,
  ModelConfig
} from './models/model-config';

export type {
  ObfuscationTechnique
} from './utils/obfuscation';

export type {
  VulnerabilityInfo
} from './utils/vulnerability-db';

// Default exports
export { default as personaManager } from './core/persona-manager';
export { default as obfuscator } from './utils/obfuscation';
export { default as vulnDB } from './utils/vulnerability-db';
export { default as reportGen } from './utils/report-generator';
export { default as modelConfig } from './models/model-config';

/**
 * BugTrace-AI Version
 */
export const VERSION = '0.1.0';

/**
 * BugTrace-AI Description
 */
export const DESCRIPTION = 'AI-powered vulnerability analysis suite with 95% accuracy through multi-persona recursive analysis';

/**
 * Quick start helper
 */
export async function quickAnalysis(url: string) {
  const { AIOrchestrator } = await import('./core/ai-orchestrator');

  const orchestrator = new AIOrchestrator({
    provider: 'google',
    model: 'gemini-flash'
  });

  return await orchestrator.analyze(
    { url },
    { depth: 5, enableConsolidation: true, enableDeepAnalysis: false }
  );
}

/**
 * Display BugTrace-AI banner
 */
export function displayBanner(): void {
  console.log(`
╔════════════════════════════════════════════════════════════════╗
║                      BUGTRACE-AI v${VERSION}                       ║
╠════════════════════════════════════════════════════════════════╣
║  AI-Powered Vulnerability Analysis Suite                     ║
║  95% Accuracy through Multi-Persona Recursive Analysis        ║
║                                                                ║
║  Apollo Platform - Intelligence-Driven Security Testing       ║
╚════════════════════════════════════════════════════════════════╝
  `);
}

// Display banner when imported
if (require.main === module) {
  displayBanner();
  console.log('BugTrace-AI loaded successfully.');
  console.log('Import modules to start using BugTrace-AI.\n');
  console.log('Example:');
  console.log('  import { AIOrchestrator } from "@apollo/bugtrace-ai";\n');
}
