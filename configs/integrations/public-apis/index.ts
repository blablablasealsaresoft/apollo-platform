/**
 * Apollo Platform - Public APIs Integration
 * Main entry point
 *
 * @module @apollo/public-apis-integration
 * @version 1.0.0
 * @elite-engineering
 */

// Export main orchestrator
export { APIOrchestrator, apiOrchestrator } from './apollo-integration/api-orchestrator';

// Export supporting modules
export { APICaller, apiCaller } from './apollo-integration/api-caller';
export { ResultProcessor, resultProcessor } from './apollo-integration/result-processor';
export { IntelligenceFeeder, intelligenceFeeder } from './apollo-integration/intelligence-feeder';
export { RateLimiter, rateLimiter } from './apollo-integration/rate-limiter';
export { ErrorHandler, errorHandler } from './apollo-integration/error-handler';
export { APIRegistry, apiRegistry } from './apollo-integration/api-registry';

// Export examples
export * from './examples/autonomous-api-usage';
export * from './examples/ignatova-hunt-apis';

/**
 * Quick Start Usage:
 *
 * ```typescript
 * import { apiOrchestrator } from '@apollo/public-apis-integration';
 *
 * // AI autonomously investigates using 1000+ APIs
 * const report = await apiOrchestrator.autonomousInvestigation(
 *   "Find everything about OneCoin and Ruja Ignatova"
 * );
 *
 * // Deploy continuous monitoring
 * await apiOrchestrator.deployContinuousMonitoring('ignatova_hunt', {
 *   frequency: 60,
 *   alertThreshold: 0.8,
 *   autoResponse: true
 * });
 * ```
 */

/**
 * Apollo Public APIs Integration
 *
 * Provides AI-powered access to 1000+ FREE APIs for autonomous intelligence gathering.
 *
 * Key Features:
 * - 1024 FREE APIs across 50+ categories
 * - AI-powered API selection (Cyberspike Villager)
 * - Autonomous execution and correlation
 * - Real-time intelligence fusion
 * - Continuous monitoring (24/7)
 * - Zero cost deployment
 *
 * Priority APIs for Ignatova Hunt:
 * - FBI Wanted, CoinGecko, IPstack, Blockchain.info
 * - Reddit, Etherscan, OpenSky Network, Twitter
 * - And 12 more priority APIs
 *
 * @see README.md for complete documentation
 * @see docs/API_CATALOG.md for complete API list
 * @see examples/ for usage examples
 */
export default {
  orchestrator: apiOrchestrator,
  caller: apiCaller,
  processor: resultProcessor,
  feeder: intelligenceFeeder,
  rateLimiter,
  errorHandler,
  registry: apiRegistry
};
