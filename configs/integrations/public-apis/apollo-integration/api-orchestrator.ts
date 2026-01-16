/**
 * Apollo Platform - Public APIs Integration
 * AI-Powered API Orchestration System
 *
 * Enables Cyberspike Villager AI to autonomously select and call 1000+ FREE APIs
 * based on mission objectives and intelligence requirements.
 *
 * @module APIOrchestrator
 * @version 1.0.0
 * @elite-engineering
 */

import { APIRegistry } from './api-registry';
import { APICaller } from './api-caller';
import { ResultProcessor } from './result-processor';
import { IntelligenceFeeder } from './intelligence-feeder';
import { RateLimiter } from './rate-limiter';
import { ErrorHandler } from './error-handler';

interface APISelectionContext {
  objective: string;
  mission?: string;
  priority?: 'critical' | 'high' | 'medium' | 'low';
  categories?: string[];
  keywords?: string[];
  timeConstraint?: number;
  budget?: {
    rateLimitBudget: number;
    apiCallBudget: number;
  };
}

interface APIExecutionResult {
  api: string;
  category: string;
  success: boolean;
  data?: any;
  error?: string;
  executionTime: number;
  timestamp: Date;
}

interface IntelligenceReport {
  objective: string;
  apisUsed: number;
  apisSuccessful: number;
  apisFailed: number;
  executionTime: number;
  intelligence: {
    findings: any[];
    correlations: any[];
    alerts: any[];
    confidence: number;
  };
  rawResults: APIExecutionResult[];
  timestamp: Date;
}

/**
 * AI-Powered API Orchestration Engine
 *
 * Core capabilities:
 * 1. Autonomous API selection based on mission objectives
 * 2. Parallel API execution with failover
 * 3. Intelligent result correlation
 * 4. Real-time intelligence fusion
 * 5. Continuous learning from API effectiveness
 */
export class APIOrchestrator {
  private registry: APIRegistry;
  private caller: APICaller;
  private processor: ResultProcessor;
  private feeder: IntelligenceFeeder;
  private rateLimiter: RateLimiter;
  private errorHandler: ErrorHandler;

  // AI model for intelligent API selection
  private aiModel: any; // Cyberspike Villager AI integration

  // Performance tracking for continuous improvement
  private apiPerformanceMetrics: Map<string, {
    successRate: number;
    avgResponseTime: number;
    dataQuality: number;
    lastUsed: Date;
  }>;

  constructor() {
    this.registry = new APIRegistry();
    this.caller = new APICaller();
    this.processor = new ResultProcessor();
    this.feeder = new IntelligenceFeeder();
    this.rateLimiter = new RateLimiter();
    this.errorHandler = new ErrorHandler();
    this.apiPerformanceMetrics = new Map();

    this.loadAllAPIs();
    this.initializeAIModel();
  }

  /**
   * Load all 1000+ APIs into registry
   */
  private async loadAllAPIs(): Promise<void> {
    await this.registry.loadFromFile('api-registry.json');
    await this.registry.loadCategories([
      'cryptocurrency',
      'geolocation',
      'government',
      'social-media',
      'finance',
      'transportation',
      'business',
      // ... all 50+ categories
    ]);

    console.log(`API Orchestrator: Loaded ${this.registry.getTotalAPIs()} APIs across ${this.registry.getTotalCategories()} categories`);
  }

  /**
   * Initialize AI model for intelligent API selection
   */
  private initializeAIModel(): void {
    // Integration with Cyberspike Villager AI
    // The AI will analyze objectives and select optimal APIs
    this.aiModel = {
      // Model configuration
      temperature: 0.7,
      maxTokens: 4096,
      model: 'claude-sonnet-4.5',
    };
  }

  /**
   * AI autonomously selects relevant APIs for a given objective
   *
   * This is the CORE intelligence feature - AI browses 1000+ APIs
   * and selects the most relevant ones without human intervention
   *
   * @param context - Mission context and objectives
   * @returns Array of selected API names
   */
  async selectAPIsForTask(context: APISelectionContext): Promise<string[]> {
    console.log(`\n🤖 AI analyzing objective: "${context.objective}"`);
    console.log(`📚 Browsing ${this.registry.getTotalAPIs()} available APIs...`);

    // Get all APIs with metadata
    const allAPIs = this.registry.getAllAPIsWithMetadata();

    // Filter by category if specified
    let candidateAPIs = context.categories
      ? allAPIs.filter(api => context.categories!.includes(api.category))
      : allAPIs;

    // Filter by priority if specified
    if (context.priority) {
      candidateAPIs = candidateAPIs.filter(api =>
        this.isPriorityMatch(api.priority, context.priority!)
      );
    }

    // AI prompt for intelligent selection
    const selectionPrompt = this.buildSelectionPrompt(context, candidateAPIs);

    // AI analyzes and selects APIs
    const selectedAPINames = await this.aiAnalyzeAndSelect(selectionPrompt);

    console.log(`✅ AI selected ${selectedAPINames.length} APIs: ${selectedAPINames.join(', ')}`);

    return selectedAPINames;
  }

  /**
   * Build AI prompt for API selection
   */
  private buildSelectionPrompt(
    context: APISelectionContext,
    candidateAPIs: any[]
  ): string {
    return `
You are an elite intelligence analyst selecting APIs for a mission.

MISSION OBJECTIVE:
${context.objective}

${context.mission ? `MISSION TYPE: ${context.mission}` : ''}
${context.priority ? `PRIORITY: ${context.priority}` : ''}
${context.keywords ? `KEYWORDS: ${context.keywords.join(', ')}` : ''}

AVAILABLE APIs (${candidateAPIs.length}):
${JSON.stringify(candidateAPIs.map(api => ({
  id: api.id,
  name: api.name,
  category: api.category,
  description: api.description,
  apollo_use: api.apollo_use,
  priority: api.priority,
  free: api.free,
  rate_limit: api.rate_limit
})), null, 2)}

SELECTION CRITERIA:
1. Relevance to mission objective
2. Data quality and reliability
3. Free tier availability
4. Rate limit compatibility
5. Apollo integration priority
6. Complementary data sources (select multiple for cross-validation)

TASK:
Analyze the objective and select the MOST RELEVANT APIs.
- Select 5-20 APIs depending on complexity
- Prioritize FREE APIs with high data quality
- Include multiple sources for critical data (redundancy)
- Consider rate limits for continuous monitoring
- Balance coverage across categories

Return ONLY a JSON array of API IDs, e.g.:
["coingecko", "blockchain_info", "ipstack", "fbi_wanted", "reddit"]

Selected APIs:`;
  }

  /**
   * AI analyzes prompt and selects APIs
   */
  private async aiAnalyzeAndSelect(prompt: string): Promise<string[]> {
    // This would integrate with actual Cyberspike Villager AI
    // For now, implementing intelligent rule-based selection

    // Extract keywords from objective
    const keywords = this.extractKeywords(prompt);

    // Score APIs based on relevance
    const scoredAPIs = this.scoreAPIsByRelevance(keywords);

    // Select top N APIs
    const topAPIs = scoredAPIs
      .sort((a, b) => b.score - a.score)
      .slice(0, 15)
      .map(api => api.id);

    return topAPIs;
  }

  /**
   * Execute selected APIs in parallel with intelligent orchestration
   *
   * @param apiNames - Selected API names
   * @param params - Parameters for API calls
   * @returns Execution results from all APIs
   */
  async executeAPICalls(
    apiNames: string[],
    params: any
  ): Promise<APIExecutionResult[]> {
    console.log(`\n🚀 Executing ${apiNames.length} APIs in parallel...`);

    const results: APIExecutionResult[] = [];
    const promises = apiNames.map(async (apiName) => {
      const startTime = Date.now();

      try {
        // Check rate limit
        await this.rateLimiter.waitForSlot(apiName);

        // Get API configuration
        const api = this.registry.getAPI(apiName);

        // Execute API call
        const data = await this.caller.call(api, params);

        const result: APIExecutionResult = {
          api: apiName,
          category: api.category,
          success: true,
          data,
          executionTime: Date.now() - startTime,
          timestamp: new Date()
        };

        // Update performance metrics
        this.updatePerformanceMetrics(apiName, result);

        return result;

      } catch (error) {
        const result: APIExecutionResult = {
          api: apiName,
          category: this.registry.getAPI(apiName)?.category || 'unknown',
          success: false,
          error: error.message,
          executionTime: Date.now() - startTime,
          timestamp: new Date()
        };

        // Handle error with intelligent retry/failover
        await this.errorHandler.handle(error, apiName);

        return result;
      }
    });

    // Wait for all APIs to complete
    const settledResults = await Promise.allSettled(promises);

    settledResults.forEach((result) => {
      if (result.status === 'fulfilled') {
        results.push(result.value);
      }
    });

    const successful = results.filter(r => r.success).length;
    console.log(`✅ Completed: ${successful}/${apiNames.length} successful`);

    return results;
  }

  /**
   * Complete autonomous API investigation
   *
   * This is the MAIN entry point for AI-driven intelligence gathering
   * AI handles everything from API selection to intelligence fusion
   *
   * @param objective - Mission objective
   * @param context - Additional context
   * @returns Intelligence report
   */
  async autonomousInvestigation(
    objective: string,
    context?: Partial<APISelectionContext>
  ): Promise<IntelligenceReport> {
    const startTime = Date.now();

    console.log(`\n${'='.repeat(80)}`);
    console.log(`🤖 APOLLO AI AUTONOMOUS INVESTIGATION`);
    console.log(`${'='.repeat(80)}`);
    console.log(`📋 Objective: ${objective}`);
    console.log(`⚡ AI will autonomously select and execute APIs from 1000+ sources`);
    console.log(`${'='.repeat(80)}\n`);

    // Step 1: AI selects relevant APIs
    const selectionContext: APISelectionContext = {
      objective,
      ...context
    };
    const selectedAPIs = await this.selectAPIsForTask(selectionContext);

    // Step 2: Execute all selected APIs in parallel
    const apiResults = await this.executeAPICalls(selectedAPIs, {
      objective,
      ...context
    });

    // Step 3: Process and correlate results
    console.log(`\n🔍 Processing and correlating results...`);
    const intelligence = await this.processor.processAndCorrelate(apiResults);

    // Step 4: Generate intelligence report
    console.log(`📊 Generating intelligence report...`);
    const report: IntelligenceReport = {
      objective,
      apisUsed: selectedAPIs.length,
      apisSuccessful: apiResults.filter(r => r.success).length,
      apisFailed: apiResults.filter(r => !r.success).length,
      executionTime: Date.now() - startTime,
      intelligence,
      rawResults: apiResults,
      timestamp: new Date()
    };

    // Step 5: Feed intelligence to Apollo fusion center
    console.log(`🔄 Feeding intelligence to Apollo fusion center...`);
    await this.feeder.feedToApollo(intelligence);

    // Step 6: Generate alerts for significant findings
    if (intelligence.alerts && intelligence.alerts.length > 0) {
      console.log(`\n⚠️  ALERTS GENERATED: ${intelligence.alerts.length}`);
      intelligence.alerts.forEach((alert: any) => {
        console.log(`   🚨 ${alert.type}: ${alert.message}`);
      });
    }

    console.log(`\n${'='.repeat(80)}`);
    console.log(`✅ INVESTIGATION COMPLETE`);
    console.log(`   APIs Used: ${report.apisUsed}`);
    console.log(`   Successful: ${report.apisSuccessful}`);
    console.log(`   Failed: ${report.apisFailed}`);
    console.log(`   Findings: ${intelligence.findings?.length || 0}`);
    console.log(`   Confidence: ${(intelligence.confidence * 100).toFixed(1)}%`);
    console.log(`   Execution Time: ${(report.executionTime / 1000).toFixed(2)}s`);
    console.log(`${'='.repeat(80)}\n`);

    return report;
  }

  /**
   * Deploy continuous monitoring for specific mission
   *
   * @param mission - Mission type (e.g., 'ignatova_hunt')
   * @param config - Monitoring configuration
   */
  async deployContinuousMonitoring(
    mission: string,
    config: {
      apis?: string[];
      frequency?: number;
      alertThreshold?: number;
      autoResponse?: boolean;
    }
  ): Promise<void> {
    console.log(`\n🎯 Deploying continuous monitoring for mission: ${mission}`);

    // Load priority APIs for mission
    const priorityAPIs = await this.loadPriorityAPIsForMission(mission);
    const selectedAPIs = config.apis || priorityAPIs;

    console.log(`📡 Monitoring ${selectedAPIs.length} APIs continuously`);
    console.log(`⏰ Frequency: ${config.frequency || 60}s`);
    console.log(`🚨 Alert threshold: ${config.alertThreshold || 'high'}`);

    // Start monitoring loop
    const monitoringLoop = setInterval(async () => {
      try {
        const results = await this.executeAPICalls(selectedAPIs, { mission });
        const intelligence = await this.processor.processAndCorrelate(results);

        // Check for alerts
        if (intelligence.alerts && intelligence.alerts.length > 0) {
          await this.feeder.feedAlertsToApollo(intelligence.alerts, mission);

          // Auto-response if enabled
          if (config.autoResponse) {
            await this.executeAutoResponse(intelligence.alerts, mission);
          }
        }

        // Feed to fusion center
        await this.feeder.feedToApollo(intelligence);

      } catch (error) {
        console.error(`Monitoring error: ${error.message}`);
      }
    }, (config.frequency || 60) * 1000);

    // Store monitoring handle for later cancellation
    // this.monitoringHandles.set(mission, monitoringLoop);
  }

  /**
   * Helper methods
   */

  private isPriorityMatch(apiPriority: string, requiredPriority: string): boolean {
    const priorityLevels = { critical: 4, high: 3, medium: 2, low: 1 };
    return priorityLevels[apiPriority] >= priorityLevels[requiredPriority];
  }

  private extractKeywords(text: string): string[] {
    // Extract meaningful keywords from text
    const keywords = text.toLowerCase()
      .match(/\b\w{4,}\b/g) || [];
    return [...new Set(keywords)];
  }

  private scoreAPIsByRelevance(keywords: string[]): Array<{ id: string; score: number }> {
    const apis = this.registry.getAllAPIsWithMetadata();

    return apis.map(api => {
      let score = 0;
      const searchText = `${api.name} ${api.description} ${api.apollo_use} ${api.category}`.toLowerCase();

      keywords.forEach(keyword => {
        if (searchText.includes(keyword)) {
          score += 1;
        }
      });

      // Boost by priority
      const priorityBoost = { critical: 3, high: 2, medium: 1, low: 0 };
      score += priorityBoost[api.priority] || 0;

      // Boost by past performance
      const perf = this.apiPerformanceMetrics.get(api.id);
      if (perf) {
        score += perf.successRate * 2;
        score += perf.dataQuality;
      }

      return { id: api.id, score };
    });
  }

  private updatePerformanceMetrics(apiName: string, result: APIExecutionResult): void {
    const existing = this.apiPerformanceMetrics.get(apiName) || {
      successRate: 0,
      avgResponseTime: 0,
      dataQuality: 0,
      lastUsed: new Date()
    };

    // Update metrics (simple exponential moving average)
    const alpha = 0.3;
    existing.successRate = alpha * (result.success ? 1 : 0) + (1 - alpha) * existing.successRate;
    existing.avgResponseTime = alpha * result.executionTime + (1 - alpha) * existing.avgResponseTime;
    existing.lastUsed = new Date();

    this.apiPerformanceMetrics.set(apiName, existing);
  }

  private async loadPriorityAPIsForMission(mission: string): Promise<string[]> {
    // Load priority APIs from configuration
    // e.g., for 'ignatova_hunt', load top-20-ignatova.yaml
    return [];
  }

  private async executeAutoResponse(alerts: any[], mission: string): Promise<void> {
    // Execute automated response to alerts
    console.log(`🤖 Executing automated response for ${alerts.length} alerts`);
  }
}

/**
 * Export singleton instance
 */
export const apiOrchestrator = new APIOrchestrator();

/**
 * Quick start example:
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
 */
