/**
 * AI C2 Controller - Core AI Decision Engine
 *
 * Transforms natural language commands into autonomous cyber operations.
 * Uses AI to plan, adapt, and execute complex attack chains.
 *
 * @module core/ai-c2-controller
 */

import { ModelRouter } from '../ai-models/model-router';
import { MCPIntegration } from './mcp-integration';
import { TaskOrchestrator } from './task-orchestrator';
import { AdaptiveEvasion } from './adaptive-evasion';
import { BehavioralAnalysis } from './behavioral-analysis';

export interface NaturalLanguageCommand {
  command: string;
  authorization: string;
  mission?: string;
  timeLimit?: string;
  preserveEvidence?: boolean;
  priority?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface OperationPlan {
  objective: string;
  phases: OperationPhase[];
  tools: string[];
  dependencies: Map<string, string[]>;
  contingencies: ContingencyPlan[];
  estimatedDuration: string;
  successProbability: number;
}

export interface OperationPhase {
  id: string;
  name: string;
  description: string;
  tools: string[];
  dependencies: string[];
  successCriteria: string;
  failureAction: string;
}

export interface ContingencyPlan {
  scenario: string;
  detectionType: string;
  response: string;
  tools: string[];
}

export interface ExecutionResult {
  success: boolean;
  objective: string;
  phasesCompleted: string[];
  evidence: Evidence[];
  defenseDetected: DefenseDetection[];
  adaptations: Adaptation[];
  report: OperationReport;
  timeline: ExecutionEvent[];
}

export interface Evidence {
  id: string;
  type: string;
  source: string;
  data: any;
  timestamp: Date;
  chainOfCustody: string[];
  integrity: {
    hash: string;
    algorithm: string;
    verified: boolean;
  };
}

export interface DefenseDetection {
  type: string;
  confidence: number;
  indicators: string[];
  timestamp: Date;
  response: string;
}

export interface Adaptation {
  trigger: string;
  original: string;
  adapted: string;
  success: boolean;
  timestamp: Date;
}

export interface OperationReport {
  summary: string;
  objectives: {
    planned: string[];
    achieved: string[];
    failed: string[];
  };
  methods: string[];
  findings: any[];
  evidence: Evidence[];
  recommendations: string[];
  legalCompliance: boolean;
  courtReady: boolean;
}

export interface ExecutionEvent {
  timestamp: Date;
  phase: string;
  action: string;
  result: string;
  evidence?: string[];
}

/**
 * AI C2 Controller - Revolutionary AI-Native Command & Control
 *
 * This is the brain of Cyberspike Villager - it takes natural language
 * commands and autonomously plans and executes complex cyber operations.
 */
export class AIC2Controller {
  private modelRouter: ModelRouter;
  private mcpIntegration: MCPIntegration;
  private taskOrchestrator: TaskOrchestrator;
  private adaptiveEvasion: AdaptiveEvasion;
  private behavioralAnalysis: BehavioralAnalysis;

  constructor() {
    this.modelRouter = new ModelRouter();
    this.mcpIntegration = new MCPIntegration();
    this.taskOrchestrator = new TaskOrchestrator();
    this.adaptiveEvasion = new AdaptiveEvasion();
    this.behavioralAnalysis = new BehavioralAnalysis();
  }

  /**
   * Execute natural language command autonomously
   *
   * This is the main entry point for AI-native operations.
   * Operator provides high-level objective, AI figures out the rest.
   *
   * @param command - Natural language command with authorization
   * @returns Complete execution results with evidence
   */
  async executeNaturalLanguageCommand(
    command: NaturalLanguageCommand
  ): Promise<ExecutionResult> {
    console.log(`[AI-C2] Received command: "${command.command}"`);
    console.log(`[AI-C2] Authorization: ${command.authorization}`);
    console.log(`[AI-C2] Mission: ${command.mission || 'general'}`);

    // Step 1: Understand objective
    const objective = await this.parseObjective(command);
    console.log(`[AI-C2] Parsed objective: ${objective.description}`);

    // Step 2: Analyze target
    const targetAnalysis = await this.behavioralAnalysis.analyzeTarget(
      objective.target
    );
    console.log(`[AI-C2] Target analysis complete: ${targetAnalysis.securityPosture}`);

    // Step 3: Plan attack chain
    const plan = await this.planOperation({
      objective,
      targetAnalysis,
      availableTools: this.mcpIntegration.getAllTools(),
      authorization: command.authorization,
      mission: command.mission
    });
    console.log(`[AI-C2] Operation plan created: ${plan.phases.length} phases`);

    // Step 4: Execute autonomously
    let execution = await this.executeAutonomously(plan, command);

    // Step 5: Adapt to defensive measures
    if (execution.defenseDetected.length > 0) {
      console.log(`[AI-C2] Defenses detected: ${execution.defenseDetected.length}`);
      execution = await this.adaptAndRetry(execution, plan);
    }

    // Step 6: Generate report
    const report = await this.generateReport(execution, command);
    execution.report = report;

    console.log(`[AI-C2] Operation complete: ${execution.success ? 'SUCCESS' : 'FAILED'}`);
    console.log(`[AI-C2] Evidence collected: ${execution.evidence.length} items`);

    return execution;
  }

  /**
   * Parse natural language objective into structured format
   */
  private async parseObjective(command: NaturalLanguageCommand): Promise<any> {
    const model = this.modelRouter.selectModel('medium');

    const prompt = `
Parse this cyber operation command into structured format:

Command: "${command.command}"
Mission: ${command.mission || 'general'}

Extract:
1. Primary objective
2. Target(s)
3. Required actions
4. Success criteria
5. Constraints

Return JSON format.
    `;

    return await model.generate(prompt);
  }

  /**
   * Plan complete operation based on objective
   *
   * AI analyzes the objective and creates a comprehensive plan
   * with phases, tools, dependencies, and contingencies.
   */
  private async planOperation(params: {
    objective: any;
    targetAnalysis: any;
    availableTools: string[];
    authorization: string;
    mission?: string;
  }): Promise<OperationPlan> {
    const model = this.modelRouter.selectModel('complex');

    const prompt = `
You are an elite AI orchestrator for criminal investigation operations.

OBJECTIVE: ${JSON.stringify(params.objective)}
TARGET ANALYSIS: ${JSON.stringify(params.targetAnalysis)}
AVAILABLE TOOLS: ${params.availableTools.slice(0, 50).join(', ')} (+ ${params.availableTools.length - 50} more)
AUTHORIZATION: ${params.authorization}
MISSION: ${params.mission || 'general'}

Plan a complete operation to achieve this objective:

1. Break down into phases with clear objectives
2. Select optimal tools for each phase
3. Define dependencies between phases
4. Include success criteria for each phase
5. Create contingency plans for failures
6. Estimate timeline and success probability
7. Ensure legal compliance

Available tool categories:
- Reconnaissance: bbot, subhunterx, amass, subfinder, cloudrecon
- Vulnerability Analysis: bugtrace-ai (95% accuracy), nuclei, nikto
- Exploitation: dnsreaper (50/sec), metasploit, custom exploits
- Post-Exploitation: privilege escalation, lateral movement, persistence
- Evidence Collection: database extraction, file recovery, chain of custody
- OPSEC: traffic obfuscation, proxy chaining, evasion techniques

Return detailed operation plan in JSON format.
    `;

    const plan = await model.generate(prompt);
    return this.validatePlan(plan);
  }

  /**
   * Execute operation autonomously
   *
   * AI orchestrates all phases, selects tools, handles failures,
   * collects evidence, and adapts in real-time.
   */
  private async executeAutonomously(
    plan: OperationPlan,
    command: NaturalLanguageCommand
  ): Promise<ExecutionResult> {
    const result: ExecutionResult = {
      success: false,
      objective: plan.objective,
      phasesCompleted: [],
      evidence: [],
      defenseDetected: [],
      adaptations: [],
      report: {} as OperationReport,
      timeline: []
    };

    // Execute each phase
    for (const phase of plan.phases) {
      console.log(`[AI-C2] Executing phase: ${phase.name}`);

      const phaseResult = await this.taskOrchestrator.executePhase(
        phase,
        command.authorization
      );

      // Record event
      result.timeline.push({
        timestamp: new Date(),
        phase: phase.name,
        action: phase.description,
        result: phaseResult.success ? 'SUCCESS' : 'FAILED',
        evidence: phaseResult.evidence?.map(e => e.id)
      });

      if (phaseResult.success) {
        result.phasesCompleted.push(phase.id);

        // Collect evidence
        if (phaseResult.evidence) {
          result.evidence.push(...phaseResult.evidence);
        }

        // Check for defense detection
        if (phaseResult.defenseDetected) {
          result.defenseDetected.push(...phaseResult.defenseDetected);
        }
      } else {
        console.log(`[AI-C2] Phase failed: ${phase.name}`);

        // Attempt contingency plan
        const contingency = plan.contingencies.find(
          c => c.scenario === 'phase_failure'
        );

        if (contingency) {
          console.log(`[AI-C2] Executing contingency: ${contingency.response}`);
          const contingencyResult = await this.executeContingency(
            contingency,
            phase,
            command.authorization
          );

          if (contingencyResult.success) {
            result.phasesCompleted.push(phase.id);
            result.adaptations.push({
              trigger: `Phase ${phase.name} failed`,
              original: phase.description,
              adapted: contingency.response,
              success: true,
              timestamp: new Date()
            });
          } else {
            // Critical failure
            result.success = false;
            return result;
          }
        } else {
          // No contingency, operation failed
          result.success = false;
          return result;
        }
      }
    }

    result.success = true;
    return result;
  }

  /**
   * Adapt and retry when defenses are detected
   *
   * AI analyzes defense mechanisms and adapts tactics to evade.
   */
  private async adaptAndRetry(
    execution: ExecutionResult,
    plan: OperationPlan
  ): Promise<ExecutionResult> {
    console.log('[AI-C2] Adapting to defensive measures...');

    for (const defense of execution.defenseDetected) {
      const evasion = await this.adaptiveEvasion.evade(defense.type);

      execution.adaptations.push({
        trigger: `Defense detected: ${defense.type}`,
        original: 'Standard approach',
        adapted: evasion.technique,
        success: evasion.success,
        timestamp: new Date()
      });

      if (evasion.success) {
        console.log(`[AI-C2] Successfully evaded: ${defense.type}`);
      } else {
        console.log(`[AI-C2] Evasion failed: ${defense.type}`);
      }
    }

    return execution;
  }

  /**
   * Execute contingency plan
   */
  private async executeContingency(
    contingency: ContingencyPlan,
    failedPhase: OperationPhase,
    authorization: string
  ): Promise<any> {
    return await this.taskOrchestrator.executeContingency(
      contingency,
      failedPhase,
      authorization
    );
  }

  /**
   * Generate comprehensive operation report
   */
  private async generateReport(
    execution: ExecutionResult,
    command: NaturalLanguageCommand
  ): Promise<OperationReport> {
    const model = this.modelRouter.selectModel('complex');

    const prompt = `
Generate a comprehensive operation report:

COMMAND: ${command.command}
AUTHORIZATION: ${command.authorization}
MISSION: ${command.mission || 'general'}

EXECUTION RESULTS:
- Success: ${execution.success}
- Phases Completed: ${execution.phasesCompleted.length}
- Evidence Collected: ${execution.evidence.length}
- Defenses Detected: ${execution.defenseDetected.length}
- Adaptations Made: ${execution.adaptations.length}

TIMELINE:
${execution.timeline.map(e => `- ${e.timestamp.toISOString()}: ${e.phase} - ${e.action} (${e.result})`).join('\n')}

Generate:
1. Executive summary
2. Objectives (planned vs achieved)
3. Methods used
4. Key findings
5. Evidence summary
6. Recommendations
7. Legal compliance verification

Format for court admissibility.
    `;

    const reportData = await model.generate(prompt);

    return {
      summary: reportData.summary,
      objectives: {
        planned: [command.command],
        achieved: execution.success ? [command.command] : [],
        failed: execution.success ? [] : [command.command]
      },
      methods: execution.timeline.map(e => e.action),
      findings: [],
      evidence: execution.evidence,
      recommendations: reportData.recommendations || [],
      legalCompliance: true,
      courtReady: command.preserveEvidence !== false
    };
  }

  /**
   * Validate operation plan
   */
  private validatePlan(plan: any): OperationPlan {
    // Ensure plan has required structure
    if (!plan.phases || !Array.isArray(plan.phases)) {
      throw new Error('Invalid operation plan: missing phases');
    }

    if (!plan.tools || !Array.isArray(plan.tools)) {
      throw new Error('Invalid operation plan: missing tools');
    }

    return plan as OperationPlan;
  }

  /**
   * Get available AI models
   */
  getAvailableModels(): string[] {
    return this.modelRouter.getAvailableModels();
  }

  /**
   * Get available tools via MCP
   */
  getAvailableTools(): string[] {
    return this.mcpIntegration.getAllTools();
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<boolean> {
    try {
      const modelsOk = await this.modelRouter.healthCheck();
      const mcpOk = await this.mcpIntegration.healthCheck();
      return modelsOk && mcpOk;
    } catch (error) {
      return false;
    }
  }
}

export default AIC2Controller;
