/**
 * Cyberspike Villager - AI-Native C2 Framework
 *
 * World's first AI-driven penetration testing framework.
 * Autonomous operation planning and execution with natural language commands.
 *
 * @module @apollo/cyberspike-villager
 */

// Core components
export { AIC2Controller } from './core/ai-c2-controller';
export { AdaptiveEvasion } from './core/adaptive-evasion';
export { IntelligentPayloads } from './core/intelligent-payloads';
export { BehavioralAnalysis } from './core/behavioral-analysis';
export { AutonomousOperations } from './core/autonomous-operations';
export { TaskOrchestrator } from './core/task-orchestrator';
export { TaskRelationManager } from './core/task-relation-manager';
export { MCPIntegration } from './core/mcp-integration';

// Mission-specific modules
export { CryptoCrimeHunter } from './modules/crypto-crime-hunter';
export { PredatorTracker } from './modules/predator-tracker';

// AI models
export { ModelRouter } from './ai-models/model-router';
export { DeepSeekIntegration } from './ai-models/deepseek-integration';
export { ClaudeIntegration } from './ai-models/claude-integration';
export { GeminiIntegration } from './ai-models/gemini-integration';
export { GPT4Integration } from './ai-models/gpt4-integration';
export {
  SpikingBrainIntegration,
  createSpikingBrainIntegration,
  type SpikingBrainConfig,
  type GenerationResult,
  type StreamChunk,
  type HealthStatus
} from './ai-models/spikingbrain-integration';

// Types
export type {
  NaturalLanguageCommand,
  OperationPlan,
  ExecutionResult,
  Evidence
} from './core/ai-c2-controller';

export type {
  EvasionStrategy,
  DefenseProfile
} from './core/adaptive-evasion';

export type {
  PayloadRequirements,
  GeneratedPayload
} from './core/intelligent-payloads';

export type {
  TargetAnalysis,
  TacticalRecommendation
} from './core/behavioral-analysis';

export type {
  Task,
  SubTask
} from './core/task-orchestrator';

export type {
  MCPTool,
  ToolExecutionResult
} from './core/mcp-integration';

export type {
  CryptoInvestigation,
  CryptoInvestigationResults
} from './modules/crypto-crime-hunter';

export type {
  PredatorOperation,
  PredatorOperationResults
} from './modules/predator-tracker';

/**
 * Quick start function
 *
 * Initialize Villager with default configuration.
 */
export function initializeVillager() {
  return new AIC2Controller();
}

/**
 * Version information
 */
export const VERSION = '0.1.0';
export const DESCRIPTION = 'AI-Native C2 Framework - World\'s First';

/**
 * Default export
 */
export default {
  AIC2Controller,
  CryptoCrimeHunter,
  PredatorTracker,
  initializeVillager,
  VERSION,
  DESCRIPTION
};
