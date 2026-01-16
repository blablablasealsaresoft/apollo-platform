/**
 * Model Router
 *
 * Intelligently selects AI model based on task complexity.
 * Routes requests to optimal model for performance and cost.
 *
 * SpikingBrain-7B is now the primary model for efficient local inference.
 *
 * @module ai-models/model-router
 */

import { DeepSeekIntegration } from './deepseek-integration';
import { ClaudeIntegration } from './claude-integration';
import { GeminiIntegration } from './gemini-integration';
import { GPT4Integration } from './gpt4-integration';
import { SpikingBrainIntegration, GenerationResult } from './spikingbrain-integration';

export type ModelComplexity = 'simple' | 'medium' | 'complex' | 'critical' | 'local';

export interface AIModel {
  name: string;
  generate(prompt: string, systemPrompt?: string): Promise<any>;
  healthCheck(): Promise<boolean | { healthy: boolean }>;
}

/**
 * Model Router
 *
 * Selects optimal AI model based on task requirements.
 * SpikingBrain-7B is the default for local inference workloads.
 */
export class ModelRouter {
  private models: Map<string, AIModel>;
  private defaultModel: string;
  private spikingBrain: SpikingBrainIntegration;
  private useLocalFirst: boolean;

  constructor() {
    this.models = new Map();
    this.defaultModel = process.env.DEFAULT_AI_MODEL || 'spikingbrain-7b';
    this.useLocalFirst = process.env.USE_LOCAL_MODEL_FIRST !== 'false';
    this.spikingBrain = new SpikingBrainIntegration();
    this.initializeModels();
  }

  /**
   * Initialize all available models
   */
  private initializeModels(): void {
    try {
      // SpikingBrain-7B variants (local inference)
      this.models.set('spikingbrain-7b', this.createSpikingBrainAdapter('sft'));
      this.models.set('spikingbrain-7b-base', this.createSpikingBrainAdapter('base'));
      this.models.set('spikingbrain-7b-quantized', this.createSpikingBrainAdapter('quantized'));

      // Cloud models (fallback)
      this.models.set('deepseek-v3', new DeepSeekIntegration() as AIModel);
      this.models.set('claude-3-opus', new ClaudeIntegration('opus') as AIModel);
      this.models.set('claude-3-sonnet', new ClaudeIntegration('sonnet') as AIModel);
      this.models.set('gemini-flash', new GeminiIntegration() as AIModel);
      this.models.set('gpt-4', new GPT4Integration() as AIModel);

      console.log('[ModelRouter] Initialized with SpikingBrain-7B as primary model');
    } catch (error: any) {
      console.error('[ModelRouter] Error initializing models:', error.message);
    }
  }

  /**
   * Create adapter to make SpikingBrain conform to AIModel interface
   */
  private createSpikingBrainAdapter(variant: 'base' | 'sft' | 'quantized'): AIModel {
    const integration = new SpikingBrainIntegration({ modelVariant: variant });

    return {
      name: `spikingbrain-7b-${variant}`,
      async generate(prompt: string, systemPrompt?: string): Promise<any> {
        const result: GenerationResult = await integration.generate(prompt, systemPrompt);
        try {
          return JSON.parse(result.content);
        } catch {
          return { response: result.content, usage: result.usage };
        }
      },
      async healthCheck(): Promise<boolean> {
        const status = await integration.healthCheck();
        return status.healthy;
      }
    };
  }

  /**
   * Select model based on task complexity
   * Prefers SpikingBrain-7B for local inference when available
   */
  selectModel(complexity: ModelComplexity): AIModel {
    // For 'local' complexity, always use SpikingBrain
    if (complexity === 'local') {
      return this.models.get('spikingbrain-7b') || this.models.get(this.defaultModel)!;
    }

    const modelName = this.getModelForComplexity(complexity);
    const model = this.models.get(modelName);

    if (!model) {
      console.warn(`[ModelRouter] Model ${modelName} not available, using default`);
      return this.models.get(this.defaultModel)!;
    }

    return model;
  }

  /**
   * Select model with automatic fallback to SpikingBrain if local inference preferred
   */
  async selectModelWithFallback(complexity: ModelComplexity): Promise<AIModel> {
    // Try SpikingBrain first if local inference is preferred
    if (this.useLocalFirst && complexity !== 'critical') {
      const spikingBrain = this.models.get('spikingbrain-7b');
      if (spikingBrain) {
        try {
          const healthy = await spikingBrain.healthCheck();
          if (healthy === true || (typeof healthy === 'object' && healthy.healthy)) {
            console.log('[ModelRouter] Using SpikingBrain-7B for local inference');
            return spikingBrain;
          }
        } catch {
          console.warn('[ModelRouter] SpikingBrain health check failed, falling back to cloud');
        }
      }
    }

    return this.selectModel(complexity);
  }

  /**
   * Get model name for complexity level
   * SpikingBrain-7B is now used for simple/medium tasks when available
   */
  private getModelForComplexity(complexity: ModelComplexity): string {
    const mapping: Record<ModelComplexity, string> = {
      simple: this.useLocalFirst ? 'spikingbrain-7b' : 'gemini-flash',
      medium: this.useLocalFirst ? 'spikingbrain-7b' : 'deepseek-v3',
      complex: 'claude-3-opus',     // High reasoning (cloud)
      critical: 'gpt-4',            // Most reliable (cloud)
      local: 'spikingbrain-7b'      // Always local
    };

    return mapping[complexity] || this.defaultModel;
  }

  /**
   * Get SpikingBrain integration directly for advanced usage
   */
  getSpikingBrain(): SpikingBrainIntegration {
    return this.spikingBrain;
  }

  /**
   * Get model by name
   */
  getModel(name: string): AIModel | undefined {
    return this.models.get(name);
  }

  /**
   * Get available models
   */
  getAvailableModels(): string[] {
    return Array.from(this.models.keys());
  }

  /**
   * Health check all models
   */
  async healthCheck(): Promise<boolean> {
    const checks = await Promise.all(
      Array.from(this.models.values()).map(m => m.healthCheck().catch(() => false))
    );

    return checks.some(check => check);
  }

  /**
   * Get model statistics
   */
  getStatistics(): any {
    return {
      totalModels: this.models.size,
      availableModels: this.getAvailableModels(),
      defaultModel: this.defaultModel
    };
  }
}

export default ModelRouter;
