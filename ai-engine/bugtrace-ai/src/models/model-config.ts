/**
 * BugTrace-AI Model Configuration
 * Configuration for multiple AI model providers
 * @module models/model-config
 */

export interface AIModel {
  provider: 'google' | 'anthropic' | 'openai' | 'spikingbrain';
  model: string;
  temperature?: number;
  maxTokens?: number;
  topP?: number;
  contextWindow?: number;
}

export interface ModelConfig {
  default: AIModel;
  models: Record<string, AIModel>;
}

export const DEFAULT_MODEL_CONFIG: ModelConfig = {
  default: {
    provider: 'spikingbrain',
    model: 'spikingbrain-7b-sft',
    temperature: 0.7,
    maxTokens: 4096,
    contextWindow: 8192
  },
  models: {
    // SpikingBrain-7B variants (local inference - primary)
    'spikingbrain/base': {
      provider: 'spikingbrain',
      model: 'Panyuqi/V1-7B-base',
      temperature: 0.7,
      maxTokens: 4096,
      contextWindow: 8192
    },
    'spikingbrain/sft': {
      provider: 'spikingbrain',
      model: 'Panyuqi/V1-7B-sft-s3-reasoning',
      temperature: 0.7,
      maxTokens: 4096,
      contextWindow: 8192
    },
    'spikingbrain/quantized': {
      provider: 'spikingbrain',
      model: 'Abel2076/SpikingBrain-7B-W8ASpike',
      temperature: 0.7,
      maxTokens: 4096,
      contextWindow: 8192
    },
    // Cloud models (fallback)
    'google/gemini-flash': {
      provider: 'google',
      model: 'gemini-flash',
      temperature: 0.7,
      maxTokens: 8000,
      contextWindow: 128000
    },
    'anthropic/claude-3-sonnet': {
      provider: 'anthropic',
      model: 'claude-3-sonnet-20240229',
      temperature: 0.7,
      maxTokens: 4000,
      contextWindow: 200000
    },
    'openai/gpt-4': {
      provider: 'openai',
      model: 'gpt-4',
      temperature: 0.7,
      maxTokens: 8000,
      contextWindow: 8192
    }
  }
};

export class ModelConfigManager {
  private config: ModelConfig;

  constructor(config?: ModelConfig) {
    this.config = config || DEFAULT_MODEL_CONFIG;
  }

  getModel(name?: string): AIModel {
    if (!name) {
      return this.config.default;
    }

    const model = this.config.models[name];
    if (!model) {
      throw new Error(`Model not found: ${name}`);
    }

    return model;
  }

  listModels(): string[] {
    return Object.keys(this.config.models);
  }
}

export default new ModelConfigManager();
