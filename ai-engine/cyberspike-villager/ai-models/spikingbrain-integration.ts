/**
 * SpikingBrain-7B Integration
 *
 * Integration with SpikingBrain-7B neuromorphic AI model for advanced reasoning.
 * Supports both local inference (vLLM server) and remote API endpoints.
 *
 * SpikingBrain-7B is a novel spiking neural network-based LLM that provides
 * energy-efficient inference with competitive accuracy for security analysis tasks.
 *
 * @see https://github.com/blablablasealsaresoft/SpikingBrain-7B
 * @module ai-models/spikingbrain-integration
 */

import { EventEmitter } from 'events';

/**
 * Configuration options for SpikingBrain-7B
 */
export interface SpikingBrainConfig {
  /** API endpoint URL (vLLM server or remote API) */
  apiUrl: string;
  /** API key for authentication (optional for local) */
  apiKey?: string;
  /** Model variant to use */
  modelVariant: 'base' | 'sft' | 'quantized';
  /** Tensor parallel size for multi-GPU inference */
  tensorParallelSize?: number;
  /** Maximum tokens to generate */
  maxTokens: number;
  /** Temperature for sampling */
  temperature: number;
  /** Top-p (nucleus) sampling */
  topP: number;
  /** Connection timeout in ms */
  timeout: number;
  /** Maximum retries on failure */
  maxRetries: number;
  /** Retry delay in ms */
  retryDelay: number;
  /** Enable streaming responses */
  enableStreaming: boolean;
}

/**
 * Streaming chunk from SpikingBrain response
 */
export interface StreamChunk {
  content: string;
  finishReason: string | null;
  index: number;
}

/**
 * Generation result from SpikingBrain
 */
export interface GenerationResult {
  content: string;
  finishReason: string;
  usage: {
    promptTokens: number;
    completionTokens: number;
    totalTokens: number;
  };
  model: string;
  latency: number;
}

/**
 * Health check result
 */
export interface HealthStatus {
  healthy: boolean;
  modelLoaded: boolean;
  gpuMemoryUsed?: number;
  gpuMemoryTotal?: number;
  version?: string;
  error?: string;
}

/**
 * Default configuration
 */
const DEFAULT_CONFIG: SpikingBrainConfig = {
  apiUrl: process.env.SPIKINGBRAIN_API_URL || 'http://localhost:8000',
  apiKey: process.env.SPIKINGBRAIN_API_KEY || '',
  modelVariant: (process.env.SPIKINGBRAIN_MODEL_VARIANT as 'base' | 'sft' | 'quantized') || 'sft',
  tensorParallelSize: parseInt(process.env.SPIKINGBRAIN_TENSOR_PARALLEL || '1', 10),
  maxTokens: parseInt(process.env.SPIKINGBRAIN_MAX_TOKENS || '4096', 10),
  temperature: parseFloat(process.env.SPIKINGBRAIN_TEMPERATURE || '0.7'),
  topP: parseFloat(process.env.SPIKINGBRAIN_TOP_P || '0.9'),
  timeout: parseInt(process.env.SPIKINGBRAIN_TIMEOUT || '60000', 10),
  maxRetries: parseInt(process.env.SPIKINGBRAIN_MAX_RETRIES || '3', 10),
  retryDelay: parseInt(process.env.SPIKINGBRAIN_RETRY_DELAY || '1000', 10),
  enableStreaming: process.env.SPIKINGBRAIN_STREAMING === 'true'
};

/**
 * Model variant configurations
 */
const MODEL_VARIANTS = {
  base: {
    name: 'Panyuqi/V1-7B-base',
    description: 'Pre-trained base model',
    contextWindow: 8192
  },
  sft: {
    name: 'Panyuqi/V1-7B-sft-s3-reasoning',
    description: 'Supervised fine-tuned model with reasoning capabilities',
    contextWindow: 8192
  },
  quantized: {
    name: 'Abel2076/SpikingBrain-7B-W8ASpike',
    description: 'W8A quantized model for efficient inference',
    contextWindow: 8192
  }
};

/**
 * SpikingBrain-7B Integration Class
 *
 * Provides connection to SpikingBrain-7B model via vLLM server API.
 * Implements OpenAI-compatible API interface for easy integration.
 */
export class SpikingBrainIntegration extends EventEmitter {
  private config: SpikingBrainConfig;
  private isConnected: boolean = false;
  private lastHealthCheck: HealthStatus | null = null;
  private requestCount: number = 0;
  private totalLatency: number = 0;

  constructor(config?: Partial<SpikingBrainConfig>) {
    super();
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Get integration name
   */
  get name(): string {
    return `spikingbrain-7b-${this.config.modelVariant}`;
  }

  /**
   * Get model information
   */
  get modelInfo(): typeof MODEL_VARIANTS['base'] {
    return MODEL_VARIANTS[this.config.modelVariant];
  }

  /**
   * Generate completion using SpikingBrain-7B
   *
   * @param prompt - User prompt to process
   * @param systemPrompt - Optional system prompt for context
   * @returns Generation result with content and metadata
   */
  async generate(prompt: string, systemPrompt?: string): Promise<GenerationResult> {
    const startTime = Date.now();

    // Build messages array (OpenAI chat format)
    const messages: Array<{ role: string; content: string }> = [];

    if (systemPrompt) {
      messages.push({ role: 'system', content: systemPrompt });
    }
    messages.push({ role: 'user', content: prompt });

    // Attempt generation with retries
    let lastError: Error | null = null;

    for (let attempt = 0; attempt < this.config.maxRetries; attempt++) {
      try {
        const result = await this.executeGeneration(messages);

        // Track metrics
        this.requestCount++;
        this.totalLatency += Date.now() - startTime;

        return {
          ...result,
          latency: Date.now() - startTime
        };
      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error));
        console.warn(
          `[SpikingBrain] Generation attempt ${attempt + 1}/${this.config.maxRetries} failed:`,
          lastError.message
        );

        if (attempt < this.config.maxRetries - 1) {
          await this.delay(this.config.retryDelay * Math.pow(2, attempt));
        }
      }
    }

    // All retries exhausted
    console.error('[SpikingBrain] All generation attempts failed');
    this.emit('error', lastError);

    throw lastError || new Error('Generation failed after all retries');
  }

  /**
   * Generate completion with streaming response
   *
   * @param prompt - User prompt to process
   * @param systemPrompt - Optional system prompt
   * @param onChunk - Callback for each streamed chunk
   * @returns Complete generation result
   */
  async generateStream(
    prompt: string,
    systemPrompt?: string,
    onChunk?: (chunk: StreamChunk) => void
  ): Promise<GenerationResult> {
    const startTime = Date.now();

    const messages: Array<{ role: string; content: string }> = [];
    if (systemPrompt) {
      messages.push({ role: 'system', content: systemPrompt });
    }
    messages.push({ role: 'user', content: prompt });

    const url = `${this.config.apiUrl}/v1/chat/completions`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    };

    if (this.config.apiKey) {
      headers['Authorization'] = `Bearer ${this.config.apiKey}`;
    }

    const body = JSON.stringify({
      model: this.modelInfo.name,
      messages,
      max_tokens: this.config.maxTokens,
      temperature: this.config.temperature,
      top_p: this.config.topP,
      stream: true
    });

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body,
      signal: AbortSignal.timeout(this.config.timeout)
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`SpikingBrain API error: ${response.status} - ${errorText}`);
    }

    if (!response.body) {
      throw new Error('No response body for streaming');
    }

    // Process SSE stream
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let fullContent = '';
    let finishReason = '';
    let usage = { promptTokens: 0, completionTokens: 0, totalTokens: 0 };

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value, { stream: true });
        const lines = chunk.split('\n').filter(line => line.startsWith('data: '));

        for (const line of lines) {
          const data = line.slice(6); // Remove 'data: ' prefix

          if (data === '[DONE]') {
            continue;
          }

          try {
            const parsed = JSON.parse(data);
            const delta = parsed.choices?.[0]?.delta?.content || '';
            const reason = parsed.choices?.[0]?.finish_reason;

            if (delta) {
              fullContent += delta;
              this.emit('chunk', { content: delta, index: parsed.choices[0].index });

              if (onChunk) {
                onChunk({
                  content: delta,
                  finishReason: reason,
                  index: parsed.choices[0].index
                });
              }
            }

            if (reason) {
              finishReason = reason;
            }

            if (parsed.usage) {
              usage = {
                promptTokens: parsed.usage.prompt_tokens || 0,
                completionTokens: parsed.usage.completion_tokens || 0,
                totalTokens: parsed.usage.total_tokens || 0
              };
            }
          } catch {
            // Skip malformed JSON chunks
          }
        }
      }
    } finally {
      reader.releaseLock();
    }

    this.requestCount++;
    this.totalLatency += Date.now() - startTime;

    return {
      content: fullContent,
      finishReason: finishReason || 'stop',
      usage,
      model: this.modelInfo.name,
      latency: Date.now() - startTime
    };
  }

  /**
   * Execute generation request to vLLM server
   */
  private async executeGeneration(
    messages: Array<{ role: string; content: string }>
  ): Promise<Omit<GenerationResult, 'latency'>> {
    const url = `${this.config.apiUrl}/v1/chat/completions`;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    };

    if (this.config.apiKey) {
      headers['Authorization'] = `Bearer ${this.config.apiKey}`;
    }

    const body = JSON.stringify({
      model: this.modelInfo.name,
      messages,
      max_tokens: this.config.maxTokens,
      temperature: this.config.temperature,
      top_p: this.config.topP,
      stream: false
    });

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body,
      signal: AbortSignal.timeout(this.config.timeout)
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`SpikingBrain API error: ${response.status} - ${errorText}`);
    }

    const data = await response.json();

    const choice = data.choices?.[0];
    if (!choice) {
      throw new Error('No completion choice in response');
    }

    return {
      content: choice.message?.content || '',
      finishReason: choice.finish_reason || 'stop',
      usage: {
        promptTokens: data.usage?.prompt_tokens || 0,
        completionTokens: data.usage?.completion_tokens || 0,
        totalTokens: data.usage?.total_tokens || 0
      },
      model: data.model || this.modelInfo.name
    };
  }

  /**
   * Parse JSON response, with fallback for non-JSON content
   */
  async generateJSON<T = unknown>(prompt: string, systemPrompt?: string): Promise<T> {
    const jsonSystemPrompt = `${systemPrompt || ''}\n\nIMPORTANT: Respond ONLY with valid JSON. No markdown, no explanation, no code blocks. Just raw JSON.`.trim();

    const result = await this.generate(prompt, jsonSystemPrompt);

    try {
      // Try to extract JSON from response
      let content = result.content.trim();

      // Remove markdown code blocks if present
      if (content.startsWith('```json')) {
        content = content.slice(7);
      } else if (content.startsWith('```')) {
        content = content.slice(3);
      }
      if (content.endsWith('```')) {
        content = content.slice(0, -3);
      }

      return JSON.parse(content.trim()) as T;
    } catch (error) {
      console.warn('[SpikingBrain] Failed to parse JSON response, returning wrapped content');
      return { response: result.content, parseError: true } as T;
    }
  }

  /**
   * Check health of SpikingBrain server
   */
  async healthCheck(): Promise<HealthStatus> {
    try {
      // Check vLLM health endpoint
      const healthUrl = `${this.config.apiUrl}/health`;
      const healthResponse = await fetch(healthUrl, {
        method: 'GET',
        signal: AbortSignal.timeout(5000)
      });

      if (!healthResponse.ok) {
        throw new Error(`Health check failed: ${healthResponse.status}`);
      }

      // Check models endpoint
      const modelsUrl = `${this.config.apiUrl}/v1/models`;
      const modelsResponse = await fetch(modelsUrl, {
        method: 'GET',
        headers: this.config.apiKey
          ? { Authorization: `Bearer ${this.config.apiKey}` }
          : {},
        signal: AbortSignal.timeout(5000)
      });

      if (!modelsResponse.ok) {
        throw new Error(`Models check failed: ${modelsResponse.status}`);
      }

      const modelsData = await modelsResponse.json();
      const modelLoaded = modelsData.data?.some(
        (m: { id: string }) => m.id.includes('SpikingBrain') || m.id.includes('V1-7B')
      );

      this.isConnected = true;
      this.lastHealthCheck = {
        healthy: true,
        modelLoaded: !!modelLoaded,
        version: modelsData.data?.[0]?.id
      };

      return this.lastHealthCheck;
    } catch (error) {
      this.isConnected = false;
      this.lastHealthCheck = {
        healthy: false,
        modelLoaded: false,
        error: error instanceof Error ? error.message : String(error)
      };

      return this.lastHealthCheck;
    }
  }

  /**
   * Get connection status
   */
  isHealthy(): boolean {
    return this.isConnected;
  }

  /**
   * Get metrics
   */
  getMetrics(): {
    requestCount: number;
    averageLatency: number;
    isConnected: boolean;
  } {
    return {
      requestCount: this.requestCount,
      averageLatency: this.requestCount > 0 ? this.totalLatency / this.requestCount : 0,
      isConnected: this.isConnected
    };
  }

  /**
   * Reset metrics
   */
  resetMetrics(): void {
    this.requestCount = 0;
    this.totalLatency = 0;
  }

  /**
   * Get current configuration
   */
  getConfig(): SpikingBrainConfig {
    return { ...this.config };
  }

  /**
   * Update configuration
   */
  updateConfig(config: Partial<SpikingBrainConfig>): void {
    this.config = { ...this.config, ...config };
    this.isConnected = false; // Force reconnection check
  }

  /**
   * Utility delay function
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Factory function to create SpikingBrain integration
 */
export function createSpikingBrainIntegration(
  config?: Partial<SpikingBrainConfig>
): SpikingBrainIntegration {
  return new SpikingBrainIntegration(config);
}

/**
 * Default export - singleton instance
 */
export default new SpikingBrainIntegration();
