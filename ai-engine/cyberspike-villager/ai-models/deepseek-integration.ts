/**
 * DeepSeek v3 Integration
 *
 * Integration with DeepSeek v3 AI model for operation planning.
 * Original Villager used DeepSeek, Apollo supports it as an option.
 *
 * @module ai-models/deepseek-integration
 */

export class DeepSeekIntegration {
  private apiUrl: string;
  private apiKey: string;
  private model: string;
  private temperature: number;
  private maxTokens: number;

  constructor() {
    this.apiUrl = process.env.DEEPSEEK_API_URL || 'https://api.deepseek.com/v1';
    this.apiKey = process.env.DEEPSEEK_API_KEY || '';
    this.model = 'deepseek-v3';
    this.temperature = 0.7;
    this.maxTokens = 8000;
  }

  get name(): string {
    return 'deepseek-v3';
  }

  async generate(prompt: string): Promise<any> {
    if (!this.apiKey) {
      console.warn('[DeepSeek] API key not configured, using mock response');
      return this.mockGenerate(prompt);
    }

    try {
      const response = await fetch(`${this.apiUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`
        },
        body: JSON.stringify({
          model: this.model,
          messages: [{ role: 'user', content: prompt }],
          temperature: this.temperature,
          max_tokens: this.maxTokens
        })
      });

      if (!response.ok) {
        throw new Error(`DeepSeek API error: ${response.statusText}`);
      }

      const data = await response.json();
      return JSON.parse(data.choices[0].message.content);
    } catch (error: any) {
      console.error('[DeepSeek] Generation error:', error.message);
      return this.mockGenerate(prompt);
    }
  }

  async healthCheck(): Promise<boolean> {
    return Boolean(this.apiKey);
  }

  private mockGenerate(prompt: string): any {
    return {
      response: 'Mock DeepSeek response',
      prompt: prompt.substring(0, 100)
    };
  }
}

export default DeepSeekIntegration;
