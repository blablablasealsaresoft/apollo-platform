/**
 * Claude Integration
 *
 * Integration with Anthropic Claude for complex reasoning.
 * Apollo's preferred model for high-accuracy operations.
 *
 * @module ai-models/claude-integration
 */

export class ClaudeIntegration {
  private apiKey: string;
  private model: string;
  private temperature: number;
  private maxTokens: number;

  constructor(variant: 'opus' | 'sonnet' = 'sonnet') {
    this.apiKey = process.env.ANTHROPIC_API_KEY || '';
    this.model = variant === 'opus' ? 'claude-3-opus-20240229' : 'claude-3-5-sonnet-20241022';
    this.temperature = 0.7;
    this.maxTokens = 8000;
  }

  get name(): string {
    return this.model.includes('opus') ? 'claude-3-opus' : 'claude-3-sonnet';
  }

  async generate(prompt: string): Promise<any> {
    if (!this.apiKey) {
      console.warn('[Claude] API key not configured, using mock response');
      return this.mockGenerate(prompt);
    }

    try {
      const response = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.apiKey,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model: this.model,
          messages: [{ role: 'user', content: prompt }],
          temperature: this.temperature,
          max_tokens: this.maxTokens
        })
      });

      if (!response.ok) {
        throw new Error(`Claude API error: ${response.statusText}`);
      }

      const data = await response.json();
      const content = data.content[0].text;

      try {
        return JSON.parse(content);
      } catch {
        return { response: content };
      }
    } catch (error: any) {
      console.error('[Claude] Generation error:', error.message);
      return this.mockGenerate(prompt);
    }
  }

  async healthCheck(): Promise<boolean> {
    return Boolean(this.apiKey);
  }

  private mockGenerate(prompt: string): any {
    return {
      response: 'Mock Claude response',
      prompt: prompt.substring(0, 100)
    };
  }
}

export default ClaudeIntegration;
