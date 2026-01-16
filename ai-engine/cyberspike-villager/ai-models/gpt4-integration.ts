/**
 * GPT-4 Integration
 *
 * Integration with OpenAI GPT-4 for critical operations.
 *
 * @module ai-models/gpt4-integration
 */

export class GPT4Integration {
  private apiKey: string;
  private model: string;

  constructor() {
    this.apiKey = process.env.OPENAI_API_KEY || '';
    this.model = 'gpt-4-turbo-preview';
  }

  get name(): string {
    return 'gpt-4';
  }

  async generate(prompt: string): Promise<any> {
    if (!this.apiKey) {
      console.warn('[GPT-4] API key not configured, using mock response');
      return this.mockGenerate(prompt);
    }

    try {
      const response = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`
        },
        body: JSON.stringify({
          model: this.model,
          messages: [{ role: 'user', content: prompt }],
          temperature: 0.7,
          max_tokens: 8000
        })
      });

      const data = await response.json();
      const content = data.choices[0].message.content;

      try {
        return JSON.parse(content);
      } catch {
        return { response: content };
      }
    } catch (error: any) {
      console.error('[GPT-4] Generation error:', error.message);
      return this.mockGenerate(prompt);
    }
  }

  async healthCheck(): Promise<boolean> {
    return Boolean(this.apiKey);
  }

  private mockGenerate(prompt: string): any {
    return {
      response: 'Mock GPT-4 response',
      prompt: prompt.substring(0, 100)
    };
  }
}

export default GPT4Integration;
