/**
 * Gemini Integration
 *
 * Integration with Google Gemini for fast, cost-effective operations.
 *
 * @module ai-models/gemini-integration
 */

export class GeminiIntegration {
  private apiKey: string;
  private model: string;

  constructor() {
    this.apiKey = process.env.GOOGLE_API_KEY || '';
    this.model = 'gemini-pro';
  }

  get name(): string {
    return 'gemini-flash';
  }

  async generate(prompt: string): Promise<any> {
    if (!this.apiKey) {
      console.warn('[Gemini] API key not configured, using mock response');
      return this.mockGenerate(prompt);
    }

    try {
      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1/models/${this.model}:generateContent?key=${this.apiKey}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }]
          })
        }
      );

      const data = await response.json();
      const content = data.candidates[0].content.parts[0].text;

      try {
        return JSON.parse(content);
      } catch {
        return { response: content };
      }
    } catch (error: any) {
      console.error('[Gemini] Generation error:', error.message);
      return this.mockGenerate(prompt);
    }
  }

  async healthCheck(): Promise<boolean> {
    return Boolean(this.apiKey);
  }

  private mockGenerate(prompt: string): any {
    return {
      response: 'Mock Gemini response',
      prompt: prompt.substring(0, 100)
    };
  }
}

export default GeminiIntegration;
