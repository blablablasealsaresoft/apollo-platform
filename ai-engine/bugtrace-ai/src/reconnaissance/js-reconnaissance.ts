/**
 * BugTrace-AI JavaScript Reconnaissance
 * Extract API endpoints, secrets, and sensitive data from JavaScript files
 * @module reconnaissance/js-reconnaissance
 */

export interface JSReconResult {
  url: string;
  endpoints: string[];
  secrets: SecretFinding[];
  apiKeys: string[];
  comments: string[];
  externalUrls: string[];
}

export interface SecretFinding {
  type: 'api-key' | 'password' | 'token' | 'secret' | 'credential';
  value: string;
  location: string;
  confidence: number;
}

export class JSReconnaissance {
  async analyze(jsCode: string, url?: string): Promise<JSReconResult> {
    const endpoints = this.extractEndpoints(jsCode);
    const secrets = this.extractSecrets(jsCode);
    const apiKeys = this.extractAPIKeys(jsCode);
    const comments = this.extractComments(jsCode);
    const externalUrls = this.extractExternalUrls(jsCode);

    return {
      url: url || 'unknown',
      endpoints,
      secrets,
      apiKeys,
      comments,
      externalUrls
    };
  }

  private extractEndpoints(code: string): string[] {
    const endpoints = new Set<string>();

    // Common patterns for API endpoints
    const patterns = [
      /['"`](\/api\/[^'"`]+)['"`]/g,
      /['"`](\/v\d+\/[^'"`]+)['"`]/g,
      /fetch\(['"`]([^'"`]+)['"`]\)/g,
      /axios\.[a-z]+\(['"`]([^'"`]+)['"`]\)/g,
      /\$\.ajax\({[\s\S]*?url:\s*['"`]([^'"`]+)['"`]/g
    ];

    patterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        endpoints.add(match[1]);
      }
    });

    return Array.from(endpoints);
  }

  private extractSecrets(code: string): SecretFinding[] {
    const secrets: SecretFinding[] = [];

    const secretPatterns = [
      { pattern: /password\s*[:=]\s*['"`]([^'"`]{6,})['"`]/gi, type: 'password' as const },
      { pattern: /secret\s*[:=]\s*['"`]([^'"`]{6,})['"`]/gi, type: 'secret' as const },
      { pattern: /token\s*[:=]\s*['"`]([^'"`]{10,})['"`]/gi, type: 'token' as const },
      { pattern: /api[_-]?key\s*[:=]\s*['"`]([^'"`]{10,})['"`]/gi, type: 'api-key' as const }
    ];

    secretPatterns.forEach(({ pattern, type }) => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        secrets.push({
          type,
          value: match[1],
          location: code.substring(Math.max(0, match.index - 50), match.index + 100),
          confidence: 80
        });
      }
    });

    return secrets;
  }

  private extractAPIKeys(code: string): string[] {
    const keys = new Set<string>();

    // Look for common API key patterns
    const patterns = [
      /['"`][A-Za-z0-9_-]{32,}['"`]/g,  // Generic long strings
      /AIza[0-9A-Za-z_-]{35}/g,          // Google API key
      /sk-[A-Za-z0-9]{32,}/g,            // OpenAI/Stripe keys
      /ghp_[A-Za-z0-9]{36}/g             // GitHub PAT
    ];

    patterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        keys.add(match[0].replace(/['"` ]/g, ''));
      }
    });

    return Array.from(keys);
  }

  private extractComments(code: string): string[] {
    const comments: string[] = [];

    // Single-line comments
    const singleLinePattern = /\/\/(.+)$/gm;
    let match;
    while ((match = singleLinePattern.exec(code)) !== null) {
      const comment = match[1].trim();
      if (comment.length > 10) {  // Filter out short comments
        comments.push(comment);
      }
    }

    // Multi-line comments
    const multiLinePattern = /\/\*([\s\S]*?)\*\//g;
    while ((match = multiLinePattern.exec(code)) !== null) {
      const comment = match[1].trim();
      if (comment.length > 10) {
        comments.push(comment);
      }
    }

    return comments;
  }

  private extractExternalUrls(code: string): string[] {
    const urls = new Set<string>();

    const urlPattern = /https?:\/\/[^\s'"`)]+/g;
    let match;
    while ((match = urlPattern.exec(code)) !== null) {
      urls.add(match[0]);
    }

    return Array.from(urls);
  }

  generateReport(result: JSReconResult): string {
    let report = '═══════════════════════════════════════════════════════\n';
    report += '        JAVASCRIPT RECONNAISSANCE REPORT\n';
    report += '═══════════════════════════════════════════════════════\n\n';

    report += `Analyzed: ${result.url}\n\n`;

    report += `API Endpoints Found: ${result.endpoints.length}\n`;
    result.endpoints.slice(0, 10).forEach(ep => {
      report += `  • ${ep}\n`;
    });

    report += `\nSecrets Found: ${result.secrets.length}\n`;
    result.secrets.forEach(secret => {
      report += `  • [${secret.type}] ${secret.value.substring(0, 20)}... (${secret.confidence}% confidence)\n`;
    });

    report += `\nAPI Keys Found: ${result.apiKeys.length}\n`;
    result.apiKeys.forEach(key => {
      report += `  • ${key.substring(0, 30)}...\n`;
    });

    report += `\nExternal URLs: ${result.externalUrls.length}\n`;
    result.externalUrls.slice(0, 5).forEach(url => {
      report += `  • ${url}\n`;
    });

    return report;
  }
}

export default JSReconnaissance;
