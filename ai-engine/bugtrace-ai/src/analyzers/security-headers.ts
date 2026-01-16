/**
 * BugTrace-AI Security Headers Analyzer
 * Analyzes HTTP security headers
 * @module analyzers/security-headers
 */

import { VulnerabilityFinding } from '../core/ai-orchestrator';

export interface SecurityHeadersResult {
  url: string;
  headers: Record<string, string>;
  findings: VulnerabilityFinding[];
  score: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
}

export class SecurityHeadersAnalyzer {
  async analyze(url: string, headers: Record<string, string>): Promise<SecurityHeadersResult> {
    const findings: VulnerabilityFinding[] = [];

    // Check for missing headers
    const requiredHeaders = [
      'Content-Security-Policy',
      'Strict-Transport-Security',
      'X-Frame-Options',
      'X-Content-Type-Options',
      'Referrer-Policy',
      'Permissions-Policy'
    ];

    requiredHeaders.forEach(header => {
      if (!headers[header] && !headers[header.toLowerCase()]) {
        findings.push({
          id: `missing-${header.toLowerCase()}`,
          title: `Missing ${header} Header`,
          severity: 'medium',
          confidence: 100,
          description: `Security header ${header} is not present`,
          location: url,
          impact: 'Increased attack surface',
          remediation: `Add ${header} header with appropriate value`,
          foundBy: ['security-headers']
        });
      }
    });

    const score = this.calculateScore(findings);
    const grade = this.calculateGrade(score);

    return { url, headers, findings, score, grade };
  }

  private calculateScore(findings: VulnerabilityFinding[]): number {
    return Math.max(0, 100 - findings.length * 15);
  }

  private calculateGrade(score: number): SecurityHeadersResult['grade'] {
    if (score >= 95) return 'A+';
    if (score >= 85) return 'A';
    if (score >= 70) return 'B';
    if (score >= 50) return 'C';
    if (score >= 30) return 'D';
    return 'F';
  }
}

export default SecurityHeadersAnalyzer;
