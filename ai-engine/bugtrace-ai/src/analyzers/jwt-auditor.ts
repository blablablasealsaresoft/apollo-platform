/**
 * BugTrace-AI JWT Auditor
 * JWT security analysis with Blue Team and Red Team modes
 * @module analyzers/jwt-auditor
 */

import { VulnerabilityFinding } from '../core/ai-orchestrator';

export type JWTAuditMode = 'blueteam' | 'redteam';

export interface JWTAuditResult {
  token: string;
  decoded: {
    header: any;
    payload: any;
    signature: string;
  };
  vulnerabilities: VulnerabilityFinding[];
  recommendations: string[];
}

export class JWTAuditor {
  async audit(token: string, mode: JWTAuditMode = 'blueteam'): Promise<JWTAuditResult> {
    const decoded = this.decodeJWT(token);
    const vulnerabilities: VulnerabilityFinding[] = [];

    // Check algorithm
    if (decoded.header.alg === 'none') {
      vulnerabilities.push({
        id: 'jwt-none-alg',
        title: 'JWT Algorithm "none" Vulnerability',
        severity: 'critical',
        confidence: 100,
        description: 'JWT uses "none" algorithm - signature can be removed',
        location: 'JWT Header',
        exploitation: 'Remove signature and set alg to "none"',
        impact: 'Complete authentication bypass',
        remediation: 'Reject tokens with alg "none"',
        cwe: 'CWE-347',
        foundBy: ['jwt-auditor']
      });
    }

    if (decoded.header.alg === 'HS256' && mode === 'redteam') {
      vulnerabilities.push({
        id: 'jwt-weak-secret',
        title: 'Potential Weak JWT Secret',
        severity: 'high',
        confidence: 70,
        description: 'JWT uses HS256 - susceptible to brute force',
        location: 'JWT Header',
        exploitation: 'Brute force HMAC secret',
        impact: 'Token forgery',
        remediation: 'Use strong secret or asymmetric signing',
        foundBy: ['jwt-auditor']
      });
    }

    // Check for sensitive data
    if (this.containsSensitiveData(decoded.payload)) {
      vulnerabilities.push({
        id: 'jwt-sensitive-data',
        title: 'Sensitive Data in JWT',
        severity: 'medium',
        confidence: 90,
        description: 'JWT contains sensitive information',
        location: 'JWT Payload',
        impact: 'Information disclosure',
        remediation: 'Remove sensitive data from JWT claims',
        foundBy: ['jwt-auditor']
      });
    }

    const recommendations = this.generateRecommendations(decoded, mode);

    return { token, decoded, vulnerabilities, recommendations };
  }

  private decodeJWT(token: string): JWTAuditResult['decoded'] {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }

    return {
      header: JSON.parse(Buffer.from(parts[0], 'base64').toString()),
      payload: JSON.parse(Buffer.from(parts[1], 'base64').toString()),
      signature: parts[2]
    };
  }

  private containsSensitiveData(payload: any): boolean {
    const sensitiveKeys = ['password', 'secret', 'ssn', 'credit_card'];
    const payloadStr = JSON.stringify(payload).toLowerCase();
    return sensitiveKeys.some(key => payloadStr.includes(key));
  }

  private generateRecommendations(decoded: any, mode: JWTAuditMode): string[] {
    const recs: string[] = [];

    if (mode === 'blueteam') {
      recs.push('Use RS256 or ES256 for production');
      recs.push('Implement token expiration (exp claim)');
      recs.push('Use short-lived tokens with refresh mechanism');
      recs.push('Validate all claims on server side');
    } else {
      recs.push('Try algorithm confusion attack (HS256→RS256)');
      recs.push('Attempt signature stripping (alg: none)');
      recs.push('Brute force HMAC secret if HS256');
      recs.push('Check for claim manipulation vulnerabilities');
    }

    return recs;
  }
}

export default JWTAuditor;
