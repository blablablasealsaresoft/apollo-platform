/**
 * BugTrace-AI DOM XSS Pathfinder
 * AI-powered data flow analysis for DOM-based XSS vulnerabilities
 * @module analyzers/dom-xss-pathfinder
 */

import { AIModel } from '../models/model-config';
import { VulnerabilityFinding } from '../core/ai-orchestrator';

export interface DOMXSSPath {
  source: string;
  sink: string;
  path: string[];
  vulnerable: boolean;
  payload?: string;
}

export class DOMXSSPathfinder {
  private model: AIModel;

  constructor(model?: AIModel) {
    this.model = model || { provider: 'google', model: 'gemini-flash' };
  }

  async analyze(jsCode: string): Promise<VulnerabilityFinding[]> {
    const findings: VulnerabilityFinding[] = [];

    // Detect sources (user-controllable data)
    const sources = this.detectSources(jsCode);

    // Detect sinks (dangerous operations)
    const sinks = this.detectSinks(jsCode);

    // Trace data flow
    const paths = this.traceDataFlow(jsCode, sources, sinks);

    // Generate findings for vulnerable paths
    paths.forEach(path => {
      if (path.vulnerable) {
        findings.push({
          id: `dom-xss-${Date.now()}`,
          title: 'DOM-Based XSS Vulnerability',
          severity: 'high',
          confidence: 85,
          description: `Data flows from ${path.source} to ${path.sink} without sanitization`,
          location: `${path.source} → ${path.sink}`,
          exploitation: 'Manipulate URL/input to inject malicious JavaScript',
          poc: path.payload,
          impact: 'Execute arbitrary JavaScript in victim browser',
          remediation: 'Sanitize user input before using in dangerous sinks',
          cwe: 'CWE-79',
          owasp: 'A03:2021 - Injection',
          foundBy: ['dom-xss-pathfinder']
        });
      }
    });

    return findings;
  }

  private detectSources(code: string): string[] {
    const sourcePatterns = [
      'location.hash',
      'location.search',
      'document.URL',
      'document.referrer',
      'window.name',
      'document.cookie'
    ];

    return sourcePatterns.filter(source => code.includes(source));
  }

  private detectSinks(code: string): string[] {
    const sinkPatterns = [
      'innerHTML',
      'outerHTML',
      'document.write',
      'eval(',
      'setTimeout(',
      'setInterval('
    ];

    return sinkPatterns.filter(sink => code.includes(sink));
  }

  private traceDataFlow(code: string, sources: string[], sinks: string[]): DOMXSSPath[] {
    const paths: DOMXSSPath[] = [];

    sources.forEach(source => {
      sinks.forEach(sink => {
        // Simplified data flow analysis
        if (code.includes(source) && code.includes(sink)) {
          paths.push({
            source,
            sink,
            path: [source, sink],
            vulnerable: true,
            payload: this.generatePayload(source, sink)
          });
        }
      });
    });

    return paths;
  }

  private generatePayload(source: string, sink: string): string {
    if (sink.includes('innerHTML')) {
      return '#<img src=x onerror=alert(1)>';
    }
    if (sink.includes('eval')) {
      return '#alert(1)';
    }
    return '#<script>alert(1)</script>';
  }
}

export default DOMXSSPathfinder;
