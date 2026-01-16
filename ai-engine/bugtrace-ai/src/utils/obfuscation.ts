/**
 * BugTrace-AI Obfuscation Utilities
 * 14+ obfuscation techniques for WAF bypass
 * @module utils/obfuscation
 */

export type ObfuscationTechnique =
  | 'unicode'
  | 'html-entity'
  | 'string-concat'
  | 'comment-insertion'
  | 'case-variation'
  | 'hex-encoding'
  | 'octal-encoding'
  | 'base64'
  | 'jsfuck'
  | 'double-encoding'
  | 'null-byte'
  | 'mixed-encoding'
  | 'context-specific'
  | 'protocol-switch';

export class Obfuscator {
  /**
   * Apply obfuscation technique to payload
   */
  obfuscate(payload: string, technique: ObfuscationTechnique, context?: string): string {
    switch (technique) {
      case 'unicode':
        return this.unicodeEncode(payload);
      case 'html-entity':
        return this.htmlEntityEncode(payload);
      case 'string-concat':
        return this.stringConcat(payload);
      case 'comment-insertion':
        return this.commentInsertion(payload, context);
      case 'case-variation':
        return this.caseVariation(payload);
      case 'hex-encoding':
        return this.hexEncode(payload);
      case 'octal-encoding':
        return this.octalEncode(payload);
      case 'base64':
        return this.base64Encode(payload);
      case 'jsfuck':
        return this.jsfuckEncode(payload);
      case 'double-encoding':
        return this.doubleEncode(payload);
      case 'null-byte':
        return this.nullByteInjection(payload);
      case 'mixed-encoding':
        return this.mixedEncode(payload);
      case 'context-specific':
        return this.contextSpecific(payload, context);
      case 'protocol-switch':
        return this.protocolSwitch(payload);
      default:
        return payload;
    }
  }

  private unicodeEncode(str: string): string {
    return str.split('').map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('');
  }

  private htmlEntityEncode(str: string): string {
    return str.split('').map(c => `&#${c.charCodeAt(0)};`).join('');
  }

  private stringConcat(str: string): string {
    // Split into chunks and concatenate
    const chunks = str.match(/.{1,2}/g) || [];
    return chunks.map(c => `'${c}'`).join('+');
  }

  private commentInsertion(str: string, context?: string): string {
    if (context === 'sql') {
      return str.split('').join('/**/');
    } else if (context === 'javascript') {
      return str.split('').join('//\n');
    }
    return str.split('').join('/* */');
  }

  private caseVariation(str: string): string {
    return str.split('').map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join('');
  }

  private hexEncode(str: string): string {
    return str.split('').map(c => `\\x${c.charCodeAt(0).toString(16)}`).join('');
  }

  private octalEncode(str: string): string {
    return str.split('').map(c => `\\${c.charCodeAt(0).toString(8)}`).join('');
  }

  private base64Encode(str: string): string {
    return `atob('${Buffer.from(str).toString('base64')}')`;
  }

  private jsfuckEncode(str: string): string {
    // Simplified JSFuck - real implementation would be much longer
    return `[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+(![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]+[+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]])()`;
  }

  private doubleEncode(str: string): string {
    const firstEncode = encodeURIComponent(str);
    return encodeURIComponent(firstEncode);
  }

  private nullByteInjection(str: string): string {
    return str + '%00';
  }

  private mixedEncode(str: string): string {
    // Combine multiple techniques
    let result = '';
    for (let i = 0; i < str.length; i++) {
      const char = str[i];
      const technique = i % 3;

      if (technique === 0) {
        result += `\\x${char.charCodeAt(0).toString(16)}`;
      } else if (technique === 1) {
        result += `&#${char.charCodeAt(0)};`;
      } else {
        result += char;
      }
    }
    return result;
  }

  private contextSpecific(str: string, context?: string): string {
    if (context === 'sql') {
      return str.replace(/'/g, "''");
    } else if (context === 'javascript') {
      return str.replace(/"/g, '\\"');
    } else if (context === 'html') {
      return this.htmlEntityEncode(str);
    }
    return str;
  }

  private protocolSwitch(str: string): string {
    // Switch protocols to bypass filters
    return str.replace(/https?:\/\//g, '//').replace(/http:/g, 'javascript:');
  }
}

export default new Obfuscator();
