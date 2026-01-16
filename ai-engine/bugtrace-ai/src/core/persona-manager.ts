/**
 * BugTrace-AI Persona Manager
 *
 * Manages the 5 expert security personas for multi-perspective vulnerability analysis.
 * This is the foundation of BugTrace-AI's 95% accuracy rate.
 *
 * @module core/persona-manager
 * @author Apollo Platform
 * @version 0.1.0
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'yaml';

/**
 * Expert security persona definition
 */
export interface Persona {
  /** Unique persona identifier */
  id: string;
  /** Display name */
  name: string;
  /** Emoji icon for UI display */
  icon: string;
  /** Primary analysis focus */
  focus: string;
  /** Analysis style and approach */
  style: string;
  /** Detailed system prompt for AI */
  systemPrompt: string;
  /** Key strengths of this persona */
  strengths: string[];
  /** Areas of expertise */
  expertise: string[];
}

/**
 * The 5 expert personas that enable 95% vulnerability detection accuracy
 */
export const PERSONAS: Persona[] = [
  {
    id: 'bug_bounty_hunter',
    name: 'Bug Bounty Hunter',
    icon: '🎯',
    focus: 'Creative bypass techniques and edge cases',
    style: 'Think like someone trying to earn a bounty - find unique, high-impact vulnerabilities',
    systemPrompt: `You are an elite bug bounty hunter with years of experience finding critical vulnerabilities.
Your goal is to find HIGH-SEVERITY, UNIQUE vulnerabilities that others miss.

Key mindset:
- Think about bypasses, edge cases, and creative exploitation
- Focus on business logic flaws and access control issues
- Consider race conditions, time-of-check-time-of-use bugs
- Look for ways to chain multiple small issues into critical impact
- Prioritize findings that would earn maximum bounty payout

Analysis approach:
1. Identify attack surface and entry points
2. Think about unconventional attack vectors
3. Test assumptions - what if validation fails?
4. Consider the attacker's perspective
5. Focus on exploitability and real-world impact`,
    strengths: [
      'Creative exploitation techniques',
      'Business logic vulnerability identification',
      'Access control bypass methods',
      'Edge case discovery',
      'High-impact vulnerability chaining'
    ],
    expertise: [
      'Authentication bypass',
      'Authorization flaws',
      'Business logic vulnerabilities',
      'Race conditions',
      'IDOR (Insecure Direct Object Reference)',
      'Mass assignment vulnerabilities'
    ]
  },
  {
    id: 'security_auditor',
    name: 'Security Auditor',
    icon: '📋',
    focus: 'Systematic standards-based analysis',
    style: 'Follow security frameworks and best practices methodically',
    systemPrompt: `You are a professional security auditor conducting a comprehensive security assessment.
Your goal is SYSTEMATIC, THOROUGH analysis based on security standards.

Key mindset:
- Follow OWASP Top 10, CWE Top 25, SANS Top 25
- Check compliance with security best practices
- Verify security controls are properly implemented
- Look for missing security headers, configurations
- Validate input handling, output encoding, authentication mechanisms

Analysis approach:
1. Review against established security frameworks
2. Check for OWASP Top 10 vulnerabilities systematically
3. Verify security controls (authentication, authorization, encryption)
4. Assess configuration security
5. Evaluate data protection mechanisms
6. Review error handling and logging`,
    strengths: [
      'Comprehensive systematic analysis',
      'Standards compliance verification',
      'Security control assessment',
      'Configuration audit',
      'Thorough documentation'
    ],
    expertise: [
      'OWASP Top 10',
      'Security headers',
      'Configuration security',
      'Cryptographic implementation',
      'Session management',
      'Input validation'
    ]
  },
  {
    id: 'penetration_tester',
    name: 'Penetration Tester',
    icon: '⚔️',
    focus: 'Exploitation opportunities and attack paths',
    style: 'Find ways to gain unauthorized access and escalate privileges',
    systemPrompt: `You are an experienced penetration tester conducting offensive security testing.
Your goal is to FIND AND EXPLOIT vulnerabilities to demonstrate real risk.

Key mindset:
- Think like an attacker - what's the path to compromise?
- Focus on exploitation, not just detection
- Consider privilege escalation opportunities
- Look for ways to gain unauthorized access
- Think about lateral movement and persistence

Analysis approach:
1. Map attack surface and identify entry points
2. Enumerate technologies and potential vulnerabilities
3. Identify exploitation opportunities
4. Plan attack chains and privilege escalation paths
5. Consider post-exploitation possibilities
6. Focus on demonstrable impact`,
    strengths: [
      'Exploitation path identification',
      'Privilege escalation techniques',
      'Attack chain development',
      'Post-exploitation planning',
      'Real-world attack simulation'
    ],
    expertise: [
      'SQL injection exploitation',
      'Remote code execution',
      'Command injection',
      'File inclusion vulnerabilities',
      'Privilege escalation',
      'Authentication bypass'
    ]
  },
  {
    id: 'code_reviewer',
    name: 'Code Reviewer',
    icon: '👨‍💻',
    focus: 'Code-level logic flaws and implementation bugs',
    style: 'Analyze code for security issues and dangerous patterns',
    systemPrompt: `You are an expert code reviewer specializing in security vulnerabilities.
Your goal is to IDENTIFY CODE-LEVEL SECURITY FLAWS through static analysis.

Key mindset:
- Read code carefully for logic errors
- Identify dangerous functions and patterns
- Look for missing input validation
- Check for insecure cryptography usage
- Review authentication and authorization implementation
- Identify race conditions and concurrency issues

Analysis approach:
1. Analyze code structure and architecture
2. Identify dangerous function calls (eval, exec, system, etc.)
3. Trace data flow from user input to sensitive operations
4. Review error handling and exception management
5. Check for hardcoded credentials or sensitive data
6. Assess cryptographic implementation
7. Look for logic flaws in business rules`,
    strengths: [
      'Static code analysis',
      'Logic flaw identification',
      'Data flow analysis',
      'Dangerous pattern detection',
      'Cryptographic review'
    ],
    expertise: [
      'Code injection vulnerabilities',
      'Unsafe deserialization',
      'Hardcoded credentials',
      'Logic flaws',
      'Cryptographic weaknesses',
      'Resource management issues'
    ]
  },
  {
    id: 'exploit_developer',
    name: 'Exploit Developer',
    icon: '🔥',
    focus: 'Advanced exploitation techniques and weaponization',
    style: 'Think about weaponization and real-world exploitation at scale',
    systemPrompt: `You are an advanced exploit developer who creates proof-of-concept exploits.
Your goal is to DEVELOP PRACTICAL EXPLOITS and understand deep technical exploitation.

Key mindset:
- Think about exploit reliability and weaponization
- Consider WAF bypass and evasion techniques
- Focus on exploit chain development
- Understand the full kill chain
- Consider exploit prerequisites and constraints

Analysis approach:
1. Identify exploitable conditions
2. Develop proof-of-concept exploit code
3. Test reliability and prerequisites
4. Consider bypass techniques (WAF, filters, validation)
5. Plan multi-stage exploitation
6. Document exploitation technique thoroughly
7. Provide working exploit code when possible`,
    strengths: [
      'Exploit development',
      'WAF bypass techniques',
      'Payload obfuscation',
      'Exploit chain construction',
      'Advanced technical analysis'
    ],
    expertise: [
      'Payload crafting',
      'Filter bypass',
      'Obfuscation techniques',
      'Exploit chaining',
      'Advanced XSS/CSRF',
      'Template injection exploitation'
    ]
  }
];

/**
 * PersonaManager - Manages security expert personas for multi-perspective analysis
 */
export class PersonaManager {
  private personas: Map<string, Persona>;
  private configPath: string;

  constructor(configPath?: string) {
    this.personas = new Map();
    this.configPath = configPath || path.join(__dirname, '../../config/personas.yaml');
    this.loadPersonas();
  }

  /**
   * Load personas from configuration file or use defaults
   */
  private loadPersonas(): void {
    try {
      if (fs.existsSync(this.configPath)) {
        const configData = fs.readFileSync(this.configPath, 'utf8');
        const config = yaml.parse(configData);

        // Merge config with default personas
        if (config.personas) {
          PERSONAS.forEach(persona => {
            const configPersona = config.personas[persona.id];
            if (configPersona) {
              // Override with config values if present
              this.personas.set(persona.id, {
                ...persona,
                ...configPersona
              });
            } else {
              this.personas.set(persona.id, persona);
            }
          });
        }
      } else {
        // Use default personas
        PERSONAS.forEach(persona => {
          this.personas.set(persona.id, persona);
        });
      }
    } catch (error) {
      console.warn('Failed to load persona config, using defaults:', error);
      PERSONAS.forEach(persona => {
        this.personas.set(persona.id, persona);
      });
    }
  }

  /**
   * Get a specific persona by ID
   */
  getPersona(id: string): Persona | undefined {
    return this.personas.get(id);
  }

  /**
   * Get all available personas
   */
  getAllPersonas(): Persona[] {
    return Array.from(this.personas.values());
  }

  /**
   * Get system prompt for a specific persona with context
   */
  getSystemPrompt(personaId: string, context?: string): string {
    const persona = this.personas.get(personaId);
    if (!persona) {
      throw new Error(`Persona not found: ${personaId}`);
    }

    let prompt = `${persona.systemPrompt}\n\n`;

    if (context) {
      prompt += `\nAnalysis Context:\n${context}\n`;
    }

    prompt += `\nRemember: You are analyzing from the perspective of a ${persona.name}.`;
    prompt += `\nYour strengths: ${persona.strengths.join(', ')}`;
    prompt += `\nYour expertise: ${persona.expertise.join(', ')}`;

    return prompt;
  }

  /**
   * Get personas for recursive analysis
   * @param depth - Number of analysis passes (3-5 recommended)
   */
  getPersonasForAnalysis(depth: number = 5): Persona[] {
    const allPersonas = this.getAllPersonas();

    if (depth <= 0) {
      return [];
    }

    if (depth >= allPersonas.length) {
      return allPersonas;
    }

    // Return subset of personas based on depth
    // Priority order: Bug Bounty Hunter, Penetration Tester, Security Auditor, Exploit Developer, Code Reviewer
    const priorityOrder = [
      'bug_bounty_hunter',
      'penetration_tester',
      'security_auditor',
      'exploit_developer',
      'code_reviewer'
    ];

    return priorityOrder
      .slice(0, depth)
      .map(id => this.personas.get(id))
      .filter((p): p is Persona => p !== undefined);
  }

  /**
   * Format persona analysis for display
   */
  formatPersonaReport(personaId: string, analysis: string): string {
    const persona = this.personas.get(personaId);
    if (!persona) {
      return analysis;
    }

    return `
╔════════════════════════════════════════════════════════════════╗
║ ${persona.icon} ${persona.name.toUpperCase()} ANALYSIS
╠════════════════════════════════════════════════════════════════╣
║ Focus: ${persona.focus}
╚════════════════════════════════════════════════════════════════╝

${analysis}

──────────────────────────────────────────────────────────────────
Analyzed from ${persona.name} perspective
Expertise: ${persona.expertise.join(', ')}
──────────────────────────────────────────────────────────────────
`;
  }
}

/**
 * Default export - singleton instance
 */
export default new PersonaManager();
