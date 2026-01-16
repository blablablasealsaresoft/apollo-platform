# BugTrace-AI API Documentation

## Table of Contents

- [Core API](#core-api)
  - [AIOrchestrator](#aiorchestrator)
  - [PersonaManager](#personamanager)
  - [ConsolidationEngine](#consolidationengine)
  - [DeepAnalysis](#deepanalysis)
- [Analyzers](#analyzers)
- [Reconnaissance](#reconnaissance)
- [Payload Generation](#payload-generation)
- [Utilities](#utilities)

---

## Core API

### AIOrchestrator

The main entry point for BugTrace-AI analysis. Orchestrates multi-persona recursive vulnerability analysis.

#### Constructor

```typescript
import { AIOrchestrator } from '@apollo/bugtrace-ai';

const orchestrator = new AIOrchestrator(model?: AIModel);
```

**Parameters:**
- `model` (optional): AI model configuration
  - `provider`: 'google' | 'anthropic' | 'openai'
  - `model`: Model name (e.g., 'gemini-flash')
  - `temperature`: 0-1 (default: 0.7)
  - `maxTokens`: Maximum tokens (default: 8000)

#### analyze()

Perform multi-persona recursive vulnerability analysis.

```typescript
async analyze(
  target: AnalysisTarget,
  options?: AnalysisOptions
): Promise<AnalysisResult>
```

**Parameters:**

`target`:
```typescript
{
  url?: string;           // Target URL
  code?: string;          // Source code to analyze
  language?: string;      // Programming language
  framework?: string;     // Framework name
  context?: string;       // Additional context
  focus?: string[];       // Analysis focus areas
}
```

`options`:
```typescript
{
  model?: AIModel;                // AI model to use
  depth?: number;                 // Analysis depth (3-5 personas)
  enableConsolidation?: boolean;  // AI-powered consolidation (default: true)
  enableDeepAnalysis?: boolean;   // Deep analysis refinement (default: false)
  maxConcurrent?: number;         // Max concurrent analyses (default: 3)
  timeout?: number;               // Analysis timeout in ms
}
```

**Returns:**

```typescript
{
  target: AnalysisTarget;
  personaResults: PersonaAnalysisResult[];
  findings: VulnerabilityFinding[];
  summary: {
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    analysisTime: number;
    personasUsed: number;
  };
  timestamp: Date;
}
```

**Example:**

```typescript
const result = await orchestrator.analyze(
  {
    url: 'https://target.com',
    focus: ['authentication', 'sql-injection']
  },
  {
    depth: 5,
    enableConsolidation: true,
    enableDeepAnalysis: true
  }
);

console.log(`Found ${result.findings.length} vulnerabilities`);
```

---

### PersonaManager

Manages the 5 expert security personas for multi-perspective analysis.

#### Constructor

```typescript
import { PersonaManager } from '@apollo/bugtrace-ai/core/persona-manager';

const personaManager = new PersonaManager(configPath?: string);
```

#### Methods

##### getPersona()

```typescript
getPersona(id: string): Persona | undefined
```

Get a specific persona by ID.

**Parameters:**
- `id`: 'bug_bounty_hunter' | 'security_auditor' | 'penetration_tester' | 'code_reviewer' | 'exploit_developer'

##### getAllPersonas()

```typescript
getAllPersonas(): Persona[]
```

Get all available personas.

##### getPersonasForAnalysis()

```typescript
getPersonasForAnalysis(depth: number = 5): Persona[]
```

Get personas for recursive analysis based on depth.

**Example:**

```typescript
const personas = personaManager.getPersonasForAnalysis(5);
console.log(`Using ${personas.length} personas`);
```

---

## Analyzers

### URLAnalyzer

Dynamic Application Security Testing (DAST) with 3 modes.

#### Constructor

```typescript
import { URLAnalyzer } from '@apollo/bugtrace-ai/analyzers/url-analysis';

const analyzer = new URLAnalyzer(model?: AIModel);
```

#### analyze()

```typescript
async analyze(options: URLAnalysisOptions): Promise<URLAnalysisResult>
```

**Options:**

```typescript
{
  mode: 'recon' | 'active' | 'greybox';
  url: string;
  model?: AIModel;
  credentials?: {
    username?: string;
    password?: string;
    token?: string;
    cookies?: Record<string, string>;
  };
  depth?: number;
  focus?: string[];
}
```

**Example:**

```typescript
const result = await analyzer.analyze({
  url: 'https://target.com',
  mode: 'active',
  depth: 20,
  focus: ['authentication', 'sql-injection']
});
```

---

### CodeAnalyzer

Static Application Security Testing (SAST).

#### Constructor

```typescript
import { CodeAnalyzer } from '@apollo/bugtrace-ai/analyzers/code-analysis';

const analyzer = new CodeAnalyzer(model?: AIModel);
```

#### analyze()

```typescript
async analyze(options: CodeAnalysisOptions): Promise<CodeAnalysisResult>
```

**Options:**

```typescript
{
  code: string;
  language: 'javascript' | 'typescript' | 'python' | 'php' | 'java' | 'csharp' | 'go' | 'ruby' | 'rust';
  framework?: string;
  model?: AIModel;
  focus?: string[];
}
```

**Example:**

```typescript
const result = await analyzer.analyze({
  code: sourceCode,
  language: 'javascript',
  framework: 'express'
});
```

---

### DOMXSSPathfinder

AI-powered data flow analysis for DOM-based XSS.

#### Constructor

```typescript
import { DOMXSSPathfinder } from '@apollo/bugtrace-ai/analyzers/dom-xss-pathfinder';

const pathfinder = new DOMXSSPathfinder(model?: AIModel);
```

#### analyze()

```typescript
async analyze(jsCode: string): Promise<VulnerabilityFinding[]>
```

**Example:**

```typescript
const findings = await pathfinder.analyze(jsCode);
```

---

### JWTAuditor

JWT security analysis with Blue Team and Red Team modes.

#### Constructor

```typescript
import { JWTAuditor } from '@apollo/bugtrace-ai/analyzers/jwt-auditor';

const auditor = new JWTAuditor();
```

#### audit()

```typescript
async audit(token: string, mode: 'blueteam' | 'redteam' = 'blueteam'): Promise<JWTAuditResult>
```

**Example:**

```typescript
const result = await auditor.audit(jwtToken, 'redteam');
```

---

## Reconnaissance

### JSReconnaissance

Extract API endpoints, secrets, and sensitive data from JavaScript.

#### Constructor

```typescript
import { JSReconnaissance } from '@apollo/bugtrace-ai/reconnaissance/js-reconnaissance';

const recon = new JSReconnaissance();
```

#### analyze()

```typescript
async analyze(jsCode: string, url?: string): Promise<JSReconResult>
```

**Returns:**

```typescript
{
  url: string;
  endpoints: string[];
  secrets: SecretFinding[];
  apiKeys: string[];
  comments: string[];
  externalUrls: string[];
}
```

**Example:**

```typescript
const result = await recon.analyze(jsCode, 'https://target.com/app.js');
console.log(`Found ${result.endpoints.length} API endpoints`);
```

---

### SubdomainFinder

Discover subdomains using Certificate Transparency logs.

#### Constructor

```typescript
import { SubdomainFinder } from '@apollo/bugtrace-ai/reconnaissance/subdomain-finder';

const finder = new SubdomainFinder();
```

#### find()

```typescript
async find(domain: string): Promise<SubdomainResult>
```

**Example:**

```typescript
const result = await finder.find('target.com');
console.log(`Found ${result.totalFound} subdomains`);
```

---

## Payload Generation

### PayloadForge

Advanced payload generation with 14+ obfuscation techniques.

#### Constructor

```typescript
import { PayloadForge } from '@apollo/bugtrace-ai/payload/payload-forge';

const forge = new PayloadForge();
```

#### generate()

```typescript
generate(options: PayloadOptions): Payload[]
```

**Options:**

```typescript
{
  type: 'xss' | 'sqli' | 'lfi' | 'rce' | 'xxe' | 'ssti' | 'csrf';
  base?: string;
  target?: string;        // WAF type
  context?: string;       // HTML, JavaScript, SQL, etc.
  variations?: number;
  techniques?: ObfuscationTechnique[];
}
```

**Example:**

```typescript
const payloads = forge.generate({
  type: 'xss',
  base: '<script>alert(1)</script>',
  target: 'ModSecurity',
  variations: 20
});

console.log(`Generated ${payloads.length} payload variations`);
```

---

### SSTIForge

Server-Side Template Injection payloads for 10+ template engines.

#### Constructor

```typescript
import { SSTIForge } from '@apollo/bugtrace-ai/payload/ssti-forge';

const sstiForge = new SSTIForge();
```

#### generate()

```typescript
generate(
  engine: TemplateEngine,
  goal: 'detect' | 'rce' | 'file-read' | 'file-write' | 'info-disclosure',
  target?: string
): SSTIPayload[]
```

**Template Engines:**
- jinja2 (Flask/Django)
- twig (Symfony)
- freemarker (Java)
- velocity (Java)
- thymeleaf (Spring)
- pug (Node.js)
- handlebars (Node.js)
- ejs (Node.js)
- erb (Ruby)
- smarty (PHP)

**Example:**

```typescript
const payloads = sstiForge.generate('jinja2', 'rce', 'whoami');
```

---

### OOBHelper

Out-of-band interaction payloads for blind vulnerability detection.

#### Constructor

```typescript
import { OOBHelper } from '@apollo/bugtrace-ai/payload/oob-helper';

const oob = new OOBHelper({
  domain: 'your-callback-domain.com',
  protocol: 'dns'
});
```

#### generate()

```typescript
generate(
  vulnType: 'xxe' | 'ssrf' | 'sqli' | 'rce' | 'xss',
  protocol?: 'dns' | 'http' | 'https' | 'smtp' | 'ldap'
): OOBPayload[]
```

**Example:**

```typescript
const payloads = oob.generate('xxe', 'http');
```

---

## Utilities

### ReportGenerator

Generate comprehensive security reports.

#### Constructor

```typescript
import { ReportGenerator } from '@apollo/bugtrace-ai/utils/report-generator';

const reportGen = new ReportGenerator();
```

#### generate()

```typescript
generate(
  result: AnalysisResult,
  format: 'markdown' | 'html' | 'json' | 'pdf' | 'text' = 'markdown'
): string
```

**Example:**

```typescript
const report = reportGen.generate(analysisResult, 'markdown');
```

#### generateExecutiveSummary()

```typescript
generateExecutiveSummary(result: AnalysisResult): string
```

**Example:**

```typescript
const summary = reportGen.generateExecutiveSummary(analysisResult);
```

---

### VulnerabilityDatabase

Knowledge base of vulnerability patterns and remediation.

#### Constructor

```typescript
import { VulnerabilityDatabase } from '@apollo/bugtrace-ai/utils/vulnerability-db';

const vulnDB = new VulnerabilityDatabase();
```

#### Methods

##### getInfo()

```typescript
getInfo(vulnId: string): VulnerabilityInfo | undefined
```

##### search()

```typescript
search(query: string): VulnerabilityInfo[]
```

##### getByCWE()

```typescript
getByCWE(cwe: string): VulnerabilityInfo[]
```

**Example:**

```typescript
const info = vulnDB.getInfo('sql-injection');
const sqlVulns = vulnDB.getByCWE('CWE-89');
```

---

## Complete Example

```typescript
import { AIOrchestrator } from '@apollo/bugtrace-ai';
import { URLAnalyzer } from '@apollo/bugtrace-ai/analyzers/url-analysis';
import { PayloadForge } from '@apollo/bugtrace-ai/payload/payload-forge';
import { ReportGenerator } from '@apollo/bugtrace-ai/utils/report-generator';

async function comprehensiveAnalysis(url: string) {
  // Initialize orchestrator
  const orchestrator = new AIOrchestrator({
    provider: 'google',
    model: 'gemini-flash'
  });

  // Multi-persona analysis
  const analysis = await orchestrator.analyze(
    { url, focus: ['authentication', 'sql-injection', 'xss'] },
    { depth: 5, enableConsolidation: true, enableDeepAnalysis: true }
  );

  // DAST analysis
  const urlAnalyzer = new URLAnalyzer();
  const dast = await urlAnalyzer.analyze({
    url,
    mode: 'active',
    depth: 20
  });

  // Generate payloads for identified vulnerabilities
  const forge = new PayloadForge();
  const payloads = forge.generate({
    type: 'xss',
    target: 'ModSecurity',
    variations: 15
  });

  // Generate report
  const reportGen = new ReportGenerator();
  const report = reportGen.generate(analysis, 'markdown');

  return {
    analysis,
    dast,
    payloads,
    report
  };
}
```

---

## Error Handling

All async methods can throw errors. Always use try-catch:

```typescript
try {
  const result = await orchestrator.analyze(target, options);
} catch (error) {
  console.error('Analysis failed:', error);
}
```

---

## Type Definitions

See `src/core/ai-orchestrator.ts` and related files for complete type definitions.

---

## Support

For questions and support:
- GitHub Issues: https://github.com/apollo-platform/bugtrace-ai/issues
- Email: support@apollo-platform.com

---

**Version**: 0.1.0
**Last Updated**: January 2026
