/**
 * BugTrace-AI Consolidation Engine
 *
 * AI-powered consolidation of findings from multiple persona analyses.
 * This is critical for achieving 95% accuracy by merging complementary insights
 * and de-duplicating similar findings.
 *
 * @module core/consolidation-engine
 * @author Apollo Platform
 * @version 0.1.0
 */

import { PersonaAnalysisResult, VulnerabilityFinding } from './ai-orchestrator';
import { AIModel } from '../models/model-config';

/**
 * Consolidation strategy
 */
export type ConsolidationStrategy = 'ai-powered' | 'rule-based' | 'hybrid';

/**
 * Consolidation options
 */
export interface ConsolidationOptions {
  /** Consolidation strategy */
  strategy?: ConsolidationStrategy;
  /** Minimum confidence threshold */
  minConfidence?: number;
  /** Similarity threshold for de-duplication (0-1) */
  similarityThreshold?: number;
  /** Maximum findings to return */
  maxFindings?: number;
}

/**
 * Finding similarity score
 */
interface SimilarityScore {
  finding1: VulnerabilityFinding;
  finding2: VulnerabilityFinding;
  score: number;
  reason: string;
}

/**
 * ConsolidationEngine - AI-powered consolidation of multi-persona findings
 */
export class ConsolidationEngine {
  /**
   * Consolidate findings from multiple persona analyses
   */
  async consolidate(
    personaResults: PersonaAnalysisResult[],
    model: AIModel,
    options: ConsolidationOptions = {}
  ): Promise<VulnerabilityFinding[]> {
    const strategy = options.strategy || 'hybrid';
    const minConfidence = options.minConfidence || 50;
    const similarityThreshold = options.similarityThreshold || 0.8;

    console.log(`  Using ${strategy} consolidation strategy...`);

    // Collect all findings
    const allFindings: VulnerabilityFinding[] = [];
    for (const result of personaResults) {
      allFindings.push(...result.findings);
    }

    console.log(`  Input: ${allFindings.length} raw findings from ${personaResults.length} personas`);

    if (allFindings.length === 0) {
      return [];
    }

    // Step 1: Filter by confidence
    const confidentFindings = allFindings.filter(f => f.confidence >= minConfidence);
    console.log(`  After confidence filter (>=${minConfidence}%): ${confidentFindings.length} findings`);

    // Step 2: De-duplicate similar findings
    let deduplicatedFindings: VulnerabilityFinding[];

    if (strategy === 'ai-powered') {
      deduplicatedFindings = await this.aiPoweredDeduplication(
        confidentFindings,
        model,
        similarityThreshold
      );
    } else if (strategy === 'rule-based') {
      deduplicatedFindings = this.ruleBasedDeduplication(
        confidentFindings,
        similarityThreshold
      );
    } else {
      // Hybrid: rule-based first, then AI refinement
      const ruleBased = this.ruleBasedDeduplication(
        confidentFindings,
        similarityThreshold
      );
      deduplicatedFindings = await this.aiRefinement(ruleBased, model);
    }

    console.log(`  After de-duplication: ${deduplicatedFindings.length} unique findings`);

    // Step 3: Merge complementary insights
    const mergedFindings = this.mergeComplementaryInsights(deduplicatedFindings);
    console.log(`  After merging insights: ${mergedFindings.length} consolidated findings`);

    // Step 4: Rank by severity and confidence
    const rankedFindings = this.rankFindings(mergedFindings);

    // Step 5: Apply max findings limit if specified
    const finalFindings = options.maxFindings
      ? rankedFindings.slice(0, options.maxFindings)
      : rankedFindings;

    return finalFindings;
  }

  /**
   * AI-powered de-duplication
   */
  private async aiPoweredDeduplication(
    findings: VulnerabilityFinding[],
    model: AIModel,
    threshold: number
  ): Promise<VulnerabilityFinding[]> {
    console.log('    Running AI-powered de-duplication...');

    // Group similar findings
    const groups = await this.groupSimilarFindings(findings, model, threshold);

    // Consolidate each group into single finding
    const consolidated: VulnerabilityFinding[] = [];

    for (const group of groups) {
      if (group.length === 1) {
        consolidated.push(group[0]);
      } else {
        // Merge multiple findings into one
        const merged = await this.mergeFindings(group, model);
        consolidated.push(merged);
      }
    }

    return consolidated;
  }

  /**
   * Rule-based de-duplication
   */
  private ruleBasedDeduplication(
    findings: VulnerabilityFinding[],
    threshold: number
  ): VulnerabilityFinding[] {
    console.log('    Running rule-based de-duplication...');

    const groups: VulnerabilityFinding[][] = [];
    const used = new Set<number>();

    for (let i = 0; i < findings.length; i++) {
      if (used.has(i)) continue;

      const group = [findings[i]];
      used.add(i);

      for (let j = i + 1; j < findings.length; j++) {
        if (used.has(j)) continue;

        const similarity = this.calculateSimilarity(findings[i], findings[j]);

        if (similarity >= threshold) {
          group.push(findings[j]);
          used.add(j);
        }
      }

      groups.push(group);
    }

    // Merge each group
    return groups.map(group => {
      if (group.length === 1) {
        return group[0];
      }
      return this.simpleMerge(group);
    });
  }

  /**
   * Calculate similarity between two findings (0-1)
   */
  private calculateSimilarity(
    finding1: VulnerabilityFinding,
    finding2: VulnerabilityFinding
  ): number {
    let score = 0;
    let maxScore = 0;

    // Title similarity (40% weight)
    maxScore += 0.4;
    const titleSim = this.stringSimilarity(finding1.title, finding2.title);
    score += titleSim * 0.4;

    // Location similarity (30% weight)
    maxScore += 0.3;
    const locationSim = this.stringSimilarity(finding1.location, finding2.location);
    score += locationSim * 0.3;

    // Severity match (15% weight)
    maxScore += 0.15;
    if (finding1.severity === finding2.severity) {
      score += 0.15;
    }

    // CWE match (15% weight)
    maxScore += 0.15;
    if (finding1.cwe && finding2.cwe && finding1.cwe === finding2.cwe) {
      score += 0.15;
    }

    return maxScore > 0 ? score / maxScore : 0;
  }

  /**
   * Calculate string similarity (Levenshtein distance normalized)
   */
  private stringSimilarity(str1: string, str2: string): number {
    const s1 = str1.toLowerCase();
    const s2 = str2.toLowerCase();

    if (s1 === s2) return 1;
    if (s1.length === 0 || s2.length === 0) return 0;

    const distance = this.levenshteinDistance(s1, s2);
    const maxLen = Math.max(s1.length, s2.length);

    return 1 - distance / maxLen;
  }

  /**
   * Calculate Levenshtein distance between two strings
   */
  private levenshteinDistance(str1: string, str2: string): number {
    const m = str1.length;
    const n = str2.length;
    const dp: number[][] = Array(m + 1)
      .fill(null)
      .map(() => Array(n + 1).fill(0));

    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        if (str1[i - 1] === str2[j - 1]) {
          dp[i][j] = dp[i - 1][j - 1];
        } else {
          dp[i][j] = Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]) + 1;
        }
      }
    }

    return dp[m][n];
  }

  /**
   * Simple merge of similar findings
   */
  private simpleMerge(findings: VulnerabilityFinding[]): VulnerabilityFinding {
    // Use the finding with highest confidence as base
    const sorted = [...findings].sort((a, b) => b.confidence - a.confidence);
    const base = { ...sorted[0] };

    // Combine foundBy arrays
    const allFoundBy = new Set<string>();
    findings.forEach(f => f.foundBy.forEach(p => allFoundBy.add(p)));
    base.foundBy = Array.from(allFoundBy);

    // Average confidence
    const avgConfidence = findings.reduce((sum, f) => sum + f.confidence, 0) / findings.length;
    base.confidence = Math.round(avgConfidence);

    // Merge descriptions
    const uniqueDescriptions = new Set(findings.map(f => f.description));
    if (uniqueDescriptions.size > 1) {
      base.description = Array.from(uniqueDescriptions).join('\n\n');
    }

    // Merge POCs
    const pocs = findings.map(f => f.poc).filter(Boolean);
    if (pocs.length > 1) {
      base.poc = pocs.join('\n\n---\n\n');
    }

    return base;
  }

  /**
   * Group similar findings using AI
   */
  private async groupSimilarFindings(
    findings: VulnerabilityFinding[],
    model: AIModel,
    threshold: number
  ): Promise<VulnerabilityFinding[][]> {
    // Placeholder - in production, this would use AI to group findings
    // For now, fall back to rule-based grouping
    const groups: VulnerabilityFinding[][] = [];
    const used = new Set<number>();

    for (let i = 0; i < findings.length; i++) {
      if (used.has(i)) continue;

      const group = [findings[i]];
      used.add(i);

      for (let j = i + 1; j < findings.length; j++) {
        if (used.has(j)) continue;

        const similarity = this.calculateSimilarity(findings[i], findings[j]);

        if (similarity >= threshold) {
          group.push(findings[j]);
          used.add(j);
        }
      }

      groups.push(group);
    }

    return groups;
  }

  /**
   * Merge multiple findings into one using AI
   */
  private async mergeFindings(
    findings: VulnerabilityFinding[],
    model: AIModel
  ): Promise<VulnerabilityFinding> {
    // Placeholder - in production, this would use AI to create optimal merge
    // For now, use simple merge
    return this.simpleMerge(findings);
  }

  /**
   * AI refinement of consolidated findings
   */
  private async aiRefinement(
    findings: VulnerabilityFinding[],
    model: AIModel
  ): Promise<VulnerabilityFinding[]> {
    // Placeholder - in production, this would use AI to refine findings
    return findings;
  }

  /**
   * Merge complementary insights from different personas
   */
  private mergeComplementaryInsights(
    findings: VulnerabilityFinding[]
  ): VulnerabilityFinding[] {
    // Group findings by CWE/OWASP category
    const categoryGroups = new Map<string, VulnerabilityFinding[]>();

    for (const finding of findings) {
      const key = finding.cwe || finding.owasp || finding.title;

      if (!categoryGroups.has(key)) {
        categoryGroups.set(key, []);
      }

      categoryGroups.get(key)!.push(finding);
    }

    // For each category, check if findings are complementary
    const merged: VulnerabilityFinding[] = [];

    for (const [category, groupFindings] of categoryGroups) {
      if (groupFindings.length === 1) {
        merged.push(groupFindings[0]);
        continue;
      }

      // Check if findings are truly different or complementary
      const unique = this.identifyUniqueFindings(groupFindings);
      merged.push(...unique);
    }

    return merged;
  }

  /**
   * Identify truly unique findings from a group
   */
  private identifyUniqueFindings(
    findings: VulnerabilityFinding[]
  ): VulnerabilityFinding[] {
    const unique: VulnerabilityFinding[] = [];
    const used = new Set<number>();

    for (let i = 0; i < findings.length; i++) {
      if (used.has(i)) continue;

      const similar: VulnerabilityFinding[] = [findings[i]];
      used.add(i);

      for (let j = i + 1; j < findings.length; j++) {
        if (used.has(j)) continue;

        // Check if locations are very similar
        const locSim = this.stringSimilarity(
          findings[i].location,
          findings[j].location
        );

        if (locSim > 0.9) {
          similar.push(findings[j]);
          used.add(j);
        }
      }

      // Merge similar findings
      unique.push(this.simpleMerge(similar));
    }

    return unique;
  }

  /**
   * Rank findings by severity and confidence
   */
  private rankFindings(findings: VulnerabilityFinding[]): VulnerabilityFinding[] {
    const severityOrder = {
      critical: 5,
      high: 4,
      medium: 3,
      low: 2,
      info: 1
    };

    return [...findings].sort((a, b) => {
      // First by severity
      const sevDiff = severityOrder[b.severity] - severityOrder[a.severity];
      if (sevDiff !== 0) return sevDiff;

      // Then by confidence
      return b.confidence - a.confidence;
    });
  }

  /**
   * Generate consolidation report
   */
  generateConsolidationReport(
    original: PersonaAnalysisResult[],
    consolidated: VulnerabilityFinding[]
  ): string {
    const totalOriginal = original.reduce((sum, r) => sum + r.findings.length, 0);

    let report = '═════════════════════════════════════════════════════════\n';
    report += '           CONSOLIDATION REPORT\n';
    report += '═════════════════════════════════════════════════════════\n\n';

    report += `Original Findings: ${totalOriginal}\n`;
    report += `Consolidated Findings: ${consolidated.length}\n`;
    report += `Reduction: ${((1 - consolidated.length / totalOriginal) * 100).toFixed(1)}%\n\n`;

    report += 'Findings by Persona:\n';
    for (const result of original) {
      report += `  ${result.persona.icon} ${result.persona.name}: ${result.findings.length}\n`;
    }

    report += '\nConsolidated by Severity:\n';
    const bySeverity = {
      critical: consolidated.filter(f => f.severity === 'critical').length,
      high: consolidated.filter(f => f.severity === 'high').length,
      medium: consolidated.filter(f => f.severity === 'medium').length,
      low: consolidated.filter(f => f.severity === 'low').length,
      info: consolidated.filter(f => f.severity === 'info').length
    };

    report += `  Critical: ${bySeverity.critical}\n`;
    report += `  High: ${bySeverity.high}\n`;
    report += `  Medium: ${bySeverity.medium}\n`;
    report += `  Low: ${bySeverity.low}\n`;
    report += `  Info: ${bySeverity.info}\n\n`;

    report += 'Multi-Persona Findings (found by 2+ personas):\n';
    const multiPersona = consolidated.filter(f => f.foundBy.length > 1);
    report += `  Count: ${multiPersona.length}\n`;

    if (multiPersona.length > 0) {
      multiPersona.slice(0, 3).forEach(f => {
        report += `  - ${f.title} (found by ${f.foundBy.length} personas)\n`;
      });
    }

    report += '\n═════════════════════════════════════════════════════════\n';

    return report;
  }
}

export default ConsolidationEngine;
