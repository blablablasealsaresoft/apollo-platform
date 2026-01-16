/**
 * Apollo Report Generator
 *
 * High-level report generation orchestrator that coordinates:
 * - Data formatting
 * - Template selection
 * - Multi-format export
 * - Classification handling
 * - Validation
 */

import {
  ReportType,
  ExportFormat,
  ReportGenerationOptions,
  ClassificationMarking,
  ReportSection,
  ReportChart,
  ReportTable,
  ReportImage,
  InvestigationSummaryData,
  TargetProfileData,
  EvidenceChainData,
  IntelligenceAnalysisData,
  OperationAfterActionData,
  ReportTemplate,
} from '../types';
import { CaseFormatter, caseFormatter } from '../formatters/case.formatter';
import { TargetFormatter, targetFormatter } from '../formatters/target.formatter';
import { TimelineFormatter, timelineFormatter } from '../formatters/timeline.formatter';
import { NetworkFormatter, networkFormatter } from '../formatters/network.formatter';
import { PDFExporter, pdfExporter } from '../exporters/pdf.exporter';
import { DocxExporter, docxExporter } from '../exporters/docx.exporter';
import { ExcelExporter, excelExporter } from '../exporters/excel.exporter';
import { HTMLExporter, htmlExporter } from '../exporters/html.exporter';
import { JSONExporter, jsonExporter } from '../exporters/json.exporter';
import { generateId } from '@apollo/shared';

/**
 * Formatted report data structure
 */
interface FormattedReportData {
  title: string;
  subtitle?: string;
  classification: ClassificationMarking;
  generatedDate: Date;
  author?: string;
  sections: ReportSection[];
  tables?: ReportTable[];
  charts?: ReportChart[];
  images?: ReportImage[];
  footer?: string;
  metadata?: Record<string, any>;
}

/**
 * Export result structure
 */
interface ExportResult {
  buffer: Buffer;
  mimeType: string;
  filename: string;
  checksum?: string;
}

/**
 * Report Generator class
 */
export class ReportGenerator {
  private caseFormatter: CaseFormatter;
  private targetFormatter: TargetFormatter;
  private timelineFormatter: TimelineFormatter;
  private networkFormatter: NetworkFormatter;
  private pdfExporter: PDFExporter;
  private docxExporter: DocxExporter;
  private excelExporter: ExcelExporter;
  private htmlExporter: HTMLExporter;
  private jsonExporter: JSONExporter;

  constructor() {
    this.caseFormatter = caseFormatter;
    this.targetFormatter = targetFormatter;
    this.timelineFormatter = timelineFormatter;
    this.networkFormatter = networkFormatter;
    this.pdfExporter = pdfExporter;
    this.docxExporter = docxExporter;
    this.excelExporter = excelExporter;
    this.htmlExporter = htmlExporter;
    this.jsonExporter = jsonExporter;
  }

  /**
   * Generate a complete report
   */
  async generate(
    type: ReportType,
    data: any,
    options: ReportGenerationOptions,
    template?: ReportTemplate
  ): Promise<ExportResult> {
    // Validate inputs
    this.validateInputs(type, data, options);

    // Apply template defaults if provided
    const effectiveOptions = template
      ? { ...template.defaultOptions, ...options }
      : options;

    // Format the data based on report type
    const formattedData = await this.formatData(type, data, effectiveOptions);

    // Apply template section configuration if provided
    if (template) {
      this.applyTemplateConfig(formattedData, template);
    }

    // Export to requested format
    const exportResult = await this.exportToFormat(formattedData, effectiveOptions);

    // Generate filename
    const filename = this.generateFilename(formattedData.title, type, effectiveOptions.format);

    return {
      ...exportResult,
      filename,
    };
  }

  /**
   * Generate a preview (HTML only)
   */
  async generatePreview(
    type: ReportType,
    data: any,
    options: ReportGenerationOptions
  ): Promise<string> {
    const formattedData = await this.formatData(type, data, options);
    const result = await this.htmlExporter.export(formattedData, options);
    return result.buffer.toString('utf-8');
  }

  /**
   * Validate report inputs
   */
  private validateInputs(
    type: ReportType,
    data: any,
    options: ReportGenerationOptions
  ): void {
    if (!Object.values(ReportType).includes(type)) {
      throw new Error(`Invalid report type: ${type}`);
    }

    if (!Object.values(ExportFormat).includes(options.format)) {
      throw new Error(`Invalid export format: ${options.format}`);
    }

    if (!data) {
      throw new Error('Report data is required');
    }

    // Type-specific validation
    switch (type) {
      case ReportType.INVESTIGATION_SUMMARY:
        if (!data.investigationId) {
          throw new Error('Investigation ID is required for investigation summary report');
        }
        break;
      case ReportType.TARGET_PROFILE:
        if (!data.target) {
          throw new Error('Target data is required for target profile report');
        }
        break;
      case ReportType.EVIDENCE_CHAIN:
        if (!data.investigationId || !data.evidence) {
          throw new Error('Investigation ID and evidence data are required for evidence chain report');
        }
        break;
      // Add more type-specific validations as needed
    }
  }

  /**
   * Format data based on report type
   */
  private async formatData(
    type: ReportType,
    data: any,
    options: ReportGenerationOptions
  ): Promise<FormattedReportData> {
    switch (type) {
      case ReportType.INVESTIGATION_SUMMARY:
        return this.caseFormatter.formatInvestigationSummary(
          data as InvestigationSummaryData,
          options
        );

      case ReportType.TARGET_PROFILE:
        return this.targetFormatter.formatTargetProfile(
          data as TargetProfileData,
          options
        );

      case ReportType.EVIDENCE_CHAIN:
        return this.caseFormatter.formatEvidenceChain(
          data as EvidenceChainData,
          options
        );

      case ReportType.INTELLIGENCE_ANALYSIS:
        return this.caseFormatter.formatIntelligenceAnalysis(
          data as IntelligenceAnalysisData,
          options
        );

      case ReportType.OPERATION_AFTER_ACTION:
        return this.caseFormatter.formatAfterActionReport(
          data as OperationAfterActionData,
          options
        );

      case ReportType.TIMELINE:
        return this.timelineFormatter.formatTimeline(data, options);

      case ReportType.NETWORK_MAPPING:
        return this.networkFormatter.formatNetworkMap(data, options);

      case ReportType.THREAT_ASSESSMENT:
        return this.formatThreatAssessment(data, options);

      case ReportType.FINANCIAL_ANALYSIS:
        return this.formatFinancialAnalysis(data, options);

      case ReportType.EXECUTIVE_BRIEF:
        return this.formatExecutiveBrief(data, options);

      default:
        throw new Error(`Unsupported report type: ${type}`);
    }
  }

  /**
   * Format threat assessment report
   */
  private formatThreatAssessment(
    data: any,
    options: ReportGenerationOptions
  ): FormattedReportData {
    const sections: ReportSection[] = [];
    const tables: ReportTable[] = [];
    const charts: ReportChart[] = [];

    // Executive Summary
    sections.push({
      id: generateId(),
      title: 'Executive Summary',
      content: `This threat assessment covers ${data.threats?.length || 0} identified threat(s).`,
      order: 1,
    });

    // Threat Overview
    if (data.threats && data.threats.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Threat Overview',
        content: 'The following threats have been identified and assessed:',
        order: 2,
        subsections: data.threats.map((threat: any, index: number) => ({
          id: generateId(),
          title: `Threat ${index + 1}: ${threat.name || 'Unknown'}`,
          content: `Level: ${threat.threat_level || 'Unknown'}\n${threat.description || ''}`,
          order: index + 1,
        })),
      });

      // Threat table
      tables.push({
        id: generateId(),
        title: 'Threats Summary',
        headers: ['#', 'Threat', 'Level', 'Target', 'Status'],
        rows: data.threats.map((t: any, i: number) => [
          (i + 1).toString(),
          t.name || 'Unknown',
          t.threat_level || 'Unknown',
          t.target_name || 'N/A',
          t.status || 'Active',
        ]),
        striped: true,
        bordered: true,
      });

      // Threat level distribution chart
      const levelCounts: Record<string, number> = {};
      data.threats.forEach((t: any) => {
        const level = t.threat_level || 'unknown';
        levelCounts[level] = (levelCounts[level] || 0) + 1;
      });

      charts.push({
        id: generateId(),
        type: 'pie',
        title: 'Threats by Level',
        data: {
          labels: Object.keys(levelCounts),
          values: Object.values(levelCounts),
        },
      });
    }

    // Recommendations
    sections.push({
      id: generateId(),
      title: 'Recommendations',
      content: 'Based on the assessed threats, the following actions are recommended.',
      order: 3,
    });

    return {
      title: 'Threat Assessment Report',
      classification: options.classification,
      generatedDate: new Date(),
      sections,
      tables,
      charts,
      metadata: {
        reportId: generateId(),
        type: 'threat_assessment',
      },
    };
  }

  /**
   * Format financial analysis report
   */
  private formatFinancialAnalysis(
    data: any,
    options: ReportGenerationOptions
  ): FormattedReportData {
    const sections: ReportSection[] = [];
    const tables: ReportTable[] = [];
    const charts: ReportChart[] = [];

    // Executive Summary
    sections.push({
      id: generateId(),
      title: 'Executive Summary',
      content: `Financial analysis for target. ${data.transactions?.length || 0} transaction(s) analyzed.`,
      order: 1,
    });

    // Financial Profile
    if (data.profile) {
      sections.push({
        id: generateId(),
        title: 'Financial Profile',
        content: `Estimated Net Worth: ${data.profile.estimated_net_worth || 'Unknown'}\nRisk Level: ${data.profile.risk_level || 'Unknown'}`,
        order: 2,
      });
    }

    // Transaction Analysis
    if (data.transactions && data.transactions.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Transaction Analysis',
        content: `${data.transactions.length} transaction(s) have been analyzed.`,
        order: 3,
      });

      tables.push({
        id: generateId(),
        title: 'Recent Transactions',
        headers: ['Date', 'Type', 'Amount', 'Currency', 'Counterparty', 'Risk Flag'],
        rows: data.transactions.slice(0, 50).map((t: any) => [
          t.transaction_date ? new Date(t.transaction_date).toLocaleDateString() : 'N/A',
          t.type || 'Unknown',
          t.amount?.toString() || 'N/A',
          t.currency || 'N/A',
          t.counterparty || 'Unknown',
          t.is_suspicious ? 'YES' : 'No',
        ]),
        striped: true,
        bordered: true,
      });

      // Transaction volume over time chart
      const monthlyVolume: Record<string, number> = {};
      data.transactions.forEach((t: any) => {
        if (t.transaction_date) {
          const month = new Date(t.transaction_date).toISOString().substring(0, 7);
          monthlyVolume[month] = (monthlyVolume[month] || 0) + (parseFloat(t.amount) || 0);
        }
      });

      const sortedMonths = Object.keys(monthlyVolume).sort();
      if (sortedMonths.length > 0) {
        charts.push({
          id: generateId(),
          type: 'line',
          title: 'Transaction Volume Over Time',
          data: {
            labels: sortedMonths,
            values: sortedMonths.map((m) => monthlyVolume[m]),
          },
        });
      }
    }

    // Suspicious Activity
    const suspiciousTransactions = data.transactions?.filter((t: any) => t.is_suspicious) || [];
    if (suspiciousTransactions.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Suspicious Activity',
        content: `${suspiciousTransactions.length} suspicious transaction(s) identified for further review.`,
        order: 4,
      });
    }

    return {
      title: 'Financial Analysis Report',
      classification: options.classification,
      generatedDate: new Date(),
      sections,
      tables,
      charts,
      metadata: {
        reportId: generateId(),
        type: 'financial_analysis',
      },
    };
  }

  /**
   * Format executive brief report
   */
  private formatExecutiveBrief(
    data: any,
    options: ReportGenerationOptions
  ): FormattedReportData {
    const sections: ReportSection[] = [];
    const tables: ReportTable[] = [];

    // Executive Summary
    sections.push({
      id: generateId(),
      title: 'Executive Summary',
      content: `This executive brief provides a high-level overview of ${data.operations?.length || 0} operation(s) and ${data.investigations?.length || 0} investigation(s).`,
      order: 1,
    });

    // Operations Overview
    if (data.operations && data.operations.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Operations Overview',
        content: `${data.operations.length} operation(s) are currently tracked.`,
        order: 2,
      });

      tables.push({
        id: generateId(),
        title: 'Operations Summary',
        headers: ['Name', 'Status', 'Priority', 'Start Date'],
        rows: data.operations.map((op: any) => [
          op.name || 'Unknown',
          op.status || 'Unknown',
          op.priority || 'Normal',
          op.start_date ? new Date(op.start_date).toLocaleDateString() : 'N/A',
        ]),
        striped: true,
        bordered: true,
      });
    }

    // Investigations Overview
    if (data.investigations && data.investigations.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Investigations Overview',
        content: `${data.investigations.length} investigation(s) are currently active.`,
        order: 3,
      });

      tables.push({
        id: generateId(),
        title: 'Investigations Summary',
        headers: ['Name', 'Status', 'Priority', 'Start Date'],
        rows: data.investigations.map((inv: any) => [
          inv.name || 'Unknown',
          inv.status || 'Unknown',
          inv.priority || 'Normal',
          inv.start_date ? new Date(inv.start_date).toLocaleDateString() : 'N/A',
        ]),
        striped: true,
        bordered: true,
      });
    }

    // Key Metrics
    sections.push({
      id: generateId(),
      title: 'Key Metrics',
      content: `Operations: ${data.operations?.length || 0}\nInvestigations: ${data.investigations?.length || 0}`,
      order: 4,
    });

    return {
      title: 'Executive Brief',
      classification: options.classification,
      generatedDate: new Date(),
      sections,
      tables,
      metadata: {
        reportId: generateId(),
        type: 'executive_brief',
      },
    };
  }

  /**
   * Apply template configuration to formatted data
   */
  private applyTemplateConfig(
    data: FormattedReportData,
    template: ReportTemplate
  ): void {
    // Reorder sections according to template
    if (template.sections) {
      const sectionOrder = new Map(
        template.sections.map((s) => [s.title.toLowerCase(), s.order])
      );

      data.sections.sort((a, b) => {
        const orderA = sectionOrder.get(a.title.toLowerCase()) ?? a.order;
        const orderB = sectionOrder.get(b.title.toLowerCase()) ?? b.order;
        return orderA - orderB;
      });

      // Filter out non-required sections that are empty
      const requiredSections = new Set(
        template.sections.filter((s) => s.required).map((s) => s.title.toLowerCase())
      );

      data.sections = data.sections.filter(
        (s) =>
          requiredSections.has(s.title.toLowerCase()) ||
          s.content.trim().length > 0 ||
          (s.subsections && s.subsections.length > 0)
      );
    }
  }

  /**
   * Export formatted data to requested format
   */
  private async exportToFormat(
    data: FormattedReportData,
    options: ReportGenerationOptions
  ): Promise<{ buffer: Buffer; mimeType: string }> {
    switch (options.format) {
      case ExportFormat.PDF:
        return this.pdfExporter.export(data, options);

      case ExportFormat.DOCX:
        return this.docxExporter.export(data, options);

      case ExportFormat.XLSX:
        return this.excelExporter.export(data, options);

      case ExportFormat.HTML:
        return this.htmlExporter.export(data, options);

      case ExportFormat.JSON:
        return this.jsonExporter.export(data, options);

      case ExportFormat.MARKDOWN:
        return this.generateMarkdown(data, options);

      default:
        throw new Error(`Unsupported export format: ${options.format}`);
    }
  }

  /**
   * Generate Markdown export
   */
  private async generateMarkdown(
    data: FormattedReportData,
    _options: ReportGenerationOptions
  ): Promise<{ buffer: Buffer; mimeType: string }> {
    let markdown = '';

    // Title
    markdown += `# ${data.title}\n\n`;
    if (data.subtitle) {
      markdown += `*${data.subtitle}*\n\n`;
    }

    // Classification
    markdown += `**Classification:** ${data.classification}\n\n`;
    markdown += `**Generated:** ${data.generatedDate.toISOString()}\n\n`;
    if (data.author) {
      markdown += `**Author:** ${data.author}\n\n`;
    }

    markdown += '---\n\n';

    // Table of Contents
    markdown += '## Table of Contents\n\n';
    data.sections.forEach((section, index) => {
      markdown += `${index + 1}. [${section.title}](#${this.slugify(section.title)})\n`;
      if (section.subsections) {
        section.subsections.forEach((sub, subIndex) => {
          markdown += `   ${index + 1}.${subIndex + 1}. [${sub.title}](#${this.slugify(sub.title)})\n`;
        });
      }
    });
    markdown += '\n---\n\n';

    // Sections
    data.sections.forEach((section) => {
      markdown += `## ${section.title}\n\n`;
      markdown += `${section.content}\n\n`;

      if (section.subsections) {
        section.subsections.forEach((sub) => {
          markdown += `### ${sub.title}\n\n`;
          markdown += `${sub.content}\n\n`;
        });
      }
    });

    // Tables
    if (data.tables && data.tables.length > 0) {
      markdown += '---\n\n## Tables\n\n';
      data.tables.forEach((table) => {
        if (table.title) {
          markdown += `### ${table.title}\n\n`;
        }

        // Header row
        markdown += '| ' + table.headers.join(' | ') + ' |\n';
        markdown += '| ' + table.headers.map(() => '---').join(' | ') + ' |\n';

        // Data rows
        table.rows.forEach((row) => {
          markdown += '| ' + row.map((cell) => (cell !== null ? String(cell) : '')).join(' | ') + ' |\n';
        });

        markdown += '\n';
      });
    }

    // Footer
    if (data.footer) {
      markdown += '---\n\n';
      markdown += `*${data.footer}*\n`;
    }

    return {
      buffer: Buffer.from(markdown, 'utf-8'),
      mimeType: 'text/markdown',
    };
  }

  /**
   * Generate filename for export
   */
  private generateFilename(title: string, type: ReportType, format: ExportFormat): string {
    const sanitizedTitle = title
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '_')
      .substring(0, 50);

    const timestamp = new Date().toISOString().split('T')[0];
    const extension = this.getFileExtension(format);

    return `${sanitizedTitle}_${type}_${timestamp}.${extension}`;
  }

  /**
   * Get file extension for format
   */
  private getFileExtension(format: ExportFormat): string {
    const extensions: Record<ExportFormat, string> = {
      [ExportFormat.PDF]: 'pdf',
      [ExportFormat.DOCX]: 'docx',
      [ExportFormat.XLSX]: 'xlsx',
      [ExportFormat.HTML]: 'html',
      [ExportFormat.JSON]: 'json',
      [ExportFormat.MARKDOWN]: 'md',
    };
    return extensions[format];
  }

  /**
   * Convert title to URL slug
   */
  private slugify(text: string): string {
    return text
      .toLowerCase()
      .replace(/[^\w\s-]/g, '')
      .replace(/[\s_-]+/g, '-')
      .replace(/^-+|-+$/g, '');
  }
}

// Export singleton instance
export const reportGenerator = new ReportGenerator();

// Legacy export for backwards compatibility
export function generateReport(payload: any): Buffer {
  // This is a simplified synchronous wrapper for basic use cases
  throw new Error('Use reportGenerator.generate() instead for async report generation');
}
