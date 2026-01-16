/**
 * Apollo JSON Exporter
 *
 * Structured JSON export for:
 * - Machine-readable report data
 * - API integrations
 * - Data interchange
 * - Report archival
 */

import {
  ReportGenerationOptions,
  ClassificationMarking,
  ReportSection,
  ReportTable,
  ReportChart,
  ReportImage,
} from '../types';

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

interface JSONReportOutput {
  reportMetadata: {
    id?: string;
    title: string;
    subtitle?: string;
    classification: ClassificationMarking;
    generatedDate: string;
    generatedTimestamp: number;
    author?: string;
    generator: string;
    version: string;
    checksum?: string;
    format: string;
    pageSize?: string;
    orientation?: string;
  };
  security: {
    classification: ClassificationMarking;
    handlingInstructions: string;
    releasableTo?: string[];
    notReleasableTo?: string[];
    declassificationDate?: string;
  };
  content: {
    sections: JSONSection[];
    tables?: JSONTable[];
    charts?: JSONChart[];
    images?: JSONImage[];
  };
  summary?: {
    sectionCount: number;
    tableCount: number;
    chartCount: number;
    imageCount: number;
    wordCount: number;
    characterCount: number;
  };
  customMetadata?: Record<string, any>;
}

interface JSONSection {
  id: string;
  title: string;
  content: string;
  order: number;
  level: number;
  wordCount: number;
  subsections?: JSONSection[];
}

interface JSONTable {
  id: string;
  title?: string;
  headers: string[];
  rows: (string | number | boolean | null)[][];
  footers?: string[];
  rowCount: number;
  columnCount: number;
}

interface JSONChart {
  id: string;
  type: string;
  title: string;
  data: any;
  options?: Record<string, any>;
}

interface JSONImage {
  id: string;
  caption?: string;
  mimeType?: string;
  width?: number;
  height?: number;
  // Base64 data can be optionally included
  includesData: boolean;
}

export class JSONExporter {
  private version = '1.0.0';

  /**
   * Export formatted data to JSON buffer
   */
  async export(
    data: FormattedReportData,
    options: ReportGenerationOptions
  ): Promise<{ buffer: Buffer; mimeType: string }> {
    const jsonOutput = this.generateJSON(data, options);
    const jsonString = JSON.stringify(jsonOutput, null, 2);

    return {
      buffer: Buffer.from(jsonString, 'utf-8'),
      mimeType: 'application/json',
    };
  }

  /**
   * Generate JSON structure from report data
   */
  private generateJSON(data: FormattedReportData, options: ReportGenerationOptions): JSONReportOutput {
    const generatedDate = new Date(data.generatedDate);

    // Process sections with level tracking
    const processedSections = this.processSections(data.sections, 0);

    // Calculate content statistics
    const stats = this.calculateStatistics(data);

    const output: JSONReportOutput = {
      reportMetadata: {
        id: data.metadata?.reportId,
        title: data.title,
        subtitle: data.subtitle,
        classification: data.classification,
        generatedDate: generatedDate.toISOString(),
        generatedTimestamp: generatedDate.getTime(),
        author: data.author,
        generator: 'Apollo Intelligence Platform',
        version: this.version,
        format: 'json',
        pageSize: options.pageSize,
        orientation: options.orientation,
      },
      security: {
        classification: data.classification,
        handlingInstructions: this.getHandlingInstructions(data.classification),
        releasableTo: data.metadata?.releasableTo,
        notReleasableTo: data.metadata?.notReleasableTo,
        declassificationDate: data.metadata?.declassificationDate,
      },
      content: {
        sections: processedSections,
        tables: data.tables?.map((table) => this.processTable(table)),
        charts: data.charts?.map((chart) => this.processChart(chart)),
        images: data.images?.map((image) => this.processImage(image, options)),
      },
      summary: stats,
      customMetadata: data.metadata,
    };

    return output;
  }

  /**
   * Process sections recursively with level tracking
   */
  private processSections(sections: ReportSection[], level: number): JSONSection[] {
    return sections.map((section) => {
      const wordCount = this.countWords(section.content);

      const jsonSection: JSONSection = {
        id: section.id,
        title: section.title,
        content: section.content,
        order: section.order,
        level,
        wordCount,
      };

      if (section.subsections && section.subsections.length > 0) {
        jsonSection.subsections = this.processSections(section.subsections, level + 1);
      }

      return jsonSection;
    });
  }

  /**
   * Process table data
   */
  private processTable(table: ReportTable): JSONTable {
    return {
      id: table.id,
      title: table.title,
      headers: table.headers,
      rows: table.rows,
      footers: table.footers,
      rowCount: table.rows.length,
      columnCount: table.headers.length,
    };
  }

  /**
   * Process chart data
   */
  private processChart(chart: ReportChart): JSONChart {
    return {
      id: chart.id,
      type: chart.type,
      title: chart.title,
      data: chart.data,
      options: chart.options,
    };
  }

  /**
   * Process image data
   */
  private processImage(image: ReportImage, options: ReportGenerationOptions): JSONImage {
    return {
      id: image.id,
      caption: image.caption,
      mimeType: image.mimeType,
      width: image.width,
      height: image.height,
      includesData: !!image.base64,
    };
  }

  /**
   * Calculate content statistics
   */
  private calculateStatistics(data: FormattedReportData): {
    sectionCount: number;
    tableCount: number;
    chartCount: number;
    imageCount: number;
    wordCount: number;
    characterCount: number;
  } {
    const countSections = (sections: ReportSection[]): number => {
      return sections.reduce((count, section) => {
        return count + 1 + (section.subsections ? countSections(section.subsections) : 0);
      }, 0);
    };

    const countWords = (sections: ReportSection[]): number => {
      return sections.reduce((count, section) => {
        const sectionWords = this.countWords(section.content);
        const subsectionWords = section.subsections ? countWords(section.subsections) : 0;
        return count + sectionWords + subsectionWords;
      }, 0);
    };

    const countCharacters = (sections: ReportSection[]): number => {
      return sections.reduce((count, section) => {
        const sectionChars = section.content?.length || 0;
        const subsectionChars = section.subsections ? countCharacters(section.subsections) : 0;
        return count + sectionChars + subsectionChars;
      }, 0);
    };

    return {
      sectionCount: countSections(data.sections),
      tableCount: data.tables?.length || 0,
      chartCount: data.charts?.length || 0,
      imageCount: data.images?.length || 0,
      wordCount: countWords(data.sections),
      characterCount: countCharacters(data.sections),
    };
  }

  /**
   * Count words in text
   */
  private countWords(text: string): number {
    if (!text) return 0;
    return text.trim().split(/\s+/).filter((word) => word.length > 0).length;
  }

  /**
   * Get handling instructions based on classification
   */
  private getHandlingInstructions(classification: ClassificationMarking): string {
    const instructions: Record<ClassificationMarking, string> = {
      [ClassificationMarking.TOP_SECRET_SCI]:
        'This document contains TOP SECRET//SCI information. Handle via SCI channels only. ' +
        'Do not disseminate without proper authorization. Destroy by approved methods only.',
      [ClassificationMarking.TOP_SECRET]:
        'This document contains TOP SECRET information. Handle via secure channels only. ' +
        'Unauthorized disclosure may cause exceptionally grave damage to national security.',
      [ClassificationMarking.SECRET]:
        'This document contains SECRET information. Handle via secure channels. ' +
        'Unauthorized disclosure may cause serious damage to national security.',
      [ClassificationMarking.CONFIDENTIAL]:
        'This document contains CONFIDENTIAL information. Protect from unauthorized disclosure.',
      [ClassificationMarking.RESTRICTED]:
        'This document contains RESTRICTED information. Limited distribution authorized.',
      [ClassificationMarking.UNCLASSIFIED]:
        'This document is UNCLASSIFIED. No special handling required.',
      [ClassificationMarking.UNCLASSIFIED_FOUO]:
        'This document is UNCLASSIFIED//FOR OFFICIAL USE ONLY. ' +
        'Exempt from public release under applicable exemptions.',
    };
    return instructions[classification];
  }

  /**
   * Export to compact JSON (no formatting)
   */
  async exportCompact(
    data: FormattedReportData,
    options: ReportGenerationOptions
  ): Promise<{ buffer: Buffer; mimeType: string }> {
    const jsonOutput = this.generateJSON(data, options);
    const jsonString = JSON.stringify(jsonOutput);

    return {
      buffer: Buffer.from(jsonString, 'utf-8'),
      mimeType: 'application/json',
    };
  }

  /**
   * Export sections only (lightweight export)
   */
  async exportSectionsOnly(
    data: FormattedReportData,
    options: ReportGenerationOptions
  ): Promise<{ buffer: Buffer; mimeType: string }> {
    const processedSections = this.processSections(data.sections, 0);

    const output = {
      reportId: data.metadata?.reportId,
      title: data.title,
      classification: data.classification,
      generatedDate: new Date(data.generatedDate).toISOString(),
      sections: processedSections,
    };

    const jsonString = JSON.stringify(output, null, 2);

    return {
      buffer: Buffer.from(jsonString, 'utf-8'),
      mimeType: 'application/json',
    };
  }
}

export const jsonExporter = new JSONExporter();
