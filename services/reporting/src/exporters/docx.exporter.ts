/**
 * Apollo DOCX Exporter
 *
 * Professional Word document generation with support for:
 * - Classification markings and headers/footers
 * - Table of contents
 * - Tables with styling
 * - Image embedding
 * - Styled headings and paragraphs
 * - Page numbering
 */

import {
  Document,
  Packer,
  Paragraph,
  TextRun,
  Header,
  Footer,
  Table,
  TableRow,
  TableCell,
  BorderStyle,
  AlignmentType,
  HeadingLevel,
  PageBreak,
  ImageRun,
  TableOfContents,
  ShadingType,
  WidthType,
  PageNumber,
  NumberFormat,
  convertInchesToTwip,
  Tab,
  TabStopPosition,
  TabStopType,
} from 'docx';
import {
  ReportGenerationOptions,
  ClassificationMarking,
  ReportSection,
  ReportTable,
  ReportImage,
} from '../types';

// Classification banner colors
const CLASSIFICATION_COLORS: Record<ClassificationMarking, string> = {
  [ClassificationMarking.TOP_SECRET_SCI]: 'FFD700',
  [ClassificationMarking.TOP_SECRET]: 'FFA500',
  [ClassificationMarking.SECRET]: 'FF0000',
  [ClassificationMarking.CONFIDENTIAL]: '0000FF',
  [ClassificationMarking.RESTRICTED]: '00FF00',
  [ClassificationMarking.UNCLASSIFIED]: '008000',
  [ClassificationMarking.UNCLASSIFIED_FOUO]: '808080',
};

interface FormattedReportData {
  title: string;
  subtitle?: string;
  classification: ClassificationMarking;
  generatedDate: Date;
  author?: string;
  sections: ReportSection[];
  tables?: ReportTable[];
  images?: ReportImage[];
  footer?: string;
  metadata?: Record<string, any>;
}

export class DocxExporter {
  /**
   * Export formatted data to DOCX buffer
   */
  async export(
    data: FormattedReportData,
    options: ReportGenerationOptions
  ): Promise<{ buffer: Buffer; mimeType: string }> {
    const classification = data.classification;
    const classificationColor = CLASSIFICATION_COLORS[classification];

    // Build document sections
    const children: any[] = [];

    // Cover page
    children.push(...this.createCoverPage(data, options));

    // Page break after cover
    children.push(new Paragraph({ children: [new PageBreak()] }));

    // Table of contents
    if (options.includeTableOfContents) {
      children.push(
        new Paragraph({
          text: 'Table of Contents',
          heading: HeadingLevel.HEADING_1,
          spacing: { after: 200 },
        }),
        new TableOfContents('Table of Contents', {
          hyperlink: true,
          headingStyleRange: '1-3',
        }),
        new Paragraph({ children: [new PageBreak()] })
      );
    }

    // Content sections
    for (const section of data.sections) {
      children.push(...this.createSection(section, 0));
    }

    // Create document
    const doc = new Document({
      creator: 'Apollo Intelligence Platform',
      title: data.title,
      subject: `${classification} Report`,
      description: data.subtitle,
      keywords: 'intelligence,report,apollo',
      lastModifiedBy: data.author || 'Apollo System',
      sections: [
        {
          properties: {
            page: {
              size: {
                width: options.pageSize === 'a4' ? 11906 : 12240, // A4 or Letter in twips
                height: options.pageSize === 'a4' ? 16838 : 15840,
              },
              margin: {
                top: convertInchesToTwip(1),
                right: convertInchesToTwip(1),
                bottom: convertInchesToTwip(1),
                left: convertInchesToTwip(1),
              },
            },
          },
          headers: {
            default: this.createHeader(classification, classificationColor, options),
          },
          footers: {
            default: this.createFooter(classification, classificationColor, options),
          },
          children,
        },
      ],
      styles: {
        paragraphStyles: [
          {
            id: 'ClassificationBanner',
            name: 'Classification Banner',
            basedOn: 'Normal',
            next: 'Normal',
            run: {
              color: 'FFFFFF',
              bold: true,
              size: 24,
            },
            paragraph: {
              alignment: AlignmentType.CENTER,
              shading: { type: ShadingType.SOLID, color: classificationColor },
            },
          },
          {
            id: 'ReportTitle',
            name: 'Report Title',
            basedOn: 'Title',
            run: {
              color: '1a1a2e',
              size: 56,
              bold: true,
            },
            paragraph: {
              alignment: AlignmentType.CENTER,
              spacing: { before: 400, after: 200 },
            },
          },
          {
            id: 'ReportSubtitle',
            name: 'Report Subtitle',
            basedOn: 'Normal',
            run: {
              color: '4a4a68',
              size: 32,
            },
            paragraph: {
              alignment: AlignmentType.CENTER,
              spacing: { after: 400 },
            },
          },
          {
            id: 'SectionContent',
            name: 'Section Content',
            basedOn: 'Normal',
            run: {
              size: options.fontSize ? options.fontSize * 2 : 22,
              font: options.fontFamily || 'Calibri',
            },
            paragraph: {
              spacing: { line: 276, after: 200 },
            },
          },
        ],
      },
    });

    const buffer = await Packer.toBuffer(doc);
    return {
      buffer: Buffer.from(buffer),
      mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    };
  }

  /**
   * Create cover page elements
   */
  private createCoverPage(data: FormattedReportData, options: ReportGenerationOptions): Paragraph[] {
    const classification = data.classification;
    const classificationColor = CLASSIFICATION_COLORS[classification];
    const paragraphs: Paragraph[] = [];

    // Top classification banner
    paragraphs.push(
      new Paragraph({
        children: [
          new TextRun({
            text: classification,
            bold: true,
            color: 'FFFFFF',
            size: 28,
          }),
        ],
        alignment: AlignmentType.CENTER,
        shading: { type: ShadingType.SOLID, color: classificationColor },
        spacing: { after: 400 },
      })
    );

    // Spacer
    paragraphs.push(new Paragraph({ spacing: { before: 1000 } }));

    // Logo placeholder
    paragraphs.push(
      new Paragraph({
        children: [
          new TextRun({
            text: 'APOLLO',
            bold: true,
            color: '1a1a2e',
            size: 48,
          }),
        ],
        alignment: AlignmentType.CENTER,
        spacing: { after: 600 },
      }),
      new Paragraph({
        children: [
          new TextRun({
            text: 'INTELLIGENCE PLATFORM',
            color: '4a4a68',
            size: 24,
          }),
        ],
        alignment: AlignmentType.CENTER,
        spacing: { after: 800 },
      })
    );

    // Title
    paragraphs.push(
      new Paragraph({
        children: [
          new TextRun({
            text: data.title,
            bold: true,
            color: '1a1a2e',
            size: 56,
          }),
        ],
        alignment: AlignmentType.CENTER,
        spacing: { after: 200 },
      })
    );

    // Subtitle
    if (data.subtitle) {
      paragraphs.push(
        new Paragraph({
          children: [
            new TextRun({
              text: data.subtitle,
              color: '4a4a68',
              size: 32,
            }),
          ],
          alignment: AlignmentType.CENTER,
          spacing: { after: 600 },
        })
      );
    }

    // Metadata
    paragraphs.push(
      new Paragraph({
        children: [
          new TextRun({
            text: `Generated: ${this.formatDate(data.generatedDate)}`,
            size: 22,
          }),
        ],
        alignment: AlignmentType.CENTER,
        spacing: { after: 100 },
      })
    );

    if (data.author) {
      paragraphs.push(
        new Paragraph({
          children: [
            new TextRun({
              text: `Prepared by: ${data.author}`,
              size: 22,
            }),
          ],
          alignment: AlignmentType.CENTER,
          spacing: { after: 100 },
        })
      );
    }

    paragraphs.push(
      new Paragraph({
        children: [
          new TextRun({
            text: `Classification: ${classification}`,
            size: 22,
            bold: true,
          }),
        ],
        alignment: AlignmentType.CENTER,
        spacing: { after: 600 },
      })
    );

    // Handling instructions
    if (classification !== ClassificationMarking.UNCLASSIFIED) {
      paragraphs.push(
        new Paragraph({
          children: [
            new TextRun({
              text: 'HANDLING INSTRUCTIONS',
              bold: true,
              underline: {},
              size: 20,
            }),
          ],
          spacing: { before: 400, after: 100 },
        }),
        new Paragraph({
          children: [
            new TextRun({
              text: this.getHandlingInstructions(classification),
              size: 18,
              italics: true,
            }),
          ],
          spacing: { after: 400 },
          border: {
            top: { style: BorderStyle.SINGLE, size: 1, color: '333333' },
            bottom: { style: BorderStyle.SINGLE, size: 1, color: '333333' },
            left: { style: BorderStyle.SINGLE, size: 1, color: '333333' },
            right: { style: BorderStyle.SINGLE, size: 1, color: '333333' },
          },
        })
      );
    }

    // Bottom classification banner
    paragraphs.push(
      new Paragraph({ spacing: { before: 400 } }),
      new Paragraph({
        children: [
          new TextRun({
            text: classification,
            bold: true,
            color: 'FFFFFF',
            size: 28,
          }),
        ],
        alignment: AlignmentType.CENTER,
        shading: { type: ShadingType.SOLID, color: classificationColor },
      })
    );

    return paragraphs;
  }

  /**
   * Create header
   */
  private createHeader(
    classification: ClassificationMarking,
    color: string,
    options: ReportGenerationOptions
  ): Header {
    return new Header({
      children: [
        new Paragraph({
          children: [
            new TextRun({
              text: classification,
              bold: true,
              color: 'FFFFFF',
              size: 20,
            }),
          ],
          alignment: AlignmentType.CENTER,
          shading: { type: ShadingType.SOLID, color },
        }),
        ...(options.headerText
          ? [
              new Paragraph({
                children: [
                  new TextRun({
                    text: options.headerText,
                    size: 16,
                    color: '666666',
                  }),
                ],
                spacing: { before: 100 },
              }),
            ]
          : []),
      ],
    });
  }

  /**
   * Create footer
   */
  private createFooter(
    classification: ClassificationMarking,
    color: string,
    options: ReportGenerationOptions
  ): Footer {
    const children: Paragraph[] = [];

    // Footer text
    if (options.footerText) {
      children.push(
        new Paragraph({
          children: [
            new TextRun({
              text: options.footerText,
              size: 14,
              color: '999999',
            }),
          ],
          alignment: AlignmentType.CENTER,
        })
      );
    }

    // Page numbers
    if (options.includePageNumbers) {
      children.push(
        new Paragraph({
          children: [
            new TextRun({
              children: ['Page ', PageNumber.CURRENT, ' of ', PageNumber.TOTAL_PAGES],
              size: 16,
              color: '666666',
            }),
          ],
          alignment: AlignmentType.CENTER,
          spacing: { before: 100 },
        })
      );
    }

    // Classification banner
    children.push(
      new Paragraph({
        children: [
          new TextRun({
            text: classification,
            bold: true,
            color: 'FFFFFF',
            size: 20,
          }),
        ],
        alignment: AlignmentType.CENTER,
        shading: { type: ShadingType.SOLID, color },
        spacing: { before: 100 },
      })
    );

    return new Footer({ children });
  }

  /**
   * Create section content
   */
  private createSection(section: ReportSection, level: number): Paragraph[] {
    const paragraphs: Paragraph[] = [];
    const headingLevels = [HeadingLevel.HEADING_1, HeadingLevel.HEADING_2, HeadingLevel.HEADING_3, HeadingLevel.HEADING_4];
    const headingLevel = headingLevels[Math.min(level, 3)];

    // Page break before if specified
    if (section.pageBreakBefore) {
      paragraphs.push(new Paragraph({ children: [new PageBreak()] }));
    }

    // Section title
    paragraphs.push(
      new Paragraph({
        text: section.title,
        heading: headingLevel,
        spacing: { before: level === 0 ? 400 : 200, after: 100 },
      })
    );

    // Section content
    if (section.content) {
      // Split content by paragraphs
      const contentParagraphs = section.content.split('\n\n');
      for (const para of contentParagraphs) {
        if (para.trim()) {
          paragraphs.push(
            new Paragraph({
              children: [
                new TextRun({
                  text: para.trim(),
                  size: 22,
                }),
              ],
              spacing: { after: 200 },
            })
          );
        }
      }
    }

    // Process subsections
    if (section.subsections) {
      for (const subsection of section.subsections) {
        paragraphs.push(...this.createSection(subsection, level + 1));
      }
    }

    // Page break after if specified
    if (section.pageBreakAfter) {
      paragraphs.push(new Paragraph({ children: [new PageBreak()] }));
    }

    return paragraphs;
  }

  /**
   * Create a table
   */
  createTable(table: ReportTable): Table {
    const columnCount = table.headers.length;
    const columnWidth = Math.floor(9000 / columnCount); // Total width in twips

    // Header row
    const headerRow = new TableRow({
      children: table.headers.map(
        (header) =>
          new TableCell({
            children: [
              new Paragraph({
                children: [
                  new TextRun({
                    text: header,
                    bold: true,
                    color: 'FFFFFF',
                    size: 20,
                  }),
                ],
              }),
            ],
            shading: { type: ShadingType.SOLID, color: '1a1a2e' },
            width: { size: columnWidth, type: WidthType.DXA },
          })
      ),
      tableHeader: true,
    });

    // Data rows
    const dataRows = table.rows.map(
      (row, rowIndex) =>
        new TableRow({
          children: row.map(
            (cell) =>
              new TableCell({
                children: [
                  new Paragraph({
                    children: [
                      new TextRun({
                        text: cell !== null && cell !== undefined ? String(cell) : '',
                        size: 18,
                      }),
                    ],
                  }),
                ],
                shading:
                  table.striped && rowIndex % 2 === 1
                    ? { type: ShadingType.SOLID, color: 'f5f5f5' }
                    : undefined,
                width: { size: columnWidth, type: WidthType.DXA },
              })
          ),
        })
    );

    // Footer row
    const footerRows = table.footers
      ? [
          new TableRow({
            children: table.footers.map(
              (footer) =>
                new TableCell({
                  children: [
                    new Paragraph({
                      children: [
                        new TextRun({
                          text: footer,
                          bold: true,
                          size: 18,
                        }),
                      ],
                    }),
                  ],
                  shading: { type: ShadingType.SOLID, color: 'e5e5e5' },
                  width: { size: columnWidth, type: WidthType.DXA },
                })
            ),
          }),
        ]
      : [];

    return new Table({
      rows: [headerRow, ...dataRows, ...footerRows],
      width: { size: 100, type: WidthType.PERCENTAGE },
    });
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
   * Format date for display
   */
  private formatDate(date: Date): string {
    return new Date(date).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  }
}

export const docxExporter = new DocxExporter();
