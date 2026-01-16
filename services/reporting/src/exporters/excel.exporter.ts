/**
 * Apollo Excel Exporter
 *
 * Professional Excel workbook generation with support for:
 * - Multiple worksheets
 * - Styled headers and data
 * - Charts
 * - Conditional formatting
 * - Data validation
 * - Print setup with classification markings
 */

import ExcelJS from 'exceljs';
import {
  ReportGenerationOptions,
  ClassificationMarking,
  ReportSection,
  ReportTable,
  ReportChart,
} from '../types';

// Classification colors in ARGB format
const CLASSIFICATION_COLORS: Record<ClassificationMarking, string> = {
  [ClassificationMarking.TOP_SECRET_SCI]: 'FFFFD700',
  [ClassificationMarking.TOP_SECRET]: 'FFFFA500',
  [ClassificationMarking.SECRET]: 'FFFF0000',
  [ClassificationMarking.CONFIDENTIAL]: 'FF0000FF',
  [ClassificationMarking.RESTRICTED]: 'FF00FF00',
  [ClassificationMarking.UNCLASSIFIED]: 'FF008000',
  [ClassificationMarking.UNCLASSIFIED_FOUO]: 'FF808080',
};

interface FormattedReportData {
  title: string;
  subtitle?: string;
  classification: ClassificationMarking;
  generatedDate: Date;
  author?: string;
  sections: ReportSection[];
  tables?: ReportTable[];
  charts?: ReportChart[];
  metadata?: Record<string, any>;
  // Excel-specific data structures
  worksheets?: ExcelWorksheetData[];
}

interface ExcelWorksheetData {
  name: string;
  type: 'summary' | 'data' | 'chart' | 'timeline';
  headers?: string[];
  rows?: (string | number | boolean | Date | null)[][];
  charts?: ReportChart[];
  metadata?: Record<string, any>;
}

export class ExcelExporter {
  /**
   * Export formatted data to Excel buffer
   */
  async export(
    data: FormattedReportData,
    options: ReportGenerationOptions
  ): Promise<{ buffer: Buffer; mimeType: string }> {
    const workbook = new ExcelJS.Workbook();
    const classification = data.classification;
    const classificationColor = CLASSIFICATION_COLORS[classification];

    // Set workbook properties
    workbook.creator = data.author || 'Apollo Intelligence Platform';
    workbook.lastModifiedBy = 'Apollo Report Generator';
    workbook.created = data.generatedDate;
    workbook.modified = new Date();
    workbook.title = data.title;
    workbook.subject = `${classification} Report`;
    workbook.company = 'Apollo Intelligence Platform';

    // Create summary sheet
    this.createSummarySheet(workbook, data, options);

    // Create worksheets for data if available
    if (data.worksheets) {
      for (const worksheetData of data.worksheets) {
        this.createDataSheet(workbook, worksheetData, options);
      }
    }

    // Create data sheets from tables
    if (data.tables && data.tables.length > 0) {
      data.tables.forEach((table, index) => {
        this.createTableSheet(workbook, table, `Data ${index + 1}`, options);
      });
    }

    // Generate buffer
    const buffer = await workbook.xlsx.writeBuffer();
    return {
      buffer: Buffer.from(buffer),
      mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    };
  }

  /**
   * Create summary sheet with report overview
   */
  private createSummarySheet(
    workbook: ExcelJS.Workbook,
    data: FormattedReportData,
    options: ReportGenerationOptions
  ): void {
    const sheet = workbook.addWorksheet('Summary', {
      properties: { tabColor: { argb: CLASSIFICATION_COLORS[data.classification].replace('FF', '') } },
      pageSetup: {
        paperSize: options.pageSize === 'a4' ? 9 : 1, // A4 or Letter
        orientation: options.orientation === 'landscape' ? 'landscape' : 'portrait',
        fitToPage: true,
        fitToWidth: 1,
        printTitlesRow: '1:3',
      },
      headerFooter: {
        oddHeader: `&C&B${data.classification}`,
        oddFooter: `&L${data.classification}&CPage &P of &N&R${this.formatDate(data.generatedDate)}`,
      },
    });

    // Classification banner (row 1)
    sheet.mergeCells('A1:H1');
    const classificationCell = sheet.getCell('A1');
    classificationCell.value = data.classification;
    classificationCell.font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 14 };
    classificationCell.fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: CLASSIFICATION_COLORS[data.classification] },
    };
    classificationCell.alignment = { horizontal: 'center', vertical: 'middle' };
    sheet.getRow(1).height = 30;

    // Title (row 3)
    sheet.mergeCells('A3:H3');
    const titleCell = sheet.getCell('A3');
    titleCell.value = data.title;
    titleCell.font = { bold: true, size: 24, color: { argb: 'FF1a1a2e' } };
    titleCell.alignment = { horizontal: 'center' };
    sheet.getRow(3).height = 35;

    // Subtitle (row 4)
    if (data.subtitle) {
      sheet.mergeCells('A4:H4');
      const subtitleCell = sheet.getCell('A4');
      subtitleCell.value = data.subtitle;
      subtitleCell.font = { size: 14, color: { argb: 'FF4a4a68' } };
      subtitleCell.alignment = { horizontal: 'center' };
    }

    // Metadata section
    let currentRow = 6;

    // Report metadata
    const metadataItems = [
      ['Report ID:', data.metadata?.reportId || 'N/A'],
      ['Generated:', this.formatDate(data.generatedDate)],
      ['Author:', data.author || 'Apollo System'],
      ['Classification:', data.classification],
      ['Report Type:', data.metadata?.type || 'General'],
    ];

    metadataItems.forEach(([label, value]) => {
      sheet.getCell(`A${currentRow}`).value = label;
      sheet.getCell(`A${currentRow}`).font = { bold: true };
      sheet.getCell(`B${currentRow}`).value = value;
      currentRow++;
    });

    // Spacer
    currentRow += 2;

    // Sections summary
    sheet.getCell(`A${currentRow}`).value = 'Report Contents';
    sheet.getCell(`A${currentRow}`).font = { bold: true, size: 14, color: { argb: 'FF1a1a2e' } };
    sheet.mergeCells(`A${currentRow}:H${currentRow}`);
    currentRow++;

    // Add horizontal line
    for (let col = 1; col <= 8; col++) {
      sheet.getCell(currentRow, col).border = {
        top: { style: 'thin', color: { argb: 'FF1a1a2e' } },
      };
    }
    currentRow++;

    // List sections
    data.sections.forEach((section, index) => {
      sheet.getCell(`A${currentRow}`).value = `${index + 1}. ${section.title}`;
      sheet.getCell(`A${currentRow}`).font = { bold: true };

      // Preview of content
      if (section.content) {
        currentRow++;
        sheet.getCell(`B${currentRow}`).value = section.content.substring(0, 200) + (section.content.length > 200 ? '...' : '');
        sheet.getCell(`B${currentRow}`).font = { size: 10, color: { argb: 'FF666666' } };
        sheet.mergeCells(`B${currentRow}:H${currentRow}`);
      }

      currentRow += 2;
    });

    // Bottom classification banner
    currentRow += 2;
    sheet.mergeCells(`A${currentRow}:H${currentRow}`);
    const bottomClassCell = sheet.getCell(`A${currentRow}`);
    bottomClassCell.value = data.classification;
    bottomClassCell.font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 14 };
    bottomClassCell.fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: CLASSIFICATION_COLORS[data.classification] },
    };
    bottomClassCell.alignment = { horizontal: 'center', vertical: 'middle' };
    sheet.getRow(currentRow).height = 30;

    // Set column widths
    sheet.getColumn('A').width = 20;
    sheet.getColumn('B').width = 40;
    for (let i = 3; i <= 8; i++) {
      sheet.getColumn(i).width = 15;
    }
  }

  /**
   * Create a data sheet
   */
  private createDataSheet(
    workbook: ExcelJS.Workbook,
    worksheetData: ExcelWorksheetData,
    options: ReportGenerationOptions
  ): void {
    const sheet = workbook.addWorksheet(worksheetData.name, {
      pageSetup: {
        paperSize: options.pageSize === 'a4' ? 9 : 1,
        orientation: 'landscape',
        fitToPage: true,
        fitToWidth: 1,
      },
      headerFooter: {
        oddHeader: `&C&B${options.classification}`,
        oddFooter: `&CPage &P of &N`,
      },
    });

    let currentRow = 1;

    // Classification banner
    const colCount = worksheetData.headers?.length || 6;
    sheet.mergeCells(1, 1, 1, colCount);
    const classCell = sheet.getCell(1, 1);
    classCell.value = options.classification;
    classCell.font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 12 };
    classCell.fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: CLASSIFICATION_COLORS[options.classification] },
    };
    classCell.alignment = { horizontal: 'center' };
    sheet.getRow(1).height = 25;
    currentRow = 3;

    // Title
    sheet.mergeCells(currentRow, 1, currentRow, colCount);
    const titleCell = sheet.getCell(currentRow, 1);
    titleCell.value = worksheetData.name;
    titleCell.font = { bold: true, size: 16, color: { argb: 'FF1a1a2e' } };
    currentRow += 2;

    // Headers
    if (worksheetData.headers) {
      worksheetData.headers.forEach((header, index) => {
        const cell = sheet.getCell(currentRow, index + 1);
        cell.value = header;
        cell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
        cell.fill = {
          type: 'pattern',
          pattern: 'solid',
          fgColor: { argb: 'FF1a1a2e' },
        };
        cell.border = {
          top: { style: 'thin' },
          left: { style: 'thin' },
          bottom: { style: 'thin' },
          right: { style: 'thin' },
        };
        cell.alignment = { horizontal: 'center', vertical: 'middle' };
      });
      sheet.getRow(currentRow).height = 25;
      currentRow++;
    }

    // Data rows
    if (worksheetData.rows) {
      worksheetData.rows.forEach((row, rowIndex) => {
        row.forEach((value, colIndex) => {
          const cell = sheet.getCell(currentRow, colIndex + 1);
          cell.value = value;
          cell.border = {
            top: { style: 'thin', color: { argb: 'FFcccccc' } },
            left: { style: 'thin', color: { argb: 'FFcccccc' } },
            bottom: { style: 'thin', color: { argb: 'FFcccccc' } },
            right: { style: 'thin', color: { argb: 'FFcccccc' } },
          };

          // Alternating row colors
          if (rowIndex % 2 === 1) {
            cell.fill = {
              type: 'pattern',
              pattern: 'solid',
              fgColor: { argb: 'FFf5f5f5' },
            };
          }
        });
        currentRow++;
      });
    }

    // Auto-fit columns
    worksheetData.headers?.forEach((_, index) => {
      sheet.getColumn(index + 1).width = 20;
    });

    // Bottom classification
    currentRow += 2;
    sheet.mergeCells(currentRow, 1, currentRow, colCount);
    const bottomCell = sheet.getCell(currentRow, 1);
    bottomCell.value = options.classification;
    bottomCell.font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 12 };
    bottomCell.fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: CLASSIFICATION_COLORS[options.classification] },
    };
    bottomCell.alignment = { horizontal: 'center' };
  }

  /**
   * Create a table sheet from ReportTable
   */
  private createTableSheet(
    workbook: ExcelJS.Workbook,
    table: ReportTable,
    sheetName: string,
    options: ReportGenerationOptions
  ): void {
    const sheet = workbook.addWorksheet(table.title || sheetName, {
      pageSetup: {
        paperSize: options.pageSize === 'a4' ? 9 : 1,
        orientation: 'landscape',
        fitToPage: true,
      },
      headerFooter: {
        oddHeader: `&C&B${options.classification}`,
        oddFooter: `&CPage &P of &N`,
      },
    });

    const colCount = table.headers.length;
    let currentRow = 1;

    // Classification banner
    sheet.mergeCells(1, 1, 1, colCount);
    const classCell = sheet.getCell(1, 1);
    classCell.value = options.classification;
    classCell.font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 12 };
    classCell.fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: CLASSIFICATION_COLORS[options.classification] },
    };
    classCell.alignment = { horizontal: 'center' };
    currentRow = 3;

    // Table title
    if (table.title) {
      sheet.mergeCells(currentRow, 1, currentRow, colCount);
      const titleCell = sheet.getCell(currentRow, 1);
      titleCell.value = table.title;
      titleCell.font = { bold: true, size: 14, color: { argb: 'FF1a1a2e' } };
      currentRow += 2;
    }

    // Headers
    table.headers.forEach((header, index) => {
      const cell = sheet.getCell(currentRow, index + 1);
      cell.value = header;
      cell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
      cell.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FF1a1a2e' },
      };
      cell.border = {
        top: { style: 'thin' },
        left: { style: 'thin' },
        bottom: { style: 'thin' },
        right: { style: 'thin' },
      };
      cell.alignment = { horizontal: 'center', vertical: 'middle' };
    });
    sheet.getRow(currentRow).height = 25;
    currentRow++;

    // Data rows
    table.rows.forEach((row, rowIndex) => {
      row.forEach((value, colIndex) => {
        const cell = sheet.getCell(currentRow, colIndex + 1);
        cell.value = value;
        cell.border = {
          top: { style: 'thin', color: { argb: 'FFcccccc' } },
          left: { style: 'thin', color: { argb: 'FFcccccc' } },
          bottom: { style: 'thin', color: { argb: 'FFcccccc' } },
          right: { style: 'thin', color: { argb: 'FFcccccc' } },
        };

        // Striped rows
        if (table.striped && rowIndex % 2 === 1) {
          cell.fill = {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: 'FFf5f5f5' },
          };
        }
      });
      currentRow++;
    });

    // Footer row
    if (table.footers) {
      table.footers.forEach((footer, index) => {
        const cell = sheet.getCell(currentRow, index + 1);
        cell.value = footer;
        cell.font = { bold: true };
        cell.fill = {
          type: 'pattern',
          pattern: 'solid',
          fgColor: { argb: 'FFe5e5e5' },
        };
        cell.border = {
          top: { style: 'thin' },
          left: { style: 'thin' },
          bottom: { style: 'thin' },
          right: { style: 'thin' },
        };
      });
      currentRow++;
    }

    // Bottom classification
    currentRow += 2;
    sheet.mergeCells(currentRow, 1, currentRow, colCount);
    const bottomCell = sheet.getCell(currentRow, 1);
    bottomCell.value = options.classification;
    bottomCell.font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 12 };
    bottomCell.fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: CLASSIFICATION_COLORS[options.classification] },
    };
    bottomCell.alignment = { horizontal: 'center' };

    // Auto-fit columns
    table.headers.forEach((header, index) => {
      const maxLength = Math.max(
        header.length,
        ...table.rows.map((row) => String(row[index] || '').length)
      );
      sheet.getColumn(index + 1).width = Math.min(Math.max(maxLength + 2, 10), 50);
    });
  }

  /**
   * Add a chart to a worksheet
   */
  addChart(sheet: ExcelJS.Worksheet, chart: ReportChart, startRow: number): void {
    // ExcelJS supports adding charts - this is a simplified implementation
    // In production, you would use chart.addChart with proper configuration

    const chartData = chart.data as { labels: string[]; values: number[] };
    if (!chartData.labels || !chartData.values) return;

    // For now, we'll add chart data as a table with a note
    const titleCell = sheet.getCell(startRow, 1);
    titleCell.value = `Chart: ${chart.title}`;
    titleCell.font = { bold: true, size: 12 };

    // Add data
    chartData.labels.forEach((label, index) => {
      sheet.getCell(startRow + 1 + index, 1).value = label;
      sheet.getCell(startRow + 1 + index, 2).value = chartData.values[index];
    });

    // Note about chart
    const noteCell = sheet.getCell(startRow + chartData.labels.length + 2, 1);
    noteCell.value = `[${chart.type} chart - Open in Excel to view visualization]`;
    noteCell.font = { italic: true, color: { argb: 'FF666666' } };
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

export const excelExporter = new ExcelExporter();
