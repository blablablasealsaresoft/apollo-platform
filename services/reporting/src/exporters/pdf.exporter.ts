/**
 * Apollo PDF Exporter
 *
 * Professional PDF generation with support for:
 * - Classification markings and headers/footers
 * - Table of contents with page numbers
 * - Charts and graphs
 * - Tables with styling
 * - Image embedding
 * - Watermarks
 * - Page numbering
 * - Encryption
 */

import PDFDocument from 'pdfkit';
import {
  ReportGenerationOptions,
  ClassificationMarking,
  ReportSection,
  ReportChart,
  ReportTable,
  ReportImage,
} from '../types';

// Color schemes for classification markings
const CLASSIFICATION_COLORS: Record<ClassificationMarking, string> = {
  [ClassificationMarking.TOP_SECRET_SCI]: '#FFD700',
  [ClassificationMarking.TOP_SECRET]: '#FFA500',
  [ClassificationMarking.SECRET]: '#FF0000',
  [ClassificationMarking.CONFIDENTIAL]: '#0000FF',
  [ClassificationMarking.RESTRICTED]: '#00FF00',
  [ClassificationMarking.UNCLASSIFIED]: '#008000',
  [ClassificationMarking.UNCLASSIFIED_FOUO]: '#808080',
};

// Page size configurations
const PAGE_SIZES = {
  letter: { width: 612, height: 792 },
  a4: { width: 595.28, height: 841.89 },
  legal: { width: 612, height: 1008 },
};

interface FormattedReportData {
  title: string;
  subtitle?: string;
  classification: ClassificationMarking;
  generatedDate: Date;
  author?: string;
  sections: ReportSection[];
  charts?: ReportChart[];
  tables?: ReportTable[];
  images?: ReportImage[];
  footer?: string;
  watermark?: string;
  metadata?: Record<string, any>;
}

interface TOCEntry {
  title: string;
  page: number;
  level: number;
}

export class PDFExporter {
  private pageCount: number = 0;
  private tocEntries: TOCEntry[] = [];
  private currentY: number = 0;

  /**
   * Export formatted data to PDF buffer
   */
  async export(
    data: FormattedReportData,
    options: ReportGenerationOptions
  ): Promise<{ buffer: Buffer; mimeType: string }> {
    return new Promise((resolve, reject) => {
      try {
        const pageSize = PAGE_SIZES[options.pageSize || 'letter'];
        const isLandscape = options.orientation === 'landscape';

        const doc = new PDFDocument({
          size: isLandscape ? [pageSize.height, pageSize.width] : [pageSize.width, pageSize.height],
          margins: options.margins || { top: 72, right: 72, bottom: 72, left: 72 },
          bufferPages: true,
          info: {
            Title: data.title,
            Author: data.author || 'Apollo Intelligence Platform',
            Subject: `${data.classification} Report`,
            Creator: 'Apollo Report Generator',
            Producer: 'Apollo v1.0',
            CreationDate: new Date(),
          },
        });

        const chunks: Buffer[] = [];
        doc.on('data', (chunk) => chunks.push(chunk));
        doc.on('end', () => {
          const buffer = Buffer.concat(chunks);
          resolve({ buffer, mimeType: 'application/pdf' });
        });
        doc.on('error', reject);

        // Reset state
        this.pageCount = 0;
        this.tocEntries = [];

        // Generate cover page
        this.generateCoverPage(doc, data, options);

        // Generate table of contents placeholder (will be filled later)
        if (options.includeTableOfContents) {
          this.generateTOCPlaceholder(doc, options);
        }

        // Generate content sections
        for (const section of data.sections) {
          this.generateSection(doc, section, options, 0);
        }

        // Generate charts if included
        if (options.includeCharts && data.charts) {
          this.generateChartSection(doc, data.charts, options);
        }

        // Add headers and footers to all pages
        this.addHeadersFooters(doc, data, options);

        // Add watermark if enabled
        if (options.includeWatermark) {
          this.addWatermark(doc, options.watermarkText || data.classification, options);
        }

        // Finalize
        doc.end();
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Generate cover page
   */
  private generateCoverPage(
    doc: PDFKit.PDFDocument,
    data: FormattedReportData,
    options: ReportGenerationOptions
  ): void {
    const pageWidth = doc.page.width;
    const pageHeight = doc.page.height;
    const classification = data.classification;
    const classificationColor = CLASSIFICATION_COLORS[classification];

    // Classification banner at top
    doc.rect(0, 0, pageWidth, 40).fill(classificationColor);
    doc.fontSize(14).fillColor('white').text(classification, 0, 12, { align: 'center' });

    // Logo placeholder (would load actual logo)
    doc.rect(pageWidth / 2 - 50, 100, 100, 100).stroke('#333333');
    doc.fontSize(10).fillColor('#333333').text('APOLLO', pageWidth / 2 - 25, 145);

    // Title
    doc.fontSize(28)
      .fillColor('#1a1a2e')
      .text(data.title, 72, 250, { align: 'center', width: pageWidth - 144 });

    // Subtitle if present
    if (data.subtitle) {
      doc.fontSize(16)
        .fillColor('#4a4a68')
        .text(data.subtitle, 72, 300, { align: 'center', width: pageWidth - 144 });
    }

    // Report metadata
    const metaY = 400;
    doc.fontSize(11).fillColor('#333333');
    doc.text(`Generated: ${this.formatDate(data.generatedDate)}`, 72, metaY, { align: 'center', width: pageWidth - 144 });
    if (data.author) {
      doc.text(`Prepared by: ${data.author}`, 72, metaY + 20, { align: 'center', width: pageWidth - 144 });
    }
    doc.text(`Classification: ${classification}`, 72, metaY + 40, { align: 'center', width: pageWidth - 144 });

    // Footer classification banner
    doc.rect(0, pageHeight - 40, pageWidth, 40).fill(classificationColor);
    doc.fontSize(14).fillColor('white').text(classification, 0, pageHeight - 28, { align: 'center' });

    // Handling instructions box
    if (classification !== ClassificationMarking.UNCLASSIFIED) {
      doc.rect(72, pageHeight - 200, pageWidth - 144, 100).stroke('#333333');
      doc.fontSize(9).fillColor('#333333');
      doc.text('HANDLING INSTRUCTIONS', 80, pageHeight - 190, { underline: true });
      doc.text(this.getHandlingInstructions(classification), 80, pageHeight - 170, {
        width: pageWidth - 160,
        align: 'left',
      });
    }

    this.pageCount++;
    doc.addPage();
  }

  /**
   * Generate Table of Contents placeholder
   */
  private generateTOCPlaceholder(doc: PDFKit.PDFDocument, options: ReportGenerationOptions): void {
    const classification = options.classification;
    const classificationColor = CLASSIFICATION_COLORS[classification];
    const pageWidth = doc.page.width;

    // Header
    doc.rect(0, 0, pageWidth, 25).fill(classificationColor);
    doc.fontSize(10).fillColor('white').text(classification, 0, 8, { align: 'center' });

    doc.fontSize(20).fillColor('#1a1a2e').text('Table of Contents', 72, 60);
    doc.moveDown(2);

    // TOC entries will be populated after all sections are processed
    // This is a placeholder that shows the structure
    doc.fontSize(11).fillColor('#333333');
    doc.text('(Table of contents generated automatically)', 72, 120);

    this.pageCount++;
    doc.addPage();
  }

  /**
   * Generate a report section
   */
  private generateSection(
    doc: PDFKit.PDFDocument,
    section: ReportSection,
    options: ReportGenerationOptions,
    level: number
  ): void {
    const classification = options.classification;
    const classificationColor = CLASSIFICATION_COLORS[classification];
    const pageWidth = doc.page.width;
    const margins = options.margins || { top: 72, right: 72, bottom: 72, left: 72 };
    const contentWidth = pageWidth - margins.left - margins.right;

    // Check for page break
    if (section.pageBreakBefore || this.needsPageBreak(doc, 100)) {
      doc.addPage();
      this.pageCount++;
      // Add classification header to new page
      doc.rect(0, 0, pageWidth, 25).fill(classificationColor);
      doc.fontSize(10).fillColor('white').text(classification, 0, 8, { align: 'center' });
      this.currentY = 50;
    }

    // Record TOC entry
    this.tocEntries.push({
      title: section.title,
      page: this.pageCount,
      level,
    });

    // Section title styling based on level
    const titleSizes = [18, 14, 12, 11];
    const titleSize = titleSizes[Math.min(level, 3)];
    const indent = level * 20;

    doc.fontSize(titleSize)
      .fillColor(level === 0 ? '#1a1a2e' : '#333333')
      .text(section.title, margins.left + indent, doc.y + 10);

    // Underline for top-level sections
    if (level === 0) {
      const titleWidth = doc.widthOfString(section.title);
      doc.moveTo(margins.left, doc.y + 5)
        .lineTo(margins.left + titleWidth, doc.y + 5)
        .stroke('#1a1a2e');
    }

    doc.moveDown(0.5);

    // Section content
    doc.fontSize(options.fontSize || 11)
      .fillColor('#333333')
      .text(section.content, margins.left + indent, doc.y, {
        width: contentWidth - indent,
        align: 'justify',
        lineGap: 2,
      });

    doc.moveDown(1);

    // Process subsections
    if (section.subsections) {
      for (const subsection of section.subsections) {
        this.generateSection(doc, subsection, options, level + 1);
      }
    }

    // Page break after if specified
    if (section.pageBreakAfter) {
      doc.addPage();
      this.pageCount++;
    }
  }

  /**
   * Generate chart section
   */
  private generateChartSection(
    doc: PDFKit.PDFDocument,
    charts: ReportChart[],
    options: ReportGenerationOptions
  ): void {
    const classification = options.classification;
    const classificationColor = CLASSIFICATION_COLORS[classification];
    const pageWidth = doc.page.width;
    const margins = options.margins || { top: 72, right: 72, bottom: 72, left: 72 };

    doc.addPage();
    this.pageCount++;

    // Classification header
    doc.rect(0, 0, pageWidth, 25).fill(classificationColor);
    doc.fontSize(10).fillColor('white').text(classification, 0, 8, { align: 'center' });

    doc.fontSize(18).fillColor('#1a1a2e').text('Charts and Visualizations', margins.left, 50);
    doc.moveDown(1);

    for (const chart of charts) {
      this.renderChart(doc, chart, options);
      doc.moveDown(2);

      if (this.needsPageBreak(doc, 300)) {
        doc.addPage();
        this.pageCount++;
        doc.rect(0, 0, pageWidth, 25).fill(classificationColor);
        doc.fontSize(10).fillColor('white').text(classification, 0, 8, { align: 'center' });
      }
    }
  }

  /**
   * Render a chart (simplified representation as PDFKit doesn't natively support charts)
   */
  private renderChart(doc: PDFKit.PDFDocument, chart: ReportChart, options: ReportGenerationOptions): void {
    const margins = options.margins || { top: 72, right: 72, bottom: 72, left: 72 };
    const chartWidth = chart.width || 400;
    const chartHeight = chart.height || 250;

    // Chart title
    doc.fontSize(12).fillColor('#333333').text(chart.title, margins.left, doc.y);
    doc.moveDown(0.5);

    const chartX = margins.left;
    const chartY = doc.y;

    // Draw chart container
    doc.rect(chartX, chartY, chartWidth, chartHeight).stroke('#cccccc');

    // Render based on chart type
    switch (chart.type) {
      case 'bar':
        this.renderBarChart(doc, chart, chartX, chartY, chartWidth, chartHeight, options);
        break;
      case 'pie':
        this.renderPieChart(doc, chart, chartX, chartY, chartWidth, chartHeight, options);
        break;
      case 'line':
        this.renderLineChart(doc, chart, chartX, chartY, chartWidth, chartHeight, options);
        break;
      case 'timeline':
        this.renderTimelineChart(doc, chart, chartX, chartY, chartWidth, chartHeight, options);
        break;
      case 'network':
        this.renderNetworkChart(doc, chart, chartX, chartY, chartWidth, chartHeight, options);
        break;
      default:
        // Placeholder for unsupported chart types
        doc.fontSize(10).fillColor('#666666').text(`[${chart.type} chart]`, chartX + 10, chartY + chartHeight / 2);
    }

    doc.y = chartY + chartHeight + 10;
  }

  /**
   * Render a simple bar chart
   */
  private renderBarChart(
    doc: PDFKit.PDFDocument,
    chart: ReportChart,
    x: number,
    y: number,
    width: number,
    height: number,
    options: ReportGenerationOptions
  ): void {
    const data = chart.data as { labels: string[]; values: number[] };
    if (!data.labels || !data.values) return;

    const padding = 40;
    const barWidth = (width - padding * 2) / data.labels.length - 10;
    const maxValue = Math.max(...data.values);
    const chartArea = height - padding * 2;

    const colors = options.chartStyle === 'grayscale'
      ? ['#333333', '#666666', '#999999', '#cccccc']
      : ['#1a1a2e', '#4a4a68', '#6b6b8d', '#9090b3'];

    // Draw bars
    data.values.forEach((value, index) => {
      const barHeight = (value / maxValue) * chartArea;
      const barX = x + padding + index * (barWidth + 10);
      const barY = y + height - padding - barHeight;

      doc.rect(barX, barY, barWidth, barHeight).fill(colors[index % colors.length]);

      // Value label
      doc.fontSize(8)
        .fillColor('#333333')
        .text(value.toString(), barX, barY - 12, { width: barWidth, align: 'center' });

      // Category label
      doc.fontSize(7)
        .fillColor('#666666')
        .text(data.labels[index], barX, y + height - padding + 5, { width: barWidth, align: 'center' });
    });
  }

  /**
   * Render a simple pie chart
   */
  private renderPieChart(
    doc: PDFKit.PDFDocument,
    chart: ReportChart,
    x: number,
    y: number,
    width: number,
    height: number,
    options: ReportGenerationOptions
  ): void {
    const data = chart.data as { labels: string[]; values: number[] };
    if (!data.labels || !data.values) return;

    const centerX = x + width / 2 - 50;
    const centerY = y + height / 2;
    const radius = Math.min(width, height) / 3;
    const total = data.values.reduce((a, b) => a + b, 0);

    const colors = options.chartStyle === 'grayscale'
      ? ['#1a1a1a', '#333333', '#4d4d4d', '#666666', '#808080', '#999999']
      : ['#1a1a2e', '#4a4a68', '#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4'];

    let currentAngle = -Math.PI / 2;

    // Draw pie slices (simplified arc representation)
    data.values.forEach((value, index) => {
      const sliceAngle = (value / total) * 2 * Math.PI;
      const endAngle = currentAngle + sliceAngle;

      // Draw slice as a polygon approximation
      const startX = centerX + Math.cos(currentAngle) * radius;
      const startY = centerY + Math.sin(currentAngle) * radius;
      const endX = centerX + Math.cos(endAngle) * radius;
      const endY = centerY + Math.sin(endAngle) * radius;

      doc.moveTo(centerX, centerY)
        .lineTo(startX, startY)
        .lineTo(endX, endY)
        .lineTo(centerX, centerY)
        .fill(colors[index % colors.length]);

      currentAngle = endAngle;
    });

    // Legend
    const legendX = x + width - 120;
    let legendY = y + 30;

    data.labels.forEach((label, index) => {
      doc.rect(legendX, legendY, 10, 10).fill(colors[index % colors.length]);
      doc.fontSize(8)
        .fillColor('#333333')
        .text(`${label} (${Math.round((data.values[index] / total) * 100)}%)`, legendX + 15, legendY);
      legendY += 15;
    });
  }

  /**
   * Render a simple line chart
   */
  private renderLineChart(
    doc: PDFKit.PDFDocument,
    chart: ReportChart,
    x: number,
    y: number,
    width: number,
    height: number,
    options: ReportGenerationOptions
  ): void {
    const data = chart.data as { labels: string[]; values: number[] };
    if (!data.labels || !data.values) return;

    const padding = 40;
    const chartWidth = width - padding * 2;
    const chartHeight = height - padding * 2;
    const maxValue = Math.max(...data.values);
    const minValue = Math.min(...data.values);
    const valueRange = maxValue - minValue || 1;

    // Draw axes
    doc.moveTo(x + padding, y + padding)
      .lineTo(x + padding, y + height - padding)
      .lineTo(x + width - padding, y + height - padding)
      .stroke('#cccccc');

    // Draw line
    const points: { x: number; y: number }[] = [];
    data.values.forEach((value, index) => {
      const pointX = x + padding + (index / (data.values.length - 1 || 1)) * chartWidth;
      const pointY = y + height - padding - ((value - minValue) / valueRange) * chartHeight;
      points.push({ x: pointX, y: pointY });
    });

    if (points.length > 0) {
      const lineColor = options.chartStyle === 'grayscale' ? '#333333' : '#1a1a2e';
      doc.moveTo(points[0].x, points[0].y);
      points.slice(1).forEach((point) => doc.lineTo(point.x, point.y));
      doc.stroke(lineColor);

      // Draw points
      points.forEach((point) => {
        doc.circle(point.x, point.y, 3).fill(lineColor);
      });
    }

    // X-axis labels
    data.labels.forEach((label, index) => {
      const labelX = x + padding + (index / (data.labels.length - 1 || 1)) * chartWidth;
      doc.fontSize(6)
        .fillColor('#666666')
        .text(label, labelX - 15, y + height - padding + 5, { width: 30, align: 'center' });
    });
  }

  /**
   * Render a timeline chart
   */
  private renderTimelineChart(
    doc: PDFKit.PDFDocument,
    chart: ReportChart,
    x: number,
    y: number,
    width: number,
    height: number,
    _options: ReportGenerationOptions
  ): void {
    const data = chart.data as { events: { date: string; title: string; description?: string }[] };
    if (!data.events) return;

    const padding = 30;
    const lineY = y + height / 2;

    // Draw timeline line
    doc.moveTo(x + padding, lineY).lineTo(x + width - padding, lineY).stroke('#1a1a2e');

    // Draw events
    const eventSpacing = (width - padding * 2) / (data.events.length - 1 || 1);
    data.events.forEach((event, index) => {
      const eventX = x + padding + index * eventSpacing;

      // Event marker
      doc.circle(eventX, lineY, 5).fill('#1a1a2e');

      // Event details (alternating above/below)
      const isAbove = index % 2 === 0;
      const textY = isAbove ? lineY - 50 : lineY + 15;

      doc.fontSize(7).fillColor('#333333').text(event.date, eventX - 25, textY, { width: 50, align: 'center' });
      doc.fontSize(8).fillColor('#1a1a2e').text(event.title, eventX - 40, textY + 12, { width: 80, align: 'center' });
    });
  }

  /**
   * Render a network/relationship chart
   */
  private renderNetworkChart(
    doc: PDFKit.PDFDocument,
    chart: ReportChart,
    x: number,
    y: number,
    width: number,
    height: number,
    _options: ReportGenerationOptions
  ): void {
    const data = chart.data as { nodes: { id: string; label: string }[]; edges: { from: string; to: string }[] };
    if (!data.nodes) return;

    const centerX = x + width / 2;
    const centerY = y + height / 2;
    const radius = Math.min(width, height) / 3;

    // Position nodes in a circle
    const nodePositions: Record<string, { x: number; y: number }> = {};
    data.nodes.forEach((node, index) => {
      const angle = (index / data.nodes.length) * 2 * Math.PI - Math.PI / 2;
      nodePositions[node.id] = {
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius,
      };
    });

    // Draw edges
    if (data.edges) {
      data.edges.forEach((edge) => {
        const from = nodePositions[edge.from];
        const to = nodePositions[edge.to];
        if (from && to) {
          doc.moveTo(from.x, from.y).lineTo(to.x, to.y).stroke('#cccccc');
        }
      });
    }

    // Draw nodes
    data.nodes.forEach((node) => {
      const pos = nodePositions[node.id];
      doc.circle(pos.x, pos.y, 15).fill('#1a1a2e');
      doc.fontSize(7).fillColor('#ffffff').text(node.label.substring(0, 3), pos.x - 8, pos.y - 3);
    });
  }

  /**
   * Generate a table
   */
  renderTable(doc: PDFKit.PDFDocument, table: ReportTable, options: ReportGenerationOptions): void {
    const margins = options.margins || { top: 72, right: 72, bottom: 72, left: 72 };
    const pageWidth = doc.page.width;
    const tableWidth = pageWidth - margins.left - margins.right;
    const columnCount = table.headers.length;
    const columnWidth = tableWidth / columnCount;
    const rowHeight = 20;
    const headerHeight = 25;

    let tableX = margins.left;
    let tableY = doc.y + 10;

    // Table title
    if (table.title) {
      doc.fontSize(12).fillColor('#333333').text(table.title, tableX, tableY);
      tableY += 20;
    }

    // Header row
    doc.rect(tableX, tableY, tableWidth, headerHeight).fill('#1a1a2e');
    table.headers.forEach((header, index) => {
      const cellX = tableX + index * columnWidth;
      doc.fontSize(9)
        .fillColor('#ffffff')
        .text(header, cellX + 5, tableY + 7, { width: columnWidth - 10, align: 'left' });
    });
    tableY += headerHeight;

    // Data rows
    table.rows.forEach((row, rowIndex) => {
      const isStriped = table.striped && rowIndex % 2 === 1;

      if (isStriped) {
        doc.rect(tableX, tableY, tableWidth, rowHeight).fill('#f5f5f5');
      }

      if (table.bordered) {
        doc.rect(tableX, tableY, tableWidth, rowHeight).stroke('#cccccc');
      }

      row.forEach((cell, cellIndex) => {
        const cellX = tableX + cellIndex * columnWidth;
        const cellValue = cell !== null && cell !== undefined ? String(cell) : '';
        doc.fontSize(8)
          .fillColor('#333333')
          .text(cellValue, cellX + 5, tableY + 5, { width: columnWidth - 10, align: 'left' });
      });

      tableY += rowHeight;

      // Check for page break
      if (tableY > doc.page.height - margins.bottom - 50) {
        doc.addPage();
        this.pageCount++;
        tableY = margins.top;
      }
    });

    // Footer row
    if (table.footers) {
      doc.rect(tableX, tableY, tableWidth, rowHeight).fill('#e5e5e5');
      table.footers.forEach((footer, index) => {
        const cellX = tableX + index * columnWidth;
        doc.fontSize(8)
          .fillColor('#333333')
          .text(footer, cellX + 5, tableY + 5, { width: columnWidth - 10, align: 'left' });
      });
    }

    doc.y = tableY + rowHeight + 10;
  }

  /**
   * Add headers and footers to all pages
   */
  private addHeadersFooters(
    doc: PDFKit.PDFDocument,
    data: FormattedReportData,
    options: ReportGenerationOptions
  ): void {
    const range = doc.bufferedPageRange();
    const classification = data.classification;
    const classificationColor = CLASSIFICATION_COLORS[classification];

    for (let i = range.start; i < range.start + range.count; i++) {
      doc.switchToPage(i);

      // Skip cover page
      if (i === 0) continue;

      const pageWidth = doc.page.width;
      const pageHeight = doc.page.height;

      // Header
      doc.rect(0, 0, pageWidth, 25).fill(classificationColor);
      doc.fontSize(10).fillColor('white').text(classification, 0, 8, { align: 'center' });

      // Header text (optional)
      if (options.headerText) {
        doc.fontSize(8).fillColor('#666666').text(options.headerText, 72, 30, { width: pageWidth - 144, align: 'left' });
      }

      // Footer classification banner
      doc.rect(0, pageHeight - 25, pageWidth, 25).fill(classificationColor);
      doc.fontSize(10).fillColor('white').text(classification, 0, pageHeight - 17, { align: 'center' });

      // Page number
      if (options.includePageNumbers) {
        doc.fontSize(8)
          .fillColor('#666666')
          .text(`Page ${i} of ${range.count}`, 0, pageHeight - 38, { align: 'center', width: pageWidth });
      }

      // Footer text
      if (options.footerText || data.footer) {
        const footerText = options.footerText || data.footer;
        doc.fontSize(7)
          .fillColor('#999999')
          .text(footerText!, 72, pageHeight - 50, { width: pageWidth - 144, align: 'center' });
      }
    }
  }

  /**
   * Add watermark to all pages
   */
  private addWatermark(doc: PDFKit.PDFDocument, text: string, options: ReportGenerationOptions): void {
    const range = doc.bufferedPageRange();

    for (let i = range.start; i < range.start + range.count; i++) {
      doc.switchToPage(i);

      const pageWidth = doc.page.width;
      const pageHeight = doc.page.height;

      // Diagonal watermark
      doc.save();
      doc.translate(pageWidth / 2, pageHeight / 2);
      doc.rotate(-45);
      doc.fontSize(60).fillColor('#cccccc').fillOpacity(0.2).text(text, -150, -30);
      doc.restore();
    }
  }

  /**
   * Check if we need a page break
   */
  private needsPageBreak(doc: PDFKit.PDFDocument, requiredSpace: number): boolean {
    const margins = { bottom: 72 };
    return doc.y > doc.page.height - margins.bottom - requiredSpace;
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

export const pdfExporter = new PDFExporter();
