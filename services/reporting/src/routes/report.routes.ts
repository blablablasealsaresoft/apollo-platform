/**
 * Apollo Report API Routes
 *
 * RESTful API endpoints for report generation and management.
 *
 * Endpoints:
 * - POST   /api/v1/reports/generate           - Generate a new report
 * - GET    /api/v1/reports                    - List all reports
 * - GET    /api/v1/reports/templates          - Get available templates
 * - GET    /api/v1/reports/templates/:type    - Get templates by report type
 * - GET    /api/v1/reports/types              - Get available report types
 * - POST   /api/v1/reports/schedules          - Create report schedule
 * - GET    /api/v1/reports/:id                - Get report details
 * - GET    /api/v1/reports/:id/status         - Get report generation status
 * - GET    /api/v1/reports/:id/download       - Download report file
 * - DELETE /api/v1/reports/:id                - Delete a report
 *
 * IMPORTANT: Static routes must be defined BEFORE parameterized routes
 * to ensure Express matches them correctly.
 */

import { Router, Request, Response, NextFunction } from 'express';
import { reportService, REPORT_ERROR_CODES } from '../services/report.service';
import {
  ReportType,
  ExportFormat,
  ReportStatus,
  ClassificationMarking,
  GenerateReportRequest,
} from '../types';

const router = Router();

// Middleware for extracting user info from request
const getUserId = (req: Request): string => {
  return (req as any).user?.id || 'system';
};

// Validation helpers
const validateReportType = (type: string): type is ReportType => {
  return Object.values(ReportType).includes(type as ReportType);
};

const validateExportFormat = (format: string): format is ExportFormat => {
  return Object.values(ExportFormat).includes(format as ExportFormat);
};

const validateClassification = (classification: string): classification is ClassificationMarking => {
  return Object.values(ClassificationMarking).includes(classification as ClassificationMarking);
};

// =============================================================================
// STATIC ROUTES (must be defined before parameterized routes)
// =============================================================================

/**
 * POST /api/v1/reports/generate
 * Generate a new report
 */
router.post('/generate', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { type, format, title, parameters, options } = req.body;

    // Validate required fields
    if (!type) {
      return res.status(400).json({
        success: false,
        error: {
          code: REPORT_ERROR_CODES.INVALID_TYPE,
          message: 'Report type is required',
        },
      });
    }

    if (!format) {
      return res.status(400).json({
        success: false,
        error: {
          code: REPORT_ERROR_CODES.INVALID_FORMAT,
          message: 'Export format is required',
        },
      });
    }

    if (!validateReportType(type)) {
      return res.status(400).json({
        success: false,
        error: {
          code: REPORT_ERROR_CODES.INVALID_TYPE,
          message: `Invalid report type: ${type}. Valid types: ${Object.values(ReportType).join(', ')}`,
        },
      });
    }

    if (!validateExportFormat(format)) {
      return res.status(400).json({
        success: false,
        error: {
          code: REPORT_ERROR_CODES.INVALID_FORMAT,
          message: `Invalid export format: ${format}. Valid formats: ${Object.values(ExportFormat).join(', ')}`,
        },
      });
    }

    if (options?.classification && !validateClassification(options.classification)) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_CLASSIFICATION',
          message: `Invalid classification: ${options.classification}`,
        },
      });
    }

    const request: GenerateReportRequest = {
      type,
      format,
      title,
      parameters: parameters || {},
      options,
    };

    const result = await reportService.generateReport(request, getUserId(req));

    res.status(202).json({
      success: true,
      data: result,
      message: 'Report generation initiated',
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/v1/reports/templates
 * Get available report templates
 */
router.get('/templates', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { type } = req.query;

    let reportType: ReportType | undefined;
    if (type && validateReportType(type as string)) {
      reportType = type as ReportType;
    }

    const templates = await reportService.getTemplates(reportType);

    res.json({
      success: true,
      data: {
        templates,
        availableTypes: Object.values(ReportType),
        availableFormats: Object.values(ExportFormat),
        availableClassifications: Object.values(ClassificationMarking),
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/v1/reports/templates/:type
 * Get templates for a specific report type
 */
router.get('/templates/:type', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { type } = req.params;

    if (!validateReportType(type)) {
      return res.status(400).json({
        success: false,
        error: {
          code: REPORT_ERROR_CODES.INVALID_TYPE,
          message: `Invalid report type: ${type}`,
        },
      });
    }

    const templates = await reportService.getTemplates(type as ReportType);

    res.json({
      success: true,
      data: templates,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/v1/reports/types
 * Get available report types and their parameters
 */
router.get('/types', async (_req: Request, res: Response) => {
  const reportTypes = [
    {
      type: ReportType.INVESTIGATION_SUMMARY,
      name: 'Investigation Summary',
      description: 'Comprehensive summary of an investigation including findings, evidence, and recommendations',
      requiredParameters: ['investigationId'],
      optionalParameters: ['includeTimeline', 'includeEvidence'],
    },
    {
      type: ReportType.TARGET_PROFILE,
      name: 'Target Profile',
      description: 'Detailed dossier on a target including personal info, associates, and threat assessment',
      requiredParameters: ['targetId'],
      optionalParameters: ['includeFinancials', 'includeDigitalFootprint'],
    },
    {
      type: ReportType.EVIDENCE_CHAIN,
      name: 'Evidence Chain',
      description: 'Chain of custody report for evidence items',
      requiredParameters: ['investigationId'],
      optionalParameters: ['evidenceIds'],
    },
    {
      type: ReportType.INTELLIGENCE_ANALYSIS,
      name: 'Intelligence Analysis',
      description: 'Intelligence analysis report with assessments and indicators',
      requiredParameters: ['reportIds'],
      optionalParameters: [],
    },
    {
      type: ReportType.OPERATION_AFTER_ACTION,
      name: 'Operation After-Action',
      description: 'Post-operation review with lessons learned and follow-up actions',
      requiredParameters: ['operationId'],
      optionalParameters: [],
    },
    {
      type: ReportType.THREAT_ASSESSMENT,
      name: 'Threat Assessment',
      description: 'Threat assessment for specified targets',
      requiredParameters: ['targetIds'],
      optionalParameters: ['timeframe'],
    },
    {
      type: ReportType.FINANCIAL_ANALYSIS,
      name: 'Financial Analysis',
      description: 'Financial analysis report including transactions and suspicious activity',
      requiredParameters: ['targetId'],
      optionalParameters: ['startDate', 'endDate'],
    },
    {
      type: ReportType.NETWORK_MAPPING,
      name: 'Network Mapping',
      description: 'Entity relationship and network analysis report',
      requiredParameters: ['entityIds'],
      optionalParameters: ['depth'],
    },
    {
      type: ReportType.TIMELINE,
      name: 'Timeline',
      description: 'Chronological timeline of events',
      requiredParameters: ['entityId', 'entityType'],
      optionalParameters: ['startDate', 'endDate'],
    },
    {
      type: ReportType.EXECUTIVE_BRIEF,
      name: 'Executive Brief',
      description: 'High-level executive summary of operations and investigations',
      requiredParameters: [],
      optionalParameters: ['operationIds', 'investigationIds', 'dateRange'],
    },
  ];

  res.json({
    success: true,
    data: {
      reportTypes,
      exportFormats: Object.values(ExportFormat),
      classifications: Object.values(ClassificationMarking),
    },
  });
});

/**
 * POST /api/v1/reports/schedules
 * Create a report schedule
 */
router.post('/schedules', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const {
      name,
      reportType,
      format,
      parameters,
      options,
      cronExpression,
      timezone = 'UTC',
      recipients,
      isActive = true,
    } = req.body;

    // Validate required fields
    if (!name || !reportType || !format || !cronExpression) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_REQUEST',
          message: 'name, reportType, format, and cronExpression are required',
        },
      });
    }

    if (!validateReportType(reportType)) {
      return res.status(400).json({
        success: false,
        error: {
          code: REPORT_ERROR_CODES.INVALID_TYPE,
          message: `Invalid report type: ${reportType}`,
        },
      });
    }

    if (!validateExportFormat(format)) {
      return res.status(400).json({
        success: false,
        error: {
          code: REPORT_ERROR_CODES.INVALID_FORMAT,
          message: `Invalid export format: ${format}`,
        },
      });
    }

    // Calculate next run time based on cron expression
    const nextRun = calculateNextRunTime(cronExpression, timezone);

    const schedule = await reportService.createSchedule({
      name,
      reportType,
      format,
      parameters: parameters || {},
      options: options || {},
      cronExpression,
      timezone,
      isActive,
      recipients: recipients || [],
      nextRun,
      createdBy: getUserId(req),
    });

    res.status(201).json({
      success: true,
      data: schedule,
      message: 'Report schedule created successfully',
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/v1/reports
 * List all reports with optional filters
 */
router.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const {
      type,
      status,
      limit = '50',
      offset = '0',
      userId,
    } = req.query;

    const filters: {
      userId?: string;
      type?: ReportType;
      status?: ReportStatus;
      limit?: number;
      offset?: number;
    } = {
      limit: parseInt(limit as string, 10),
      offset: parseInt(offset as string, 10),
    };

    if (type && validateReportType(type as string)) {
      filters.type = type as ReportType;
    }

    if (status && Object.values(ReportStatus).includes(status as ReportStatus)) {
      filters.status = status as ReportStatus;
    }

    if (userId) {
      filters.userId = userId as string;
    }

    const result = await reportService.listReports(filters);

    res.json({
      success: true,
      data: {
        reports: result.reports,
        pagination: {
          total: result.total,
          limit: filters.limit,
          offset: filters.offset,
          hasMore: (filters.offset || 0) + result.reports.length < result.total,
        },
      },
    });
  } catch (error) {
    next(error);
  }
});

// =============================================================================
// PARAMETERIZED ROUTES (must be defined after static routes)
// =============================================================================

/**
 * GET /api/v1/reports/:id
 * Get report details by ID
 */
router.get('/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;

    const report = await reportService.getReport(id);

    res.json({
      success: true,
      data: report,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/v1/reports/:id/status
 * Get report generation status
 */
router.get('/:id/status', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;

    const report = await reportService.getReport(id);

    res.json({
      success: true,
      data: {
        id: report.id,
        status: report.status,
        createdAt: report.createdAt,
        completedAt: report.completedAt,
        error: report.error,
        progress: getProgressEstimate(report.status),
      },
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/v1/reports/:id/download
 * Download report file
 */
router.get('/:id/download', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;

    const { metadata, content } = await reportService.downloadReport(id);

    // Set response headers
    const filename = generateDownloadFilename(metadata.title, metadata.format);
    const mimeType = getMimeType(metadata.format);

    res.setHeader('Content-Type', mimeType);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', content.length);
    res.setHeader('X-Report-Classification', metadata.classification);
    res.setHeader('X-Report-ID', metadata.id);

    if (metadata.checksum) {
      res.setHeader('X-Report-Checksum', metadata.checksum);
    }

    res.send(content);
  } catch (error) {
    next(error);
  }
});

/**
 * DELETE /api/v1/reports/:id
 * Delete a report
 */
router.delete('/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;

    await reportService.deleteReport(id);

    res.json({
      success: true,
      message: 'Report deleted successfully',
    });
  } catch (error) {
    next(error);
  }
});

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

function getProgressEstimate(status: ReportStatus): number {
  const progressMap: Record<ReportStatus, number> = {
    [ReportStatus.QUEUED]: 10,
    [ReportStatus.GENERATING]: 50,
    [ReportStatus.COMPLETED]: 100,
    [ReportStatus.FAILED]: 0,
    [ReportStatus.EXPIRED]: 100,
  };
  return progressMap[status] || 0;
}

function generateDownloadFilename(title: string, format: ExportFormat): string {
  const sanitizedTitle = title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .substring(0, 50);

  const timestamp = new Date().toISOString().split('T')[0];
  const extension = getFileExtension(format);

  return `${sanitizedTitle}_${timestamp}.${extension}`;
}

function getFileExtension(format: ExportFormat): string {
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

function getMimeType(format: ExportFormat): string {
  const mimeTypes: Record<ExportFormat, string> = {
    [ExportFormat.PDF]: 'application/pdf',
    [ExportFormat.DOCX]: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    [ExportFormat.XLSX]: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    [ExportFormat.HTML]: 'text/html',
    [ExportFormat.JSON]: 'application/json',
    [ExportFormat.MARKDOWN]: 'text/markdown',
  };
  return mimeTypes[format];
}

function calculateNextRunTime(cronExpression: string, _timezone: string): Date {
  // Simplified next run calculation - in production, use a proper cron parser
  // For now, return 24 hours from now
  return new Date(Date.now() + 24 * 60 * 60 * 1000);
}

export default router;
