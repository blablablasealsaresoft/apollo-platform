/**
 * Apollo Report Service
 *
 * Core service for generating professional reports across multiple formats.
 * Supports investigation summaries, target profiles, evidence chains,
 * intelligence analysis, and operation after-action reports.
 */

import {
  database,
  logger,
  generateId,
  redis,
  NotFoundError,
  BadRequestError,
  InternalServerError,
} from '@apollo/shared';
import {
  ReportType,
  ExportFormat,
  ReportStatus,
  ReportMetadata,
  GenerateReportRequest,
  GenerateReportResponse,
  ReportGenerationOptions,
  ClassificationMarking,
  InvestigationSummaryData,
  TargetProfileData,
  EvidenceChainData,
  IntelligenceAnalysisData,
  OperationAfterActionData,
  ReportTemplate,
  ReportSchedule,
} from '../types';
import { PDFExporter } from '../exporters/pdf.exporter';
import { DocxExporter } from '../exporters/docx.exporter';
import { ExcelExporter } from '../exporters/excel.exporter';
import { HTMLExporter } from '../exporters/html.exporter';
import { JSONExporter } from '../exporters/json.exporter';
import { CaseFormatter } from '../formatters/case.formatter';
import { TargetFormatter } from '../formatters/target.formatter';
import { TimelineFormatter } from '../formatters/timeline.formatter';
import { NetworkFormatter } from '../formatters/network.formatter';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs/promises';

// Error codes for report service
export const REPORT_ERROR_CODES = {
  NOT_FOUND: 'REPORT_NOT_FOUND',
  GENERATION_FAILED: 'REPORT_GENERATION_FAILED',
  INVALID_FORMAT: 'REPORT_INVALID_FORMAT',
  INVALID_TYPE: 'REPORT_INVALID_TYPE',
  EXPORT_FAILED: 'REPORT_EXPORT_FAILED',
  DATA_FETCH_FAILED: 'REPORT_DATA_FETCH_FAILED',
  TEMPLATE_NOT_FOUND: 'REPORT_TEMPLATE_NOT_FOUND',
  SCHEDULE_NOT_FOUND: 'REPORT_SCHEDULE_NOT_FOUND',
  CACHE_ERROR: 'REPORT_CACHE_ERROR',
} as const;

// Default report options
const DEFAULT_OPTIONS: ReportGenerationOptions = {
  format: ExportFormat.PDF,
  classification: ClassificationMarking.UNCLASSIFIED,
  includeTableOfContents: true,
  includePageNumbers: true,
  includeWatermark: true,
  pageSize: 'letter',
  orientation: 'portrait',
  margins: { top: 72, right: 72, bottom: 72, left: 72 },
  fontSize: 11,
  fontFamily: 'Helvetica',
  includeCharts: true,
  chartStyle: 'color',
  expirationHours: 24,
};

// Report storage directory
const REPORTS_DIR = process.env.REPORTS_DIR || '/tmp/apollo-reports';

export class ReportService {
  private pdfExporter: PDFExporter;
  private docxExporter: DocxExporter;
  private excelExporter: ExcelExporter;
  private htmlExporter: HTMLExporter;
  private jsonExporter: JSONExporter;
  private caseFormatter: CaseFormatter;
  private targetFormatter: TargetFormatter;
  private timelineFormatter: TimelineFormatter;
  private networkFormatter: NetworkFormatter;

  constructor() {
    this.pdfExporter = new PDFExporter();
    this.docxExporter = new DocxExporter();
    this.excelExporter = new ExcelExporter();
    this.htmlExporter = new HTMLExporter();
    this.jsonExporter = new JSONExporter();
    this.caseFormatter = new CaseFormatter();
    this.targetFormatter = new TargetFormatter();
    this.timelineFormatter = new TimelineFormatter();
    this.networkFormatter = new NetworkFormatter();
  }

  /**
   * Initialize report service - ensure storage directory exists
   */
  async initialize(): Promise<void> {
    try {
      await fs.mkdir(REPORTS_DIR, { recursive: true });
      logger.info(`Report storage initialized at: ${REPORTS_DIR}`);
    } catch (error: any) {
      logger.error(`Failed to initialize report storage: ${error.message}`);
      throw new InternalServerError('Failed to initialize report service');
    }
  }

  /**
   * Generate a report based on the request
   */
  async generateReport(
    request: GenerateReportRequest,
    userId: string
  ): Promise<GenerateReportResponse> {
    const reportId = generateId();
    const options = { ...DEFAULT_OPTIONS, ...request.options, format: request.format };

    // Validate request
    if (!Object.values(ReportType).includes(request.type)) {
      throw new BadRequestError(`Invalid report type: ${request.type}`, REPORT_ERROR_CODES.INVALID_TYPE);
    }
    if (!Object.values(ExportFormat).includes(request.format)) {
      throw new BadRequestError(`Invalid export format: ${request.format}`, REPORT_ERROR_CODES.INVALID_FORMAT);
    }

    // Create report metadata record
    const metadata: ReportMetadata = {
      id: reportId,
      title: request.title || this.generateDefaultTitle(request.type),
      type: request.type,
      format: request.format,
      status: ReportStatus.QUEUED,
      classification: options.classification,
      clearanceRequired: this.getRequiredClearance(options.classification),
      createdBy: userId,
      createdAt: new Date(),
      parameters: request.parameters,
    };

    // Store metadata
    await this.saveReportMetadata(metadata);

    // Queue report generation (async processing)
    this.processReport(reportId, request, options, userId).catch((error) => {
      logger.error(`Report generation failed for ${reportId}: ${error.message}`);
      this.updateReportStatus(reportId, ReportStatus.FAILED, error.message);
    });

    return {
      reportId,
      status: ReportStatus.QUEUED,
      estimatedCompletionTime: this.estimateGenerationTime(request.type, request.format),
    };
  }

  /**
   * Process report generation asynchronously
   */
  private async processReport(
    reportId: string,
    request: GenerateReportRequest,
    options: ReportGenerationOptions,
    userId: string
  ): Promise<void> {
    try {
      // Update status to generating
      await this.updateReportStatus(reportId, ReportStatus.GENERATING);

      // Fetch report data based on type
      const data = await this.fetchReportData(request.type, request.parameters);

      // Format data
      const formattedData = await this.formatReportData(request.type, data, options);

      // Export to requested format
      const exportResult = await this.exportReport(request.format, formattedData, options);

      // Calculate checksum
      const checksum = crypto.createHash('sha256').update(exportResult.buffer).digest('hex');

      // Save file
      const filename = this.generateFilename(reportId, request.type, request.format);
      const filePath = path.join(REPORTS_DIR, filename);
      await fs.writeFile(filePath, exportResult.buffer);

      // Update metadata with completion info
      await this.updateReportMetadata(reportId, {
        status: ReportStatus.COMPLETED,
        completedAt: new Date(),
        expiresAt: new Date(Date.now() + (options.expirationHours || 24) * 60 * 60 * 1000),
        fileSize: exportResult.buffer.length,
        filePath,
        checksum,
      });

      // Cache report metadata
      await this.cacheReportMetadata(reportId);

      logger.info(`Report generated successfully: ${reportId}`);
    } catch (error: any) {
      logger.error(`Report generation error: ${error.message}`);
      throw error;
    }
  }

  /**
   * Fetch data for report based on type
   */
  private async fetchReportData(
    type: ReportType,
    parameters: Record<string, any>
  ): Promise<any> {
    try {
      switch (type) {
        case ReportType.INVESTIGATION_SUMMARY:
          return this.fetchInvestigationData(parameters.investigationId);
        case ReportType.TARGET_PROFILE:
          return this.fetchTargetData(parameters.targetId);
        case ReportType.EVIDENCE_CHAIN:
          return this.fetchEvidenceChainData(parameters.investigationId, parameters.evidenceIds);
        case ReportType.INTELLIGENCE_ANALYSIS:
          return this.fetchIntelligenceData(parameters.reportIds);
        case ReportType.OPERATION_AFTER_ACTION:
          return this.fetchOperationData(parameters.operationId);
        case ReportType.THREAT_ASSESSMENT:
          return this.fetchThreatAssessmentData(parameters);
        case ReportType.FINANCIAL_ANALYSIS:
          return this.fetchFinancialData(parameters.targetId, parameters);
        case ReportType.NETWORK_MAPPING:
          return this.fetchNetworkData(parameters);
        case ReportType.TIMELINE:
          return this.fetchTimelineData(parameters);
        case ReportType.EXECUTIVE_BRIEF:
          return this.fetchExecutiveBriefData(parameters);
        default:
          throw new BadRequestError(`Unsupported report type: ${type}`);
      }
    } catch (error: any) {
      if (error instanceof BadRequestError || error instanceof NotFoundError) {
        throw error;
      }
      logger.error(`Failed to fetch report data: ${error.message}`);
      throw new InternalServerError('Failed to fetch report data', REPORT_ERROR_CODES.DATA_FETCH_FAILED);
    }
  }

  /**
   * Fetch investigation summary data
   */
  private async fetchInvestigationData(investigationId: string): Promise<InvestigationSummaryData> {
    // Fetch investigation details
    const investigationResult = await database.query(
      `SELECT * FROM investigations WHERE id = $1`,
      [investigationId]
    );
    if (investigationResult.rows.length === 0) {
      throw new NotFoundError(`Investigation not found: ${investigationId}`);
    }
    const investigation = investigationResult.rows[0];

    // Fetch lead investigator
    const leadResult = await database.query(
      `SELECT id, email, username, first_name, last_name, role FROM users WHERE id = $1`,
      [investigation.lead_investigator_id]
    );

    // Fetch team members
    const teamResult = await database.query(
      `SELECT u.id, u.email, u.username, u.first_name, u.last_name, u.role
       FROM users u
       INNER JOIN investigation_team_members itm ON u.id = itm.user_id
       WHERE itm.investigation_id = $1`,
      [investigationId]
    );

    // Fetch evidence
    const evidenceResult = await database.query(
      `SELECT * FROM evidence WHERE investigation_id = $1 ORDER BY collected_at DESC`,
      [investigationId]
    );

    // Fetch targets
    const targetsResult = await database.query(
      `SELECT t.* FROM targets t
       INNER JOIN investigation_targets it ON t.id = it.target_id
       WHERE it.investigation_id = $1`,
      [investigationId]
    );

    // Fetch intelligence reports
    const intelResult = await database.query(
      `SELECT * FROM intelligence_reports WHERE investigation_id = $1 ORDER BY created_at DESC`,
      [investigationId]
    );

    // Fetch key findings
    const findingsResult = await database.query(
      `SELECT * FROM investigation_findings WHERE investigation_id = $1 ORDER BY severity_order, discovered_at DESC`,
      [investigationId]
    );

    // Fetch timeline events
    const timelineResult = await database.query(
      `SELECT * FROM investigation_timeline WHERE investigation_id = $1 ORDER BY event_timestamp ASC`,
      [investigationId]
    );

    return {
      investigationId,
      title: investigation.name,
      codename: investigation.codename,
      status: investigation.status,
      priority: investigation.priority,
      startDate: investigation.start_date,
      endDate: investigation.end_date,
      leadInvestigator: leadResult.rows[0] || {},
      teamMembers: teamResult.rows,
      objectives: investigation.objectives || [],
      keyFindings: findingsResult.rows.map((f: any) => ({
        id: f.id,
        title: f.title,
        description: f.description,
        severity: f.severity,
        confidence: f.confidence,
        evidence: f.evidence_ids || [],
        dateDiscovered: f.discovered_at,
      })),
      evidence: evidenceResult.rows.map((e: any) => ({
        id: e.id,
        type: e.type,
        description: e.description,
        source: e.source,
        dateCollected: e.collected_at,
        chain_of_custody: e.custody_chain || [],
        classification: e.classification,
        hash: e.hash,
      })),
      targets: targetsResult.rows,
      intelligence: intelResult.rows,
      timeline: timelineResult.rows.map((t: any) => ({
        id: t.id,
        timestamp: t.event_timestamp,
        title: t.title,
        description: t.description,
        type: t.event_type,
        actors: t.actors,
        location: t.location,
        relatedEntities: t.related_entities,
        source: t.source,
        confidence: t.confidence,
      })),
      recommendations: investigation.recommendations || [],
      nextSteps: investigation.next_steps || [],
    };
  }

  /**
   * Fetch target profile data
   */
  private async fetchTargetData(targetId: string): Promise<TargetProfileData> {
    const targetResult = await database.query(`SELECT * FROM targets WHERE id = $1`, [targetId]);
    if (targetResult.rows.length === 0) {
      throw new NotFoundError(`Target not found: ${targetId}`);
    }
    const target = targetResult.rows[0];

    // Fetch aliases
    const aliasResult = await database.query(
      `SELECT * FROM target_aliases WHERE target_id = $1 ORDER BY confidence DESC`,
      [targetId]
    );

    // Fetch locations
    const locationResult = await database.query(
      `SELECT * FROM target_locations WHERE target_id = $1 ORDER BY last_seen DESC`,
      [targetId]
    );

    // Fetch associates
    const associatesResult = await database.query(
      `SELECT * FROM target_associates WHERE target_id = $1 ORDER BY strength DESC`,
      [targetId]
    );

    // Fetch organizations
    const orgsResult = await database.query(
      `SELECT * FROM target_organizations WHERE target_id = $1`,
      [targetId]
    );

    // Fetch intelligence reports
    const intelResult = await database.query(
      `SELECT * FROM intelligence_reports WHERE target_id = $1 ORDER BY created_at DESC LIMIT 20`,
      [targetId]
    );

    // Fetch photos
    const photosResult = await database.query(
      `SELECT * FROM target_photos WHERE target_id = $1 ORDER BY created_at DESC`,
      [targetId]
    );

    return {
      target,
      aliases: aliasResult.rows.map((a: any) => ({
        alias: a.alias_value,
        type: a.alias_type,
        confidence: a.confidence,
        source: a.source,
        dateFirstSeen: a.first_seen,
        dateLastSeen: a.last_seen,
      })),
      knownLocations: locationResult.rows.map((l: any) => ({
        address: l.address,
        city: l.city,
        country: l.country,
        coordinates: l.latitude && l.longitude ? { lat: l.latitude, lng: l.longitude } : undefined,
        type: l.location_type,
        dateFirstSeen: l.first_seen,
        dateLastSeen: l.last_seen,
        source: l.source,
        confidence: l.confidence,
      })),
      associates: associatesResult.rows.map((a: any) => ({
        id: a.id,
        name: a.associate_name,
        relationship: a.relationship_type,
        strength: a.strength,
        direction: a.direction,
        dateFirstSeen: a.first_seen,
        dateLastSeen: a.last_seen,
        notes: a.notes,
      })),
      organizations: orgsResult.rows.map((o: any) => ({
        organizationName: o.organization_name,
        role: o.role,
        startDate: o.start_date,
        endDate: o.end_date,
        isActive: o.is_active,
        source: o.source,
      })),
      operationalHistory: target.operational_history || [],
      intelligence: intelResult.rows,
      photos: photosResult.rows.map((p: any) => ({
        id: p.id,
        path: p.file_path,
        caption: p.caption,
        width: p.width,
        height: p.height,
      })),
    };
  }

  /**
   * Fetch evidence chain data
   */
  private async fetchEvidenceChainData(
    investigationId: string,
    evidenceIds?: string[]
  ): Promise<EvidenceChainData> {
    let evidenceQuery = `SELECT * FROM evidence WHERE investigation_id = $1`;
    const params: any[] = [investigationId];

    if (evidenceIds && evidenceIds.length > 0) {
      evidenceQuery += ` AND id = ANY($2)`;
      params.push(evidenceIds);
    }
    evidenceQuery += ` ORDER BY collected_at DESC`;

    const evidenceResult = await database.query(evidenceQuery, params);

    // Fetch custody records
    const custodyResult = await database.query(
      `SELECT * FROM evidence_custody
       WHERE evidence_id = ANY($1)
       ORDER BY evidence_id, timestamp ASC`,
      [evidenceResult.rows.map((e: any) => e.id)]
    );

    // Fetch analysis results
    const analysisResult = await database.query(
      `SELECT * FROM evidence_analysis
       WHERE evidence_id = ANY($1)
       ORDER BY analysis_date DESC`,
      [evidenceResult.rows.map((e: any) => e.id)]
    );

    // Fetch integrity checks
    const integrityResult = await database.query(
      `SELECT * FROM evidence_integrity_checks
       WHERE evidence_id = ANY($1)
       ORDER BY check_date DESC`,
      [evidenceResult.rows.map((e: any) => e.id)]
    );

    return {
      investigationId,
      evidence: evidenceResult.rows.map((e: any) => ({
        id: e.id,
        type: e.type,
        subtype: e.subtype,
        description: e.description,
        originalSource: e.original_source,
        collectionMethod: e.collection_method,
        collectionDate: e.collected_at,
        collectedBy: e.collected_by,
        classification: e.classification,
        storageLocation: e.storage_location,
        hashes: e.hashes || [],
        metadata: e.metadata || {},
        relatedEvidence: e.related_evidence_ids,
      })),
      custodyChain: custodyResult.rows.map((c: any) => ({
        evidenceId: c.evidence_id,
        timestamp: c.timestamp,
        action: c.action,
        from: c.from_user,
        to: c.to_user,
        location: c.location,
        notes: c.notes,
        signature: c.signature,
      })),
      analysisResults: analysisResult.rows.map((a: any) => ({
        evidenceId: a.evidence_id,
        analysisType: a.analysis_type,
        analyst: a.analyst,
        date: a.analysis_date,
        findings: a.findings,
        confidence: a.confidence,
        methodology: a.methodology,
        tools: a.tools,
      })),
      integrityVerification: integrityResult.rows.map((i: any) => ({
        evidenceId: i.evidence_id,
        checkDate: i.check_date,
        checkedBy: i.checked_by,
        algorithm: i.algorithm,
        expectedHash: i.expected_hash,
        actualHash: i.actual_hash,
        isValid: i.is_valid,
        notes: i.notes,
      })),
    };
  }

  /**
   * Fetch intelligence analysis data
   */
  private async fetchIntelligenceData(reportIds: string[]): Promise<IntelligenceAnalysisData> {
    const reportsResult = await database.query(
      `SELECT * FROM intelligence_reports WHERE id = ANY($1) ORDER BY created_at DESC`,
      [reportIds]
    );

    if (reportsResult.rows.length === 0) {
      throw new NotFoundError('No intelligence reports found');
    }

    // Aggregate data from multiple reports
    const reports = reportsResult.rows;
    const primaryReport = reports[0];

    // Fetch analyst info
    const analystResult = await database.query(
      `SELECT id, email, username, first_name, last_name, role FROM users WHERE id = $1`,
      [primaryReport.author_id]
    );

    return {
      title: primaryReport.title,
      analyst: analystResult.rows[0] || {},
      dateCompleted: primaryReport.created_at,
      intelligenceRequirement: primaryReport.intelligence_requirement,
      sources: reports.flatMap((r: any) => r.sources || []),
      keyAssessments: reports.flatMap((r: any) => r.assessments || []),
      analyticalConfidence: {
        overall: primaryReport.confidence,
        factors: primaryReport.confidence_factors || {},
        limitations: primaryReport.limitations || [],
      },
      gaps: primaryReport.intelligence_gaps || [],
      indicators: reports.flatMap((r: any) => r.indicators || []),
      recommendations: reports.flatMap((r: any) => r.recommendations || []),
      dissemination: {
        classification: primaryReport.classification,
        releasableTo: primaryReport.releasable_to || [],
        notReleasableTo: primaryReport.not_releasable_to,
        handlingCaveats: primaryReport.handling_caveats,
      },
    };
  }

  /**
   * Fetch operation after-action data
   */
  private async fetchOperationData(operationId: string): Promise<OperationAfterActionData> {
    const operationResult = await database.query(
      `SELECT * FROM operations WHERE id = $1`,
      [operationId]
    );
    if (operationResult.rows.length === 0) {
      throw new NotFoundError(`Operation not found: ${operationId}`);
    }
    const operation = operationResult.rows[0];

    // Fetch objectives
    const objectivesResult = await database.query(
      `SELECT * FROM operation_objectives WHERE operation_id = $1 ORDER BY priority`,
      [operationId]
    );

    // Fetch phases
    const phasesResult = await database.query(
      `SELECT * FROM operation_phases WHERE operation_id = $1 ORDER BY start_date`,
      [operationId]
    );

    // Fetch lessons learned
    const lessonsResult = await database.query(
      `SELECT * FROM operation_lessons_learned WHERE operation_id = $1 ORDER BY priority, category`,
      [operationId]
    );

    // Fetch incidents
    const incidentsResult = await database.query(
      `SELECT * FROM operation_incidents WHERE operation_id = $1 ORDER BY incident_date`,
      [operationId]
    );

    // Fetch follow-up actions
    const actionsResult = await database.query(
      `SELECT * FROM operation_follow_up_actions WHERE operation_id = $1 ORDER BY priority, due_date`,
      [operationId]
    );

    return {
      operation: {
        id: operation.id,
        name: operation.name,
        codename: operation.codename,
        description: operation.description,
        status: operation.status,
        priority: operation.priority,
        clearanceLevel: operation.clearance_level,
        startDate: operation.start_date,
        endDate: operation.end_date,
      },
      missionObjectives: objectivesResult.rows.map((o: any) => ({
        id: o.id,
        description: o.description,
        status: o.status,
        outcome: o.outcome,
        metrics: o.metrics,
      })),
      executionSummary: {
        startDate: operation.start_date,
        endDate: operation.end_date || new Date(),
        phases: phasesResult.rows.map((p: any) => ({
          name: p.name,
          startDate: p.start_date,
          endDate: p.end_date,
          status: p.status,
          notes: p.notes,
        })),
        majorEvents: operation.major_events || [],
        deviationsFromPlan: operation.deviations || [],
      },
      resourceUtilization: operation.resource_utilization || [],
      lessonsLearned: lessonsResult.rows.map((l: any) => ({
        category: l.category,
        title: l.title,
        description: l.description,
        recommendation: l.recommendation,
        priority: l.priority,
      })),
      teamPerformance: {
        overallRating: operation.team_performance_rating || 'N/A',
        strengthsObserved: operation.team_strengths || [],
        areasForImprovement: operation.team_improvements || [],
        trainingNeeds: operation.training_needs,
      },
      incidentReports: incidentsResult.rows.map((i: any) => ({
        date: i.incident_date,
        type: i.incident_type,
        description: i.description,
        impact: i.impact,
        resolution: i.resolution,
        preventiveMeasures: i.preventive_measures,
      })),
      followUpActions: actionsResult.rows.map((a: any) => ({
        id: a.id,
        action: a.action_description,
        assignedTo: a.assigned_to,
        dueDate: a.due_date,
        priority: a.priority,
        status: a.status,
      })),
    };
  }

  /**
   * Fetch threat assessment data
   */
  private async fetchThreatAssessmentData(parameters: Record<string, any>): Promise<any> {
    const { targetIds, timeframe } = parameters;
    // Aggregate threat data across targets
    const threatsResult = await database.query(
      `SELECT * FROM threat_assessments
       WHERE target_id = ANY($1)
       AND created_at >= NOW() - INTERVAL '${timeframe || '30 days'}'
       ORDER BY threat_level DESC, created_at DESC`,
      [targetIds]
    );
    return { threats: threatsResult.rows, parameters };
  }

  /**
   * Fetch financial analysis data
   */
  private async fetchFinancialData(targetId: string, parameters: Record<string, any>): Promise<any> {
    const financialResult = await database.query(
      `SELECT * FROM financial_profiles WHERE target_id = $1`,
      [targetId]
    );
    const transactionsResult = await database.query(
      `SELECT * FROM financial_transactions WHERE target_id = $1 ORDER BY transaction_date DESC LIMIT 1000`,
      [targetId]
    );
    return {
      profile: financialResult.rows[0],
      transactions: transactionsResult.rows,
      parameters,
    };
  }

  /**
   * Fetch network mapping data
   */
  private async fetchNetworkData(parameters: Record<string, any>): Promise<any> {
    const { entityIds, depth = 2 } = parameters;
    // Fetch relationship network data
    const nodesResult = await database.query(
      `SELECT * FROM entity_nodes WHERE id = ANY($1)`,
      [entityIds]
    );
    const edgesResult = await database.query(
      `SELECT * FROM entity_relationships
       WHERE source_id = ANY($1) OR target_id = ANY($1)`,
      [entityIds]
    );
    return {
      nodes: nodesResult.rows,
      edges: edgesResult.rows,
      depth,
    };
  }

  /**
   * Fetch timeline data
   */
  private async fetchTimelineData(parameters: Record<string, any>): Promise<any> {
    const { entityId, entityType, startDate, endDate } = parameters;
    let query = `SELECT * FROM timeline_events WHERE entity_id = $1 AND entity_type = $2`;
    const params = [entityId, entityType];

    if (startDate) {
      query += ` AND event_timestamp >= $${params.length + 1}`;
      params.push(startDate);
    }
    if (endDate) {
      query += ` AND event_timestamp <= $${params.length + 1}`;
      params.push(endDate);
    }
    query += ` ORDER BY event_timestamp ASC`;

    const result = await database.query(query, params);
    return { events: result.rows, parameters };
  }

  /**
   * Fetch executive brief data
   */
  private async fetchExecutiveBriefData(parameters: Record<string, any>): Promise<any> {
    const { operationIds, investigationIds, dateRange } = parameters;

    // Aggregate high-level data for executive summary
    const opsResult = operationIds?.length > 0
      ? await database.query(`SELECT * FROM operations WHERE id = ANY($1)`, [operationIds])
      : { rows: [] };

    const invResult = investigationIds?.length > 0
      ? await database.query(`SELECT * FROM investigations WHERE id = ANY($1)`, [investigationIds])
      : { rows: [] };

    return {
      operations: opsResult.rows,
      investigations: invResult.rows,
      parameters,
    };
  }

  /**
   * Format data for report generation
   */
  private async formatReportData(
    type: ReportType,
    data: any,
    options: ReportGenerationOptions
  ): Promise<any> {
    switch (type) {
      case ReportType.INVESTIGATION_SUMMARY:
        return this.caseFormatter.formatInvestigationSummary(data, options);
      case ReportType.TARGET_PROFILE:
        return this.targetFormatter.formatTargetProfile(data, options);
      case ReportType.EVIDENCE_CHAIN:
        return this.caseFormatter.formatEvidenceChain(data, options);
      case ReportType.INTELLIGENCE_ANALYSIS:
        return this.caseFormatter.formatIntelligenceAnalysis(data, options);
      case ReportType.OPERATION_AFTER_ACTION:
        return this.caseFormatter.formatAfterActionReport(data, options);
      case ReportType.TIMELINE:
        return this.timelineFormatter.formatTimeline(data, options);
      case ReportType.NETWORK_MAPPING:
        return this.networkFormatter.formatNetworkMap(data, options);
      default:
        return data;
    }
  }

  /**
   * Export report to requested format
   */
  private async exportReport(
    format: ExportFormat,
    data: any,
    options: ReportGenerationOptions
  ): Promise<{ buffer: Buffer; mimeType: string }> {
    switch (format) {
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
        return {
          buffer: Buffer.from(data.markdown || JSON.stringify(data, null, 2)),
          mimeType: 'text/markdown',
        };
      default:
        throw new BadRequestError(`Unsupported export format: ${format}`);
    }
  }

  /**
   * Get report by ID
   */
  async getReport(reportId: string): Promise<ReportMetadata> {
    // Try cache first
    const cached = await this.getCachedReportMetadata(reportId);
    if (cached) {
      return cached;
    }

    // Fetch from database
    const result = await database.query(
      `SELECT * FROM reports WHERE id = $1`,
      [reportId]
    );
    if (result.rows.length === 0) {
      throw new NotFoundError(`Report not found: ${reportId}`, REPORT_ERROR_CODES.NOT_FOUND);
    }

    const report = this.mapDbRowToMetadata(result.rows[0]);

    // Cache for future requests
    await this.cacheReportMetadata(reportId);

    return report;
  }

  /**
   * Download report file
   */
  async downloadReport(reportId: string): Promise<{ metadata: ReportMetadata; content: Buffer }> {
    const metadata = await this.getReport(reportId);

    if (metadata.status !== ReportStatus.COMPLETED) {
      throw new BadRequestError(`Report is not ready for download. Status: ${metadata.status}`);
    }

    if (!metadata.filePath) {
      throw new InternalServerError('Report file path not found');
    }

    // Check if file exists
    try {
      await fs.access(metadata.filePath);
    } catch {
      throw new NotFoundError('Report file not found on disk');
    }

    // Check expiration
    if (metadata.expiresAt && new Date(metadata.expiresAt) < new Date()) {
      throw new BadRequestError('Report has expired');
    }

    const content = await fs.readFile(metadata.filePath);

    // Verify checksum
    if (metadata.checksum) {
      const actualChecksum = crypto.createHash('sha256').update(content).digest('hex');
      if (actualChecksum !== metadata.checksum) {
        throw new InternalServerError('Report file integrity check failed');
      }
    }

    return { metadata, content };
  }

  /**
   * List reports with pagination and filtering
   */
  async listReports(filters: {
    userId?: string;
    type?: ReportType;
    status?: ReportStatus;
    limit?: number;
    offset?: number;
  }): Promise<{ reports: ReportMetadata[]; total: number }> {
    let query = `SELECT * FROM reports WHERE 1=1`;
    let countQuery = `SELECT COUNT(*) FROM reports WHERE 1=1`;
    const params: any[] = [];
    let paramIdx = 1;

    if (filters.userId) {
      const filter = ` AND created_by = $${paramIdx++}`;
      query += filter;
      countQuery += filter;
      params.push(filters.userId);
    }
    if (filters.type) {
      const filter = ` AND type = $${paramIdx++}`;
      query += filter;
      countQuery += filter;
      params.push(filters.type);
    }
    if (filters.status) {
      const filter = ` AND status = $${paramIdx++}`;
      query += filter;
      countQuery += filter;
      params.push(filters.status);
    }

    const countResult = await database.query(countQuery, params);
    const total = parseInt(countResult.rows[0]?.count || '0', 10);

    query += ` ORDER BY created_at DESC`;
    const limit = Math.min(filters.limit || 50, 100);
    const offset = filters.offset || 0;
    query += ` LIMIT ${limit} OFFSET ${offset}`;

    const result = await database.query(query, params);

    return {
      reports: result.rows.map(this.mapDbRowToMetadata),
      total,
    };
  }

  /**
   * Get available report templates
   */
  async getTemplates(type?: ReportType): Promise<ReportTemplate[]> {
    let query = `SELECT * FROM report_templates WHERE 1=1`;
    const params: any[] = [];

    if (type) {
      query += ` AND type = $1`;
      params.push(type);
    }
    query += ` ORDER BY name ASC`;

    const result = await database.query(query, params);
    return result.rows.map((t: any) => ({
      id: t.id,
      name: t.name,
      description: t.description,
      type: t.type,
      version: t.version,
      defaultOptions: t.default_options,
      sections: t.sections,
      createdAt: t.created_at,
      updatedAt: t.updated_at,
    }));
  }

  /**
   * Create a report schedule
   */
  async createSchedule(schedule: Omit<ReportSchedule, 'id' | 'createdAt' | 'updatedAt'>): Promise<ReportSchedule> {
    const id = generateId();
    const now = new Date();

    const result = await database.query(
      `INSERT INTO report_schedules (id, name, report_type, format, parameters, options, cron_expression, timezone, is_active, recipients, next_run, created_by, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
       RETURNING *`,
      [
        id,
        schedule.name,
        schedule.reportType,
        schedule.format,
        JSON.stringify(schedule.parameters),
        JSON.stringify(schedule.options),
        schedule.cronExpression,
        schedule.timezone,
        schedule.isActive,
        schedule.recipients,
        schedule.nextRun,
        schedule.createdBy,
        now,
        now,
      ]
    );

    return this.mapDbRowToSchedule(result.rows[0]);
  }

  /**
   * Delete a report
   */
  async deleteReport(reportId: string): Promise<void> {
    const report = await this.getReport(reportId);

    // Delete file if exists
    if (report.filePath) {
      try {
        await fs.unlink(report.filePath);
      } catch (error) {
        logger.warn(`Failed to delete report file: ${report.filePath}`);
      }
    }

    // Delete from database
    await database.query(`DELETE FROM reports WHERE id = $1`, [reportId]);

    // Remove from cache
    await redis.del(`report:${reportId}`);

    logger.info(`Report deleted: ${reportId}`);
  }

  // Helper methods

  private generateDefaultTitle(type: ReportType): string {
    const date = new Date().toISOString().split('T')[0];
    const typeNames: Record<ReportType, string> = {
      [ReportType.INVESTIGATION_SUMMARY]: 'Investigation Summary',
      [ReportType.TARGET_PROFILE]: 'Target Profile',
      [ReportType.EVIDENCE_CHAIN]: 'Evidence Chain Report',
      [ReportType.INTELLIGENCE_ANALYSIS]: 'Intelligence Analysis',
      [ReportType.OPERATION_AFTER_ACTION]: 'After-Action Report',
      [ReportType.THREAT_ASSESSMENT]: 'Threat Assessment',
      [ReportType.FINANCIAL_ANALYSIS]: 'Financial Analysis',
      [ReportType.NETWORK_MAPPING]: 'Network Mapping Report',
      [ReportType.TIMELINE]: 'Timeline Report',
      [ReportType.EXECUTIVE_BRIEF]: 'Executive Brief',
    };
    return `${typeNames[type]} - ${date}`;
  }

  private generateFilename(reportId: string, type: ReportType, format: ExportFormat): string {
    const timestamp = Date.now();
    const extension = this.getFileExtension(format);
    return `${type}_${reportId}_${timestamp}.${extension}`;
  }

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

  private getRequiredClearance(classification: ClassificationMarking): any {
    const clearanceMap: Record<ClassificationMarking, string> = {
      [ClassificationMarking.TOP_SECRET_SCI]: 'top_secret',
      [ClassificationMarking.TOP_SECRET]: 'top_secret',
      [ClassificationMarking.SECRET]: 'secret',
      [ClassificationMarking.CONFIDENTIAL]: 'confidential',
      [ClassificationMarking.RESTRICTED]: 'restricted',
      [ClassificationMarking.UNCLASSIFIED]: 'unclassified',
      [ClassificationMarking.UNCLASSIFIED_FOUO]: 'unclassified',
    };
    return clearanceMap[classification];
  }

  private estimateGenerationTime(type: ReportType, format: ExportFormat): number {
    // Estimate in milliseconds
    const baseTime: Record<ReportType, number> = {
      [ReportType.INVESTIGATION_SUMMARY]: 5000,
      [ReportType.TARGET_PROFILE]: 3000,
      [ReportType.EVIDENCE_CHAIN]: 4000,
      [ReportType.INTELLIGENCE_ANALYSIS]: 6000,
      [ReportType.OPERATION_AFTER_ACTION]: 5000,
      [ReportType.THREAT_ASSESSMENT]: 4000,
      [ReportType.FINANCIAL_ANALYSIS]: 7000,
      [ReportType.NETWORK_MAPPING]: 8000,
      [ReportType.TIMELINE]: 3000,
      [ReportType.EXECUTIVE_BRIEF]: 2000,
    };
    const formatMultiplier: Record<ExportFormat, number> = {
      [ExportFormat.PDF]: 1.5,
      [ExportFormat.DOCX]: 1.3,
      [ExportFormat.XLSX]: 1.2,
      [ExportFormat.HTML]: 1.0,
      [ExportFormat.JSON]: 0.5,
      [ExportFormat.MARKDOWN]: 0.5,
    };
    return Math.round(baseTime[type] * formatMultiplier[format]);
  }

  private async saveReportMetadata(metadata: ReportMetadata): Promise<void> {
    await database.query(
      `INSERT INTO reports (id, title, type, format, status, classification, clearance_required, created_by, created_at, parameters)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        metadata.id,
        metadata.title,
        metadata.type,
        metadata.format,
        metadata.status,
        metadata.classification,
        metadata.clearanceRequired,
        metadata.createdBy,
        metadata.createdAt,
        JSON.stringify(metadata.parameters),
      ]
    );
  }

  private async updateReportStatus(reportId: string, status: ReportStatus, error?: string): Promise<void> {
    await database.query(
      `UPDATE reports SET status = $1, error = $2, updated_at = NOW() WHERE id = $3`,
      [status, error, reportId]
    );
  }

  private async updateReportMetadata(reportId: string, updates: Partial<ReportMetadata>): Promise<void> {
    const fields: string[] = [];
    const values: any[] = [];
    let idx = 1;

    const fieldMapping: Record<string, string> = {
      status: 'status',
      completedAt: 'completed_at',
      expiresAt: 'expires_at',
      fileSize: 'file_size',
      filePath: 'file_path',
      checksum: 'checksum',
      error: 'error',
    };

    Object.entries(updates).forEach(([key, value]) => {
      if (value !== undefined && fieldMapping[key]) {
        fields.push(`${fieldMapping[key]} = $${idx++}`);
        values.push(value);
      }
    });

    if (fields.length === 0) return;

    values.push(reportId);
    await database.query(
      `UPDATE reports SET ${fields.join(', ')}, updated_at = NOW() WHERE id = $${idx}`,
      values
    );
  }

  private async cacheReportMetadata(reportId: string): Promise<void> {
    try {
      const result = await database.query(`SELECT * FROM reports WHERE id = $1`, [reportId]);
      if (result.rows.length > 0) {
        const metadata = this.mapDbRowToMetadata(result.rows[0]);
        await redis.setex(`report:${reportId}`, 3600, JSON.stringify(metadata)); // 1 hour cache
      }
    } catch (error: any) {
      logger.warn(`Failed to cache report metadata: ${error.message}`);
    }
  }

  private async getCachedReportMetadata(reportId: string): Promise<ReportMetadata | null> {
    try {
      const cached = await redis.get(`report:${reportId}`);
      if (cached) {
        return JSON.parse(cached);
      }
    } catch (error: any) {
      logger.warn(`Failed to get cached report metadata: ${error.message}`);
    }
    return null;
  }

  private mapDbRowToMetadata(row: any): ReportMetadata {
    return {
      id: row.id,
      title: row.title,
      type: row.type,
      format: row.format,
      status: row.status,
      classification: row.classification,
      clearanceRequired: row.clearance_required,
      createdBy: row.created_by,
      createdAt: row.created_at,
      completedAt: row.completed_at,
      expiresAt: row.expires_at,
      fileSize: row.file_size,
      filePath: row.file_path,
      checksum: row.checksum,
      parameters: row.parameters,
      error: row.error,
    };
  }

  private mapDbRowToSchedule(row: any): ReportSchedule {
    return {
      id: row.id,
      name: row.name,
      reportType: row.report_type,
      format: row.format,
      parameters: row.parameters,
      options: row.options,
      cronExpression: row.cron_expression,
      timezone: row.timezone,
      isActive: row.is_active,
      recipients: row.recipients,
      lastRun: row.last_run,
      nextRun: row.next_run,
      createdBy: row.created_by,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}

export const reportService = new ReportService();
