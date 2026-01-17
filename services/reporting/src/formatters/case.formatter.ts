/**
 * Apollo Case Formatter
 *
 * Formats investigation and case-related data for report generation.
 * Supports:
 * - Investigation summaries
 * - Evidence chains
 * - Intelligence analysis reports
 * - After-action reports
 */

import {
  ReportGenerationOptions,
  ClassificationMarking,
  ReportSection,
  ReportTable,
  ReportChart,
  ReportImage,
  InvestigationSummaryData,
  EvidenceChainData,
  IntelligenceAnalysisData,
  OperationAfterActionData,
  KeyFinding,
  EvidenceItem,
  TimelineEvent,
  DetailedEvidence,
  CustodyRecord,
  AnalysisResult,
  Assessment,
  MissionObjective,
  LessonLearned,
} from '../types';
import { generateId } from '@apollo/shared';

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

export class CaseFormatter {
  /**
   * Format investigation summary data for report generation
   */
  formatInvestigationSummary(
    data: InvestigationSummaryData,
    options: ReportGenerationOptions
  ): FormattedReportData {
    const sections: ReportSection[] = [];
    const tables: ReportTable[] = [];
    const charts: ReportChart[] = [];

    // Executive Summary Section
    sections.push({
      id: generateId(),
      title: 'Executive Summary',
      content: this.generateExecutiveSummary(data),
      order: 1,
      pageBreakAfter: true,
    });

    // Investigation Overview
    sections.push({
      id: generateId(),
      title: 'Investigation Overview',
      content: this.generateInvestigationOverview(data),
      order: 2,
      subsections: [
        {
          id: generateId(),
          title: 'Objectives',
          content: data.objectives.map((obj, i) => `${i + 1}. ${obj}`).join('\n\n'),
          order: 1,
        },
        {
          id: generateId(),
          title: 'Team Composition',
          content: this.formatTeamComposition(data),
          order: 2,
        },
      ],
    });

    // Key Findings Section
    if (data.keyFindings && data.keyFindings.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Key Findings',
        content: 'The following critical findings have been identified during this investigation:',
        order: 3,
        subsections: data.keyFindings.map((finding, index) =>
          this.formatKeyFinding(finding, index)
        ),
        pageBreakBefore: true,
      });

      // Key findings table
      tables.push({
        id: generateId(),
        title: 'Key Findings Summary',
        headers: ['#', 'Finding', 'Severity', 'Confidence', 'Date Discovered'],
        rows: data.keyFindings.map((f, i) => [
          (i + 1).toString(),
          f.title,
          f.severity.toUpperCase(),
          f.confidence,
          this.formatDate(f.dateDiscovered),
        ]),
        striped: true,
        bordered: true,
      });

      // Severity distribution chart
      const severityCounts = this.countBySeverity(data.keyFindings);
      charts.push({
        id: generateId(),
        type: 'pie',
        title: 'Findings by Severity',
        data: {
          labels: Object.keys(severityCounts),
          values: Object.values(severityCounts),
        },
      });
    }

    // Evidence Section
    if (data.evidence && data.evidence.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Evidence Collected',
        content: `A total of ${data.evidence.length} pieces of evidence have been collected and processed during this investigation.`,
        order: 4,
        pageBreakBefore: true,
      });

      tables.push({
        id: generateId(),
        title: 'Evidence Inventory',
        headers: ['ID', 'Type', 'Description', 'Source', 'Date Collected', 'Classification'],
        rows: data.evidence.map((e) => [
          e.id.substring(0, 8),
          e.type,
          e.description.substring(0, 50) + (e.description.length > 50 ? '...' : ''),
          e.source,
          this.formatDate(e.dateCollected),
          e.classification,
        ]),
        striped: true,
        bordered: true,
      });

      // Evidence type distribution
      const typeCounts = this.countByField(data.evidence, 'type');
      charts.push({
        id: generateId(),
        type: 'bar',
        title: 'Evidence by Type',
        data: {
          labels: Object.keys(typeCounts),
          values: Object.values(typeCounts),
        },
      });
    }

    // Targets Section
    if (data.targets && data.targets.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Subjects of Investigation',
        content: `This investigation involves ${data.targets.length} subject(s) of interest.`,
        order: 5,
        subsections: data.targets.map((target, index) => ({
          id: generateId(),
          title: `Subject ${index + 1}: ${target.name || 'Unknown'}`,
          content: this.formatTargetSummary(target),
          order: index + 1,
        })),
        pageBreakBefore: true,
      });
    }

    // Intelligence Section
    if (data.intelligence && data.intelligence.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Intelligence Products',
        content: `${data.intelligence.length} intelligence report(s) have been produced during this investigation.`,
        order: 6,
        pageBreakBefore: true,
      });

      tables.push({
        id: generateId(),
        title: 'Intelligence Reports',
        headers: ['Report ID', 'Title', 'Classification', 'Date'],
        rows: data.intelligence.map((intel: any) => [
          intel.id?.substring(0, 8) || 'N/A',
          intel.title || 'Untitled',
          intel.classification || options.classification,
          this.formatDate(intel.created_at || new Date()),
        ]),
        striped: true,
        bordered: true,
      });
    }

    // Timeline Section
    if (data.timeline && data.timeline.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Investigation Timeline',
        content: this.formatTimelineNarrative(data.timeline),
        order: 7,
        pageBreakBefore: true,
      });

      charts.push({
        id: generateId(),
        type: 'timeline',
        title: 'Key Events Timeline',
        data: {
          events: data.timeline.slice(0, 20).map((event) => ({
            date: this.formatDate(event.timestamp),
            title: event.title,
            description: event.description,
          })),
        },
      });
    }

    // Risk Assessment Section
    if (data.riskAssessment) {
      sections.push({
        id: generateId(),
        title: 'Risk Assessment',
        content: this.formatRiskAssessment(data.riskAssessment),
        order: 8,
        pageBreakBefore: true,
      });
    }

    // Recommendations Section
    if (data.recommendations && data.recommendations.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Recommendations',
        content: data.recommendations.map((rec, i) => `${i + 1}. ${rec}`).join('\n\n'),
        order: 9,
      });
    }

    // Next Steps Section
    if (data.nextSteps && data.nextSteps.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Next Steps',
        content: data.nextSteps.map((step, i) => `${i + 1}. ${step}`).join('\n\n'),
        order: 10,
      });
    }

    return {
      title: data.title,
      subtitle: data.codename ? `Codename: ${data.codename}` : undefined,
      classification: options.classification,
      generatedDate: new Date(),
      author: data.leadInvestigator?.email || 'Apollo System',
      sections,
      tables,
      charts,
      footer: `Investigation ID: ${data.investigationId}`,
      metadata: {
        reportId: generateId(),
        investigationId: data.investigationId,
        type: 'investigation_summary',
      },
    };
  }

  /**
   * Format evidence chain data for report generation
   */
  formatEvidenceChain(
    data: EvidenceChainData,
    options: ReportGenerationOptions
  ): FormattedReportData {
    const sections: ReportSection[] = [];
    const tables: ReportTable[] = [];

    // Introduction
    sections.push({
      id: generateId(),
      title: 'Evidence Chain of Custody Report',
      content: `This report documents the chain of custody for ${data.evidence.length} piece(s) of evidence associated with investigation ${data.investigationId}. All evidence handling has been tracked to ensure integrity and admissibility.`,
      order: 1,
    });

    // Evidence Inventory
    sections.push({
      id: generateId(),
      title: 'Evidence Inventory',
      content: 'The following evidence items are documented in this report:',
      order: 2,
      pageBreakBefore: true,
    });

    tables.push({
      id: generateId(),
      title: 'Evidence Items',
      headers: ['Evidence ID', 'Type', 'Description', 'Collection Date', 'Classification', 'Storage'],
      rows: data.evidence.map((e) => [
        e.id.substring(0, 8),
        e.type,
        e.description.substring(0, 40) + '...',
        this.formatDate(e.collectionDate),
        e.classification,
        e.storageLocation,
      ]),
      striped: true,
      bordered: true,
    });

    // Detailed Evidence Sections
    data.evidence.forEach((evidence, index) => {
      const custodyRecords = data.custodyChain.filter((c) => c.evidenceId === evidence.id);
      const analysisRecords = data.analysisResults.filter((a) => a.evidenceId === evidence.id);
      const integrityRecords = data.integrityVerification.filter((i) => i.evidenceId === evidence.id);

      sections.push({
        id: generateId(),
        title: `Evidence ${index + 1}: ${evidence.id.substring(0, 8)}`,
        content: this.formatDetailedEvidence(evidence),
        order: index + 3,
        pageBreakBefore: true,
        subsections: [
          {
            id: generateId(),
            title: 'Collection Details',
            content: `Collected by: ${evidence.collectedBy}\nCollection Method: ${evidence.collectionMethod}\nOriginal Source: ${evidence.originalSource}\nCollection Date: ${this.formatDate(evidence.collectionDate)}`,
            order: 1,
          },
          {
            id: generateId(),
            title: 'Hash Values',
            content: evidence.hashes.map((h) => `${h.algorithm}: ${h.value}`).join('\n'),
            order: 2,
          },
        ],
      });

      // Custody chain table for this evidence
      if (custodyRecords.length > 0) {
        tables.push({
          id: generateId(),
          title: `Chain of Custody - ${evidence.id.substring(0, 8)}`,
          headers: ['Date/Time', 'Action', 'From', 'To', 'Location', 'Notes'],
          rows: custodyRecords.map((c) => [
            this.formatDateTime(c.timestamp),
            c.action.toUpperCase(),
            c.from || 'N/A',
            c.to,
            c.location,
            c.notes || '',
          ]),
          striped: true,
          bordered: true,
        });
      }

      // Analysis results for this evidence
      if (analysisRecords.length > 0) {
        tables.push({
          id: generateId(),
          title: `Analysis Results - ${evidence.id.substring(0, 8)}`,
          headers: ['Date', 'Type', 'Analyst', 'Findings', 'Confidence'],
          rows: analysisRecords.map((a) => [
            this.formatDate(a.date),
            a.analysisType,
            a.analyst,
            a.findings.substring(0, 50) + '...',
            a.confidence,
          ]),
          striped: true,
          bordered: true,
        });
      }
    });

    // Integrity Verification Summary
    const allValid = data.integrityVerification.every((i) => i.isValid);
    sections.push({
      id: generateId(),
      title: 'Integrity Verification Summary',
      content: allValid
        ? 'All evidence items have passed integrity verification. Hash values match expected values, confirming that evidence has not been tampered with.'
        : 'WARNING: Some evidence items have failed integrity verification. Review the detailed records below for affected items.',
      order: data.evidence.length + 3,
    });

    tables.push({
      id: generateId(),
      title: 'Integrity Check Results',
      headers: ['Evidence ID', 'Check Date', 'Algorithm', 'Status', 'Verified By'],
      rows: data.integrityVerification.map((i) => [
        i.evidenceId.substring(0, 8),
        this.formatDate(i.checkDate),
        i.algorithm,
        i.isValid ? 'VALID' : 'FAILED',
        i.checkedBy,
      ]),
      striped: true,
      bordered: true,
    });

    return {
      title: 'Evidence Chain of Custody Report',
      subtitle: `Investigation: ${data.investigationId}`,
      classification: options.classification,
      generatedDate: new Date(),
      sections,
      tables,
      footer: `Evidence count: ${data.evidence.length} | Custody records: ${data.custodyChain.length}`,
      metadata: {
        reportId: generateId(),
        investigationId: data.investigationId,
        type: 'evidence_chain',
      },
    };
  }

  /**
   * Format intelligence analysis data for report generation
   */
  formatIntelligenceAnalysis(
    data: IntelligenceAnalysisData,
    options: ReportGenerationOptions
  ): FormattedReportData {
    const sections: ReportSection[] = [];
    const tables: ReportTable[] = [];
    const charts: ReportChart[] = [];

    // Title Page Content
    sections.push({
      id: generateId(),
      title: 'Intelligence Analysis Summary',
      content: `Analyst: ${data.analyst?.firstName || ''} ${data.analyst?.lastName || data.analyst?.email || 'Unknown'}\nDate Completed: ${this.formatDate(data.dateCompleted)}\n\n${data.intelligenceRequirement ? `Intelligence Requirement: ${data.intelligenceRequirement}` : ''}`,
      order: 1,
    });

    // Key Assessments Section
    if (data.keyAssessments && data.keyAssessments.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Key Assessments',
        content: 'The following key assessments have been made based on available intelligence:',
        order: 2,
        pageBreakBefore: true,
        subsections: data.keyAssessments.map((assessment, index) =>
          this.formatAssessment(assessment, index)
        ),
      });

      tables.push({
        id: generateId(),
        title: 'Assessment Summary',
        headers: ['#', 'Assessment', 'Confidence', 'Supporting Evidence'],
        rows: data.keyAssessments.map((a, i) => [
          (i + 1).toString(),
          a.statement.substring(0, 60) + '...',
          a.confidence.toUpperCase(),
          a.supportingEvidence.length.toString(),
        ]),
        striped: true,
        bordered: true,
      });
    }

    // Source Reliability Section
    if (data.sources && data.sources.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Source Analysis',
        content: `This analysis is based on ${data.sources.length} intelligence source(s).`,
        order: 3,
        pageBreakBefore: true,
      });

      tables.push({
        id: generateId(),
        title: 'Source Reliability Matrix',
        headers: ['Source ID', 'Type', 'Reliability', 'Credibility', 'Date Obtained', 'Classification'],
        rows: data.sources.map((s) => [
          s.id.substring(0, 8),
          s.type,
          s.reliability,
          s.credibility,
          this.formatDate(s.dateObtained),
          s.classification,
        ]),
        striped: true,
        bordered: true,
      });

      // Reliability distribution chart
      const reliabilityCounts = this.countByField(data.sources, 'reliability');
      charts.push({
        id: generateId(),
        type: 'bar',
        title: 'Source Reliability Distribution',
        data: {
          labels: Object.keys(reliabilityCounts).sort(),
          values: Object.keys(reliabilityCounts).sort().map((k) => reliabilityCounts[k]),
        },
      });
    }

    // Analytical Confidence Section
    sections.push({
      id: generateId(),
      title: 'Analytical Confidence Assessment',
      content: this.formatConfidenceAssessment(data.analyticalConfidence),
      order: 4,
    });

    // Indicators Section
    if (data.indicators && data.indicators.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Indicators',
        content: `${data.indicators.length} indicator(s) have been identified:`,
        order: 5,
        pageBreakBefore: true,
      });

      tables.push({
        id: generateId(),
        title: 'Indicators of Interest',
        headers: ['Type', 'Value', 'Context', 'Confidence', 'First Seen', 'Last Seen'],
        rows: data.indicators.map((ind) => [
          ind.type,
          ind.value.substring(0, 30) + (ind.value.length > 30 ? '...' : ''),
          ind.context.substring(0, 30) + '...',
          ind.confidence,
          ind.firstSeen ? this.formatDate(ind.firstSeen) : 'N/A',
          ind.lastSeen ? this.formatDate(ind.lastSeen) : 'N/A',
        ]),
        striped: true,
        bordered: true,
      });
    }

    // Intelligence Gaps Section
    if (data.gaps && data.gaps.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Intelligence Gaps',
        content: 'The following intelligence gaps have been identified:',
        order: 6,
        subsections: data.gaps.map((gap, index) => ({
          id: generateId(),
          title: `Gap ${index + 1}: ${gap.area}`,
          content: `Impact: ${gap.impact.toUpperCase()}\nPriority: ${gap.priority}\nRecommended Collection: ${gap.recommendedCollection}`,
          order: index + 1,
        })),
      });
    }

    // Recommendations Section
    if (data.recommendations && data.recommendations.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Recommendations',
        content: data.recommendations.map((rec, i) => `${i + 1}. ${rec}`).join('\n\n'),
        order: 7,
      });
    }

    // Dissemination Information
    sections.push({
      id: generateId(),
      title: 'Dissemination',
      content: this.formatDisseminationInfo(data.dissemination),
      order: 8,
    });

    return {
      title: data.title,
      subtitle: 'Intelligence Analysis Report',
      classification: options.classification,
      generatedDate: new Date(),
      author: data.analyst?.email,
      sections,
      tables,
      charts,
      metadata: {
        reportId: generateId(),
        type: 'intelligence_analysis',
        analyticalConfidence: data.analyticalConfidence.overall,
      },
    };
  }

  /**
   * Format operation after-action report data
   */
  formatAfterActionReport(
    data: OperationAfterActionData,
    options: ReportGenerationOptions
  ): FormattedReportData {
    const sections: ReportSection[] = [];
    const tables: ReportTable[] = [];
    const charts: ReportChart[] = [];

    // Operation Overview
    sections.push({
      id: generateId(),
      title: 'Operation Overview',
      content: this.formatOperationOverview(data.operation),
      order: 1,
    });

    // Mission Objectives
    if (data.missionObjectives && data.missionObjectives.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Mission Objectives',
        content: 'The following objectives were established for this operation:',
        order: 2,
        pageBreakBefore: true,
      });

      tables.push({
        id: generateId(),
        title: 'Objectives Status',
        headers: ['#', 'Objective', 'Status', 'Outcome'],
        rows: data.missionObjectives.map((obj, i) => [
          (i + 1).toString(),
          obj.description.substring(0, 50) + '...',
          obj.status.toUpperCase().replace('_', ' '),
          obj.outcome.substring(0, 40) + '...',
        ]),
        striped: true,
        bordered: true,
      });

      // Objectives achievement chart
      const statusCounts = this.countByField(data.missionObjectives, 'status');
      charts.push({
        id: generateId(),
        type: 'pie',
        title: 'Objective Achievement Rate',
        data: {
          labels: Object.keys(statusCounts).map((s) => s.replace('_', ' ').toUpperCase()),
          values: Object.values(statusCounts),
        },
      });
    }

    // Execution Summary
    sections.push({
      id: generateId(),
      title: 'Execution Summary',
      content: this.formatExecutionSummary(data.executionSummary),
      order: 3,
      pageBreakBefore: true,
      subsections: [
        {
          id: generateId(),
          title: 'Operation Phases',
          content: data.executionSummary.phases
            .map(
              (p) =>
                `${p.name}\nStart: ${this.formatDate(p.startDate)}\nEnd: ${this.formatDate(p.endDate)}\nStatus: ${p.status}\n${p.notes ? `Notes: ${p.notes}` : ''}`
            )
            .join('\n\n'),
          order: 1,
        },
        {
          id: generateId(),
          title: 'Deviations from Plan',
          content:
            data.executionSummary.deviationsFromPlan.length > 0
              ? data.executionSummary.deviationsFromPlan.map((d, i) => `${i + 1}. ${d}`).join('\n')
              : 'No significant deviations from the operational plan were recorded.',
          order: 2,
        },
      ],
    });

    // Resource Utilization
    if (data.resourceUtilization && data.resourceUtilization.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Resource Utilization',
        content: 'The following resources were allocated and utilized during the operation:',
        order: 4,
      });

      tables.push({
        id: generateId(),
        title: 'Resource Allocation',
        headers: ['Resource Type', 'Allocated', 'Utilized', 'Variance', 'Notes'],
        rows: data.resourceUtilization.map((r) => [
          r.type,
          String(r.allocated),
          String(r.utilized),
          r.variance || 'N/A',
          r.notes || '',
        ]),
        striped: true,
        bordered: true,
      });
    }

    // Team Performance
    sections.push({
      id: generateId(),
      title: 'Team Performance Assessment',
      content: this.formatTeamPerformance(data.teamPerformance),
      order: 5,
    });

    // Lessons Learned
    if (data.lessonsLearned && data.lessonsLearned.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Lessons Learned',
        content: 'The following lessons have been identified for future operations:',
        order: 6,
        pageBreakBefore: true,
        subsections: data.lessonsLearned.map((lesson, index) =>
          this.formatLessonLearned(lesson, index)
        ),
      });

      tables.push({
        id: generateId(),
        title: 'Lessons Summary',
        headers: ['Category', 'Title', 'Priority', 'Recommendation'],
        rows: data.lessonsLearned.map((l) => [
          l.category.toUpperCase(),
          l.title,
          l.priority.toUpperCase(),
          l.recommendation.substring(0, 40) + '...',
        ]),
        striped: true,
        bordered: true,
      });
    }

    // Incident Reports
    if (data.incidentReports && data.incidentReports.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Incident Reports',
        content: `${data.incidentReports.length} incident(s) were recorded during this operation:`,
        order: 7,
        pageBreakBefore: true,
      });

      tables.push({
        id: generateId(),
        title: 'Incidents',
        headers: ['Date', 'Type', 'Description', 'Impact', 'Resolution'],
        rows: data.incidentReports.map((inc) => [
          this.formatDate(inc.date),
          inc.type,
          inc.description.substring(0, 30) + '...',
          inc.impact,
          inc.resolution.substring(0, 30) + '...',
        ]),
        striped: true,
        bordered: true,
      });
    }

    // Follow-up Actions
    if (data.followUpActions && data.followUpActions.length > 0) {
      sections.push({
        id: generateId(),
        title: 'Follow-up Actions',
        content: 'The following actions are required following this operation:',
        order: 8,
      });

      tables.push({
        id: generateId(),
        title: 'Action Items',
        headers: ['ID', 'Action', 'Assigned To', 'Due Date', 'Priority', 'Status'],
        rows: data.followUpActions.map((action) => [
          action.id.substring(0, 8),
          action.action.substring(0, 40) + '...',
          action.assignedTo,
          this.formatDate(action.dueDate),
          action.priority.toUpperCase(),
          action.status.toUpperCase().replace('_', ' '),
        ]),
        striped: true,
        bordered: true,
      });
    }

    return {
      title: `After-Action Report: ${data.operation.name || 'Operation'}`,
      subtitle: data.operation.codename ? `Codename: ${data.operation.codename}` : undefined,
      classification: options.classification,
      generatedDate: new Date(),
      sections,
      tables,
      charts,
      footer: `Operation ID: ${data.operation.id}`,
      metadata: {
        reportId: generateId(),
        operationId: data.operation.id,
        type: 'operation_after_action',
      },
    };
  }

  // Helper methods

  private generateExecutiveSummary(data: InvestigationSummaryData): string {
    const findingsSummary =
      data.keyFindings.length > 0
        ? `${data.keyFindings.length} key findings have been identified, including ${
            data.keyFindings.filter((f) => f.severity === 'critical').length
          } critical findings.`
        : 'Investigation is ongoing with no critical findings to date.';

    return `This report summarizes the investigation "${data.title}" (Status: ${data.status}, Priority: ${data.priority}).

Investigation Period: ${this.formatDate(data.startDate)} - ${data.endDate ? this.formatDate(data.endDate) : 'Ongoing'}

Lead Investigator: ${data.leadInvestigator?.firstName || ''} ${data.leadInvestigator?.lastName || data.leadInvestigator?.email || 'Not Assigned'}
Team Size: ${data.teamMembers?.length || 0} member(s)

${findingsSummary}

Evidence Collected: ${data.evidence?.length || 0} item(s)
Subjects of Interest: ${data.targets?.length || 0}
Intelligence Reports: ${data.intelligence?.length || 0}`;
  }

  private generateInvestigationOverview(data: InvestigationSummaryData): string {
    return `Investigation Name: ${data.title}
${data.codename ? `Codename: ${data.codename}` : ''}
Status: ${data.status}
Priority: ${data.priority}
Start Date: ${this.formatDate(data.startDate)}
${data.endDate ? `End Date: ${this.formatDate(data.endDate)}` : 'Status: Active'}`;
  }

  private formatTeamComposition(data: InvestigationSummaryData): string {
    const lead = data.leadInvestigator;
    const members = data.teamMembers || [];

    let content = `Lead Investigator: ${lead?.firstName || ''} ${lead?.lastName || lead?.email || 'Not Assigned'} (${lead?.role || 'N/A'})\n\nTeam Members:`;

    if (members.length === 0) {
      content += '\nNo additional team members assigned.';
    } else {
      members.forEach((member, i) => {
        content += `\n${i + 1}. ${member.firstName || ''} ${member.lastName || member.email || 'Unknown'} - ${member.role || 'Team Member'}`;
      });
    }

    return content;
  }

  private formatKeyFinding(finding: KeyFinding, index: number): ReportSection {
    return {
      id: generateId(),
      title: `Finding ${index + 1}: ${finding.title}`,
      content: `Severity: ${finding.severity.toUpperCase()}
Confidence: ${finding.confidence}
Date Discovered: ${this.formatDate(finding.dateDiscovered)}

${finding.description}

Supporting Evidence: ${finding.evidence.length > 0 ? finding.evidence.join(', ') : 'None specified'}`,
      order: index + 1,
    };
  }

  private formatTargetSummary(target: any): string {
    return `Name: ${target.name || 'Unknown'}
Status: ${target.status || 'Active'}
Type: ${target.type || 'Person'}
Risk Level: ${target.risk_level || 'Unknown'}
${target.description ? `\nDescription: ${target.description}` : ''}`;
  }

  private formatTimelineNarrative(events: TimelineEvent[]): string {
    if (events.length === 0) {
      return 'No timeline events recorded.';
    }

    const sortedEvents = [...events].sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    let narrative = `The investigation timeline spans from ${this.formatDate(sortedEvents[0].timestamp)} to ${this.formatDate(sortedEvents[sortedEvents.length - 1].timestamp)}.\n\n`;

    sortedEvents.slice(0, 10).forEach((event) => {
      narrative += `${this.formatDateTime(event.timestamp)} - ${event.title}\n${event.description}\n\n`;
    });

    if (events.length > 10) {
      narrative += `... and ${events.length - 10} additional events.`;
    }

    return narrative;
  }

  private formatRiskAssessment(risk: any): string {
    let content = `Overall Risk Level: ${risk.overallRisk.toUpperCase()}\n\n`;

    if (risk.categories && risk.categories.length > 0) {
      content += 'Risk Categories:\n';
      risk.categories.forEach((cat: any) => {
        content += `\n${cat.name} (${cat.level.toUpperCase()})\n${cat.description}\nFactors: ${cat.factors.join(', ')}\n`;
      });
    }

    if (risk.mitigationMeasures && risk.mitigationMeasures.length > 0) {
      content += '\nMitigation Measures:\n';
      risk.mitigationMeasures.forEach((measure: string, i: number) => {
        content += `${i + 1}. ${measure}\n`;
      });
    }

    return content;
  }

  private formatDetailedEvidence(evidence: DetailedEvidence): string {
    return `Type: ${evidence.type}${evidence.subtype ? ` (${evidence.subtype})` : ''}
Description: ${evidence.description}
Classification: ${evidence.classification}

Collection Details:
- Method: ${evidence.collectionMethod}
- Source: ${evidence.originalSource}
- Collected By: ${evidence.collectedBy}
- Date: ${this.formatDate(evidence.collectionDate)}

Storage: ${evidence.storageLocation}`;
  }

  private formatAssessment(assessment: Assessment, index: number): ReportSection {
    let content = `Confidence: ${assessment.confidence.toUpperCase()}\n\n${assessment.statement}`;

    if (assessment.supportingEvidence && assessment.supportingEvidence.length > 0) {
      content += `\n\nSupporting Evidence:\n${assessment.supportingEvidence.map((e, i) => `${i + 1}. ${e}`).join('\n')}`;
    }

    if (assessment.alternativeHypotheses && assessment.alternativeHypotheses.length > 0) {
      content += `\n\nAlternative Hypotheses:\n${assessment.alternativeHypotheses.map((h, i) => `${i + 1}. ${h}`).join('\n')}`;
    }

    if (assessment.analystNotes) {
      content += `\n\nAnalyst Notes: ${assessment.analystNotes}`;
    }

    return {
      id: generateId(),
      title: `Assessment ${index + 1}`,
      content,
      order: index + 1,
    };
  }

  private formatConfidenceAssessment(confidence: any): string {
    return `Overall Confidence: ${confidence.overall.toUpperCase()}

Contributing Factors:
- Source Reliability: ${confidence.factors.sourceReliability}
- Information Credibility: ${confidence.factors.informationCredibility}
- Analytical Rigor: ${confidence.factors.analyticalRigor}
- Corroboration: ${confidence.factors.corroboration}

${confidence.limitations && confidence.limitations.length > 0 ? `Limitations:\n${confidence.limitations.map((l: string, i: number) => `${i + 1}. ${l}`).join('\n')}` : ''}`;
  }

  private formatDisseminationInfo(dissemination: any): string {
    let content = `Classification: ${dissemination.classification}\n`;

    if (dissemination.releasableTo && dissemination.releasableTo.length > 0) {
      content += `\nReleasable To: ${dissemination.releasableTo.join(', ')}`;
    }

    if (dissemination.notReleasableTo && dissemination.notReleasableTo.length > 0) {
      content += `\nNot Releasable To: ${dissemination.notReleasableTo.join(', ')}`;
    }

    if (dissemination.handlingCaveats && dissemination.handlingCaveats.length > 0) {
      content += `\n\nHandling Caveats:\n${dissemination.handlingCaveats.map((c: string, i: number) => `${i + 1}. ${c}`).join('\n')}`;
    }

    return content;
  }

  private formatOperationOverview(operation: any): string {
    return `Operation Name: ${operation.name || 'Unknown'}
${operation.codename ? `Codename: ${operation.codename}` : ''}
Status: ${operation.status || 'Unknown'}
Priority: ${operation.priority || 'Normal'}
Clearance Required: ${operation.clearanceLevel || 'Not Specified'}

Period: ${this.formatDate(operation.startDate)} - ${operation.endDate ? this.formatDate(operation.endDate) : 'Ongoing'}

${operation.description ? `Description:\n${operation.description}` : ''}`;
  }

  private formatExecutionSummary(summary: any): string {
    return `Operation Duration: ${this.formatDate(summary.startDate)} to ${this.formatDate(summary.endDate)}

Total Phases: ${summary.phases?.length || 0}
Major Events Recorded: ${summary.majorEvents?.length || 0}
Plan Deviations: ${summary.deviationsFromPlan?.length || 0}`;
  }

  private formatTeamPerformance(performance: any): string {
    let content = `Overall Rating: ${performance.overallRating}\n\n`;

    if (performance.strengthsObserved && performance.strengthsObserved.length > 0) {
      content += `Strengths Observed:\n${performance.strengthsObserved.map((s: string, i: number) => `${i + 1}. ${s}`).join('\n')}\n\n`;
    }

    if (performance.areasForImprovement && performance.areasForImprovement.length > 0) {
      content += `Areas for Improvement:\n${performance.areasForImprovement.map((a: string, i: number) => `${i + 1}. ${a}`).join('\n')}\n\n`;
    }

    if (performance.trainingNeeds && performance.trainingNeeds.length > 0) {
      content += `Training Needs Identified:\n${performance.trainingNeeds.map((t: string, i: number) => `${i + 1}. ${t}`).join('\n')}`;
    }

    return content;
  }

  private formatLessonLearned(lesson: LessonLearned, index: number): ReportSection {
    return {
      id: generateId(),
      title: `${lesson.category.toUpperCase()}: ${lesson.title}`,
      content: `Priority: ${lesson.priority.toUpperCase()}\n\n${lesson.description}\n\nRecommendation: ${lesson.recommendation}`,
      order: index + 1,
    };
  }

  private countBySeverity(findings: KeyFinding[]): Record<string, number> {
    return findings.reduce(
      (acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );
  }

  private countByField(items: any[], field: string): Record<string, number> {
    return items.reduce(
      (acc, item) => {
        const value = item[field];
        acc[value] = (acc[value] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );
  }

  private formatDate(date: Date | string): string {
    return new Date(date).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  }

  private formatDateTime(date: Date | string): string {
    return new Date(date).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  }
}

export const caseFormatter = new CaseFormatter();
