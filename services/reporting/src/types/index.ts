/**
 * Apollo Reporting Service Types
 *
 * Defines all types for report generation, including report types,
 * export formats, templates, and scheduling configurations.
 */

import { ClearanceLevel, Operation, Target, IntelligenceReport, User } from '@apollo/shared';

// ============================================================================
// Report Types
// ============================================================================

export enum ReportType {
  INVESTIGATION_SUMMARY = 'investigation_summary',
  TARGET_PROFILE = 'target_profile',
  EVIDENCE_CHAIN = 'evidence_chain',
  INTELLIGENCE_ANALYSIS = 'intelligence_analysis',
  OPERATION_AFTER_ACTION = 'operation_after_action',
  THREAT_ASSESSMENT = 'threat_assessment',
  FINANCIAL_ANALYSIS = 'financial_analysis',
  NETWORK_MAPPING = 'network_mapping',
  TIMELINE = 'timeline',
  EXECUTIVE_BRIEF = 'executive_brief',
}

export enum ExportFormat {
  PDF = 'pdf',
  DOCX = 'docx',
  XLSX = 'xlsx',
  HTML = 'html',
  JSON = 'json',
  MARKDOWN = 'markdown',
}

export enum ReportStatus {
  QUEUED = 'queued',
  GENERATING = 'generating',
  COMPLETED = 'completed',
  FAILED = 'failed',
  EXPIRED = 'expired',
}

export enum ClassificationMarking {
  TOP_SECRET_SCI = 'TOP SECRET//SCI',
  TOP_SECRET = 'TOP SECRET',
  SECRET = 'SECRET',
  CONFIDENTIAL = 'CONFIDENTIAL',
  RESTRICTED = 'RESTRICTED',
  UNCLASSIFIED = 'UNCLASSIFIED',
  UNCLASSIFIED_FOUO = 'UNCLASSIFIED//FOUO',
}

// ============================================================================
// Report Data Structures
// ============================================================================

export interface ReportMetadata {
  id: string;
  title: string;
  type: ReportType;
  format: ExportFormat;
  status: ReportStatus;
  classification: ClassificationMarking;
  clearanceRequired: ClearanceLevel;
  createdBy: string;
  createdAt: Date;
  completedAt?: Date;
  expiresAt?: Date;
  fileSize?: number;
  filePath?: string;
  checksum?: string;
  parameters: Record<string, any>;
  error?: string;
}

export interface ReportSection {
  id: string;
  title: string;
  content: string;
  order: number;
  pageBreakBefore?: boolean;
  pageBreakAfter?: boolean;
  subsections?: ReportSection[];
}

export interface ReportChart {
  id: string;
  type: 'bar' | 'line' | 'pie' | 'doughnut' | 'radar' | 'scatter' | 'network' | 'timeline';
  title: string;
  data: any;
  options?: Record<string, any>;
  width?: number;
  height?: number;
}

export interface ReportTable {
  id: string;
  title?: string;
  headers: string[];
  rows: (string | number | boolean | null)[][];
  footers?: string[];
  columnWidths?: number[];
  striped?: boolean;
  bordered?: boolean;
}

export interface ReportImage {
  id: string;
  path: string;
  caption?: string;
  width?: number;
  height?: number;
  base64?: string;
  mimeType?: string;
}

// ============================================================================
// Investigation Summary Report
// ============================================================================

export interface InvestigationSummaryData {
  investigationId: string;
  title: string;
  codename?: string;
  status: string;
  priority: string;
  startDate: Date;
  endDate?: Date;
  leadInvestigator: Partial<User>;
  teamMembers: Partial<User>[];
  objectives: string[];
  keyFindings: KeyFinding[];
  evidence: EvidenceItem[];
  targets: Partial<Target>[];
  intelligence: Partial<IntelligenceReport>[];
  timeline: TimelineEvent[];
  recommendations: string[];
  nextSteps: string[];
  riskAssessment?: RiskAssessment;
}

export interface KeyFinding {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: string;
  evidence: string[];
  dateDiscovered: Date;
}

export interface EvidenceItem {
  id: string;
  type: string;
  description: string;
  source: string;
  dateCollected: Date;
  chain_of_custody: string[];
  classification: ClassificationMarking;
  hash?: string;
}

export interface TimelineEvent {
  id: string;
  timestamp: Date;
  title: string;
  description: string;
  type: string;
  actors?: string[];
  location?: string;
  relatedEntities?: string[];
  source?: string;
  confidence?: string;
}

export interface RiskAssessment {
  overallRisk: 'critical' | 'high' | 'medium' | 'low';
  categories: RiskCategory[];
  mitigationMeasures: string[];
}

export interface RiskCategory {
  name: string;
  level: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  factors: string[];
}

// ============================================================================
// Target Profile Report
// ============================================================================

export interface TargetProfileData {
  target: Target;
  personalInfo?: PersonalInfo;
  aliases: AliasRecord[];
  knownLocations: LocationRecord[];
  associates: AssociateRecord[];
  organizations: OrganizationLink[];
  financialProfile?: FinancialProfile;
  digitalFootprint?: DigitalFootprint;
  threatAssessment?: ThreatAssessment;
  operationalHistory: OperationalEvent[];
  intelligence: Partial<IntelligenceReport>[];
  photos: ReportImage[];
}

export interface PersonalInfo {
  fullName: string;
  dateOfBirth?: Date;
  placeOfBirth?: string;
  nationality?: string[];
  gender?: string;
  physicalDescription?: string;
  identificationDocuments?: IdentificationDocument[];
}

export interface IdentificationDocument {
  type: string;
  number: string;
  issuingCountry: string;
  expirationDate?: Date;
  status: 'valid' | 'expired' | 'revoked' | 'unknown';
}

export interface AliasRecord {
  alias: string;
  type: 'name' | 'nickname' | 'online_handle' | 'business_name';
  confidence: string;
  source: string;
  dateFirstSeen?: Date;
  dateLastSeen?: Date;
}

export interface LocationRecord {
  address?: string;
  city: string;
  country: string;
  coordinates?: { lat: number; lng: number };
  type: 'residence' | 'work' | 'frequent' | 'one_time' | 'suspected';
  dateFirstSeen?: Date;
  dateLastSeen?: Date;
  source: string;
  confidence: string;
}

export interface AssociateRecord {
  id: string;
  name: string;
  relationship: string;
  strength: 'strong' | 'moderate' | 'weak';
  direction: 'bidirectional' | 'inbound' | 'outbound';
  dateFirstSeen?: Date;
  dateLastSeen?: Date;
  notes?: string;
}

export interface OrganizationLink {
  organizationName: string;
  role?: string;
  startDate?: Date;
  endDate?: Date;
  isActive: boolean;
  source: string;
}

export interface FinancialProfile {
  estimatedNetWorth?: string;
  knownBankAccounts: BankAccount[];
  cryptoWallets: CryptoWallet[];
  properties: PropertyRecord[];
  companies: CompanyRecord[];
  suspiciousTransactions: SuspiciousTransaction[];
}

export interface BankAccount {
  bank: string;
  country: string;
  accountType?: string;
  status: 'active' | 'closed' | 'frozen' | 'unknown';
  lastActivity?: Date;
}

export interface CryptoWallet {
  blockchain: string;
  address: string;
  balance?: string;
  lastActivity?: Date;
  tags?: string[];
}

export interface PropertyRecord {
  type: string;
  location: string;
  estimatedValue?: string;
  ownershipType: 'direct' | 'through_company' | 'beneficial';
  acquisitionDate?: Date;
}

export interface CompanyRecord {
  name: string;
  jurisdiction: string;
  registrationNumber?: string;
  role: string;
  status: 'active' | 'dissolved' | 'suspended';
  isShellCompany?: boolean;
}

export interface SuspiciousTransaction {
  date: Date;
  amount: string;
  currency: string;
  counterparty?: string;
  type: string;
  riskIndicators: string[];
}

export interface DigitalFootprint {
  domains: string[];
  emailAddresses: string[];
  phoneNumbers: string[];
  socialMediaProfiles: SocialMediaProfile[];
  ipAddresses: IPRecord[];
  devices: DeviceRecord[];
}

export interface SocialMediaProfile {
  platform: string;
  username: string;
  url?: string;
  followers?: number;
  lastActive?: Date;
  verified?: boolean;
}

export interface IPRecord {
  address: string;
  type: 'ipv4' | 'ipv6';
  firstSeen: Date;
  lastSeen: Date;
  geolocation?: { country: string; city?: string };
  isp?: string;
}

export interface DeviceRecord {
  type: string;
  identifier?: string;
  operatingSystem?: string;
  firstSeen: Date;
  lastSeen: Date;
}

export interface ThreatAssessment {
  overallThreatLevel: 'critical' | 'high' | 'medium' | 'low';
  capabilities: string[];
  intentions?: string;
  opportunities?: string[];
  vulnerabilities?: string[];
  projectedActions?: string[];
}

export interface OperationalEvent {
  date: Date;
  type: string;
  description: string;
  outcome?: string;
  relatedEntities?: string[];
}

// ============================================================================
// Evidence Chain Report
// ============================================================================

export interface EvidenceChainData {
  investigationId: string;
  evidence: DetailedEvidence[];
  custodyChain: CustodyRecord[];
  analysisResults: AnalysisResult[];
  integrityVerification: IntegrityRecord[];
}

export interface DetailedEvidence {
  id: string;
  type: string;
  subtype?: string;
  description: string;
  originalSource: string;
  collectionMethod: string;
  collectionDate: Date;
  collectedBy: string;
  classification: ClassificationMarking;
  storageLocation: string;
  hashes: { algorithm: string; value: string }[];
  metadata: Record<string, any>;
  relatedEvidence?: string[];
}

export interface CustodyRecord {
  evidenceId: string;
  timestamp: Date;
  action: 'collected' | 'transferred' | 'analyzed' | 'stored' | 'retrieved' | 'disposed';
  from?: string;
  to: string;
  location: string;
  notes?: string;
  signature?: string;
}

export interface AnalysisResult {
  evidenceId: string;
  analysisType: string;
  analyst: string;
  date: Date;
  findings: string;
  confidence: string;
  methodology?: string;
  tools?: string[];
}

export interface IntegrityRecord {
  evidenceId: string;
  checkDate: Date;
  checkedBy: string;
  algorithm: string;
  expectedHash: string;
  actualHash: string;
  isValid: boolean;
  notes?: string;
}

// ============================================================================
// Intelligence Analysis Report
// ============================================================================

export interface IntelligenceAnalysisData {
  title: string;
  analyst: Partial<User>;
  dateCompleted: Date;
  intelligenceRequirement?: string;
  sources: IntelligenceSource[];
  keyAssessments: Assessment[];
  analyticalConfidence: ConfidenceAssessment;
  gaps: IntelligenceGap[];
  indicators: Indicator[];
  recommendations: string[];
  dissemination: DisseminationRecord;
}

export interface IntelligenceSource {
  id: string;
  type: string;
  reliability: 'A' | 'B' | 'C' | 'D' | 'E' | 'F';
  credibility: '1' | '2' | '3' | '4' | '5' | '6';
  description: string;
  dateObtained: Date;
  classification: ClassificationMarking;
}

export interface Assessment {
  id: string;
  statement: string;
  confidence: 'high' | 'moderate' | 'low';
  supportingEvidence: string[];
  alternativeHypotheses?: string[];
  analystNotes?: string;
}

export interface ConfidenceAssessment {
  overall: 'high' | 'moderate' | 'low';
  factors: {
    sourceReliability: string;
    informationCredibility: string;
    analyticalRigor: string;
    corroboration: string;
  };
  limitations: string[];
}

export interface IntelligenceGap {
  area: string;
  impact: 'high' | 'medium' | 'low';
  recommendedCollection: string;
  priority: number;
}

export interface Indicator {
  id: string;
  type: string;
  value: string;
  context: string;
  confidence: string;
  firstSeen?: Date;
  lastSeen?: Date;
  relatedIndicators?: string[];
}

export interface DisseminationRecord {
  classification: ClassificationMarking;
  releasableTo: string[];
  notReleasableTo?: string[];
  handlingCaveats?: string[];
}

// ============================================================================
// Operation After-Action Report
// ============================================================================

export interface OperationAfterActionData {
  operation: Partial<Operation>;
  missionObjectives: MissionObjective[];
  executionSummary: ExecutionSummary;
  resourceUtilization: ResourceRecord[];
  lessonsLearned: LessonLearned[];
  teamPerformance: TeamPerformanceRecord;
  incidentReports?: IncidentRecord[];
  followUpActions: FollowUpAction[];
}

export interface MissionObjective {
  id: string;
  description: string;
  status: 'achieved' | 'partially_achieved' | 'not_achieved' | 'cancelled';
  outcome: string;
  metrics?: Record<string, any>;
}

export interface ExecutionSummary {
  startDate: Date;
  endDate: Date;
  phases: OperationPhase[];
  majorEvents: TimelineEvent[];
  deviationsFromPlan: string[];
}

export interface OperationPhase {
  name: string;
  startDate: Date;
  endDate: Date;
  status: 'completed' | 'partial' | 'skipped';
  notes?: string;
}

export interface ResourceRecord {
  type: string;
  allocated: number | string;
  utilized: number | string;
  variance?: string;
  notes?: string;
}

export interface LessonLearned {
  category: 'success' | 'improvement' | 'failure';
  title: string;
  description: string;
  recommendation: string;
  priority: 'high' | 'medium' | 'low';
}

export interface TeamPerformanceRecord {
  overallRating: string;
  strengthsObserved: string[];
  areasForImprovement: string[];
  trainingNeeds?: string[];
}

export interface IncidentRecord {
  date: Date;
  type: string;
  description: string;
  impact: string;
  resolution: string;
  preventiveMeasures?: string;
}

export interface FollowUpAction {
  id: string;
  action: string;
  assignedTo: string;
  dueDate: Date;
  priority: 'high' | 'medium' | 'low';
  status: 'pending' | 'in_progress' | 'completed';
}

// ============================================================================
// Report Generation Configuration
// ============================================================================

export interface ReportGenerationOptions {
  format: ExportFormat;
  classification: ClassificationMarking;
  includeTableOfContents?: boolean;
  includePageNumbers?: boolean;
  includeWatermark?: boolean;
  watermarkText?: string;
  headerText?: string;
  footerText?: string;
  pageSize?: 'letter' | 'a4' | 'legal';
  orientation?: 'portrait' | 'landscape';
  margins?: { top: number; right: number; bottom: number; left: number };
  fontSize?: number;
  fontFamily?: string;
  includeCharts?: boolean;
  chartStyle?: 'color' | 'grayscale';
  encryptPdf?: boolean;
  pdfPassword?: string;
  expirationHours?: number;
}

export interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  type: ReportType;
  version: string;
  defaultOptions: Partial<ReportGenerationOptions>;
  sections: TemplateSectionConfig[];
  createdAt: Date;
  updatedAt: Date;
}

export interface TemplateSectionConfig {
  id: string;
  title: string;
  required: boolean;
  order: number;
  dataMapping: string;
  formatters?: string[];
}

// ============================================================================
// Report Scheduling
// ============================================================================

export interface ReportSchedule {
  id: string;
  name: string;
  reportType: ReportType;
  format: ExportFormat;
  parameters: Record<string, any>;
  options: ReportGenerationOptions;
  cronExpression: string;
  timezone: string;
  isActive: boolean;
  recipients: string[];
  lastRun?: Date;
  nextRun: Date;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface ScheduledReportRun {
  id: string;
  scheduleId: string;
  reportId?: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  startedAt?: Date;
  completedAt?: Date;
  error?: string;
  deliveryStatus?: {
    recipient: string;
    status: 'sent' | 'failed';
    sentAt?: Date;
    error?: string;
  }[];
}

// ============================================================================
// Report Generation Request/Response
// ============================================================================

export interface GenerateReportRequest {
  type: ReportType;
  format: ExportFormat;
  title?: string;
  parameters: Record<string, any>;
  options?: Partial<ReportGenerationOptions>;
}

export interface GenerateReportResponse {
  reportId: string;
  status: ReportStatus;
  estimatedCompletionTime?: number;
  queuePosition?: number;
}

export interface ReportDownloadResponse {
  reportId: string;
  filename: string;
  mimeType: string;
  size: number;
  content: Buffer;
  checksum: string;
}
