// Core Types
export interface User {
  id: string;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  role: UserRole;
  avatar?: string;
  department?: string;
  badgeNumber?: string;
  mfaEnabled: boolean;
  lastLogin?: string;
  createdAt: string;
  updatedAt: string;
}

export enum UserRole {
  ADMIN = 'admin',
  INVESTIGATOR = 'investigator',
  ANALYST = 'analyst',
  FIELD_AGENT = 'field_agent',
  VIEWER = 'viewer',
}

export interface AuthState {
  user: User | null;
  token: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  loading: boolean;
  error: string | null;
}

// Investigation Types
export interface Investigation {
  id: string;
  caseNumber: string;
  title: string;
  description: string;
  status: InvestigationStatus;
  priority: Priority;
  classification: Classification;
  leadInvestigator: User;
  teamMembers: User[];
  targets: Target[];
  evidence: Evidence[];
  startDate: string;
  estimatedEndDate?: string;
  actualEndDate?: string;
  budget?: number;
  tags: string[];
  notes: string;
  createdAt: string;
  updatedAt: string;
}

export enum InvestigationStatus {
  PLANNING = 'planning',
  ACTIVE = 'active',
  ON_HOLD = 'on_hold',
  CLOSED = 'closed',
  ARCHIVED = 'archived',
}

export enum Priority {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export enum Classification {
  UNCLASSIFIED = 'unclassified',
  CONFIDENTIAL = 'confidential',
  SECRET = 'secret',
  TOP_SECRET = 'top_secret',
}

// Target Types
export interface Target {
  id: string;
  firstName: string;
  lastName: string;
  aliases: string[];
  dateOfBirth?: string;
  nationality?: string;
  gender?: string;
  photo?: string;
  biometrics?: Biometrics;
  riskLevel: RiskLevel;
  status: TargetStatus;
  knownAddresses: Address[];
  phoneNumbers: string[];
  emailAddresses: string[];
  socialMedia: SocialMediaAccount[];
  knownAssociates: Associate[];
  criminalHistory: CriminalRecord[];
  financialProfile?: FinancialProfile;
  locationHistory: LocationHistory[];
  notes: string;
  investigations: string[];
  createdAt: string;
  updatedAt: string;
}

export interface Biometrics {
  facialRecognition?: FacialRecognitionData;
  fingerprints?: string[];
  dna?: string;
  iris?: string;
  voiceprint?: string;
}

export interface FacialRecognitionData {
  faceId: string;
  encoding: number[];
  quality: number;
  capturedAt: string;
}

export enum RiskLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  EXTREME = 'extreme',
}

export enum TargetStatus {
  ACTIVE = 'active',
  MONITORING = 'monitoring',
  APPREHENDED = 'apprehended',
  CLEARED = 'cleared',
  DECEASED = 'deceased',
}

export interface Address {
  street: string;
  city: string;
  state: string;
  country: string;
  postalCode: string;
  type: 'home' | 'work' | 'other';
  verified: boolean;
}

export interface SocialMediaAccount {
  platform: string;
  username: string;
  url: string;
  verified: boolean;
  lastActive?: string;
}

export interface Associate {
  targetId: string;
  name: string;
  relationship: string;
  confidence: number;
  lastContact?: string;
}

export interface CriminalRecord {
  id: string;
  offense: string;
  date: string;
  jurisdiction: string;
  disposition: string;
  sentence?: string;
}

export interface FinancialProfile {
  estimatedWealth?: number;
  knownAccounts: BankAccount[];
  cryptocurrencyWallets: CryptoWallet[];
  assets: Asset[];
  suspiciousTransactions: Transaction[];
}

export interface BankAccount {
  institution: string;
  accountNumber: string;
  accountType: string;
  balance?: number;
  currency: string;
}

export interface CryptoWallet {
  id: string;
  blockchain: string;
  address: string;
  balance?: number;
  currency: string;
  firstSeen: string;
  lastActive?: string;
  transactionCount: number;
}

export interface Asset {
  type: string;
  description: string;
  estimatedValue?: number;
  location?: string;
}

export interface Transaction {
  id: string;
  date: string;
  amount: number;
  currency: string;
  from: string;
  to: string;
  type: 'bank' | 'crypto' | 'cash';
  flagged: boolean;
  flags: string[];
}

export interface LocationHistory {
  id: string;
  latitude: number;
  longitude: number;
  address?: string;
  timestamp: string;
  source: string;
  accuracy?: number;
}

// Evidence Types
export interface Evidence {
  id: string;
  investigationId: string;
  type: EvidenceType;
  title: string;
  description: string;
  fileUrl?: string;
  fileName?: string;
  fileSize?: number;
  mimeType?: string;
  thumbnailUrl?: string;
  collectedBy: User;
  collectedAt: string;
  location?: string;
  chainOfCustody: ChainOfCustodyEntry[];
  tags: string[];
  metadata: Record<string, any>;
  verified: boolean;
  classification: Classification;
  createdAt: string;
  updatedAt: string;
}

export enum EvidenceType {
  DOCUMENT = 'document',
  PHOTO = 'photo',
  VIDEO = 'video',
  AUDIO = 'audio',
  DIGITAL = 'digital',
  PHYSICAL = 'physical',
  FINANCIAL = 'financial',
  COMMUNICATION = 'communication',
}

export interface ChainOfCustodyEntry {
  id: string;
  userId: string;
  userName: string;
  action: string;
  timestamp: string;
  location: string;
  notes?: string;
}

// Intelligence Types
export interface IntelligenceReport {
  id: string;
  title: string;
  summary: string;
  content: string;
  type: IntelligenceType;
  source: IntelligenceSource;
  confidence: ConfidenceLevel;
  classification: Classification;
  relatedTargets: string[];
  relatedInvestigations: string[];
  correlations: Correlation[];
  author: User;
  verifiedBy?: User;
  tags: string[];
  attachments: string[];
  validFrom: string;
  validUntil?: string;
  createdAt: string;
  updatedAt: string;
}

export enum IntelligenceType {
  HUMINT = 'humint',
  SIGINT = 'sigint',
  OSINT = 'osint',
  FININT = 'finint',
  IMINT = 'imint',
  GEOINT = 'geoint',
}

export interface IntelligenceSource {
  name: string;
  type: string;
  reliability: number;
  verified: boolean;
}

export enum ConfidenceLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CONFIRMED = 'confirmed',
}

export interface Correlation {
  id: string;
  type: string;
  targetId: string;
  confidence: number;
  description: string;
}

// Operations Types
export interface Operation {
  id: string;
  operationName: string;
  codename?: string;
  description: string;
  investigationId: string;
  type: OperationType;
  status: OperationStatus;
  priority: Priority;
  startDate: string;
  endDate?: string;
  location?: OperationLocation;
  teamLead: User;
  teamMembers: User[];
  objectives: string[];
  resources: Resource[];
  reports: FieldReport[];
  timeline: TimelineEvent[];
  riskAssessment: RiskAssessment;
  budget?: number;
  expenditure?: number;
  createdAt: string;
  updatedAt: string;
}

export enum OperationType {
  SURVEILLANCE = 'surveillance',
  RAID = 'raid',
  INTERVIEW = 'interview',
  UNDERCOVER = 'undercover',
  DIGITAL_FORENSICS = 'digital_forensics',
  ASSET_SEIZURE = 'asset_seizure',
}

export enum OperationStatus {
  PLANNING = 'planning',
  APPROVED = 'approved',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
  CANCELLED = 'cancelled',
}

export interface OperationLocation {
  latitude: number;
  longitude: number;
  address: string;
  description?: string;
}

export interface Resource {
  type: string;
  quantity: number;
  description: string;
  assignedTo?: string;
}

export interface FieldReport {
  id: string;
  operationId: string;
  author: User;
  timestamp: string;
  location?: string;
  summary: string;
  details: string;
  attachments: string[];
  classification: Classification;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  event: string;
  description: string;
  author: User;
  importance: 'low' | 'medium' | 'high';
}

export interface RiskAssessment {
  overallRisk: RiskLevel;
  factors: RiskFactor[];
  mitigations: string[];
  assessedBy: User;
  assessedAt: string;
}

export interface RiskFactor {
  factor: string;
  level: RiskLevel;
  description: string;
}

// Alert Types
export interface Alert {
  id: string;
  type: AlertType;
  severity: AlertSeverity;
  title: string;
  message: string;
  source: string;
  relatedEntity?: {
    type: 'investigation' | 'target' | 'operation' | 'evidence';
    id: string;
  };
  actionRequired: boolean;
  assignedTo?: User;
  status: AlertStatus;
  createdAt: string;
  acknowledgedAt?: string;
  resolvedAt?: string;
}

export enum AlertType {
  SECURITY = 'security',
  INTELLIGENCE = 'intelligence',
  OPERATION = 'operation',
  SYSTEM = 'system',
  COMPLIANCE = 'compliance',
  FACIAL_MATCH = 'facial_match',
  TRANSACTION = 'transaction',
}

export enum AlertSeverity {
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical',
}

export enum AlertStatus {
  NEW = 'new',
  ACKNOWLEDGED = 'acknowledged',
  IN_PROGRESS = 'in_progress',
  RESOLVED = 'resolved',
  DISMISSED = 'dismissed',
}

// Dashboard Types
export interface DashboardStats {
  activeInvestigations: number;
  totalTargets: number;
  activeOperations: number;
  evidenceCount: number;
  recentAlerts: number;
  pendingReports: number;
}

export interface ActivityItem {
  id: string;
  type: string;
  title: string;
  description: string;
  user: User;
  timestamp: string;
  icon: string;
}

// Network Graph Types
export interface NetworkNode {
  id: string;
  label: string;
  type: 'target' | 'associate' | 'organization' | 'location' | 'account';
  data: any;
  color?: string;
  size?: number;
}

export interface NetworkEdge {
  id: string;
  from: string;
  to: string;
  label?: string;
  type: string;
  weight?: number;
  color?: string;
}

// Blockchain Types
export interface BlockchainTransaction {
  hash: string;
  blockchain: string;
  from: string;
  to: string;
  value: number;
  currency: string;
  timestamp: string;
  blockNumber: number;
  confirmations: number;
  fee: number;
  flagged: boolean;
  flags: string[];
  relatedTargets?: string[];
}

export interface WalletWatch {
  id: string;
  blockchain: string;
  address: string;
  label: string;
  targetId?: string;
  alertOnTransaction: boolean;
  alertThreshold?: number;
  balance?: number;
  transactionCount: number;
  firstSeen: string;
  lastActive?: string;
  tags: string[];
  createdAt: string;
}

// Facial Recognition Types
export interface FacialMatch {
  id: string;
  sourceImage: string;
  matchedTargetId: string;
  matchedTarget: Target;
  confidence: number;
  timestamp: string;
  location?: string;
  source: string;
  verified: boolean;
  notes?: string;
}

export interface FacialSearchRequest {
  image: File | string;
  threshold?: number;
  maxResults?: number;
}

export interface FacialSearchResult {
  matches: FacialMatch[];
  processedAt: string;
  queryImage: string;
}

// API Types
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
  pagination?: PaginationMeta;
}

export interface PaginationMeta {
  page: number;
  pageSize: number;
  totalPages: number;
  totalItems: number;
}

export interface ApiError {
  message: string;
  code?: string;
  details?: any;
}

// Filter and Search Types
export interface FilterOptions {
  search?: string;
  status?: string[];
  priority?: string[];
  dateFrom?: string;
  dateTo?: string;
  assignedTo?: string[];
  tags?: string[];
}

export interface SortOptions {
  field: string;
  direction: 'asc' | 'desc';
}

export interface PaginationOptions {
  page: number;
  pageSize: number;
}

// Notification Types
export interface Notification {
  id: string;
  type: NotificationType;
  title: string;
  message: string;
  read: boolean;
  actionUrl?: string;
  createdAt: string;
}

export enum NotificationType {
  ALERT = 'alert',
  MESSAGE = 'message',
  SYSTEM = 'system',
  ASSIGNMENT = 'assignment',
}

// Settings Types
export interface UserSettings {
  userId: string;
  notifications: NotificationSettings;
  display: DisplaySettings;
  privacy: PrivacySettings;
}

export interface NotificationSettings {
  emailEnabled: boolean;
  pushEnabled: boolean;
  alertTypes: AlertType[];
  digestFrequency: 'realtime' | 'hourly' | 'daily' | 'weekly';
}

export interface DisplaySettings {
  theme: 'light' | 'dark' | 'auto';
  language: string;
  timezone: string;
  dateFormat: string;
  timeFormat: '12h' | '24h';
}

export interface PrivacySettings {
  profileVisibility: 'public' | 'team' | 'private';
  activityTracking: boolean;
  dataRetention: number;
}

// Audit Log Types
export interface AuditLog {
  id: string;
  userId: string;
  userName: string;
  action: string;
  entityType: string;
  entityId: string;
  changes?: Record<string, any>;
  ipAddress: string;
  userAgent: string;
  timestamp: string;
}

// Export Types
export interface ExportOptions {
  format: 'pdf' | 'excel' | 'csv' | 'json';
  includeAttachments: boolean;
  dateRange?: {
    from: string;
    to: string;
  };
}

// WebSocket Types
export interface WebSocketMessage {
  type: string;
  payload: any;
  timestamp: string;
}

export interface RealtimeUpdate {
  entity: string;
  action: 'create' | 'update' | 'delete';
  data: any;
}
