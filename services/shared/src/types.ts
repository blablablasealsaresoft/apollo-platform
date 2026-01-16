// User Roles
export enum UserRole {
  ADMIN = 'admin',
  INVESTIGATOR = 'investigator',
  ANALYST = 'analyst',
  VIEWER = 'viewer',
}

// Clearance Levels
export enum ClearanceLevel {
  TOP_SECRET = 'top_secret',
  SECRET = 'secret',
  CONFIDENTIAL = 'confidential',
  RESTRICTED = 'restricted',
  UNCLASSIFIED = 'unclassified',
}

// User Interface
export interface User {
  id: string;
  email: string;
  username: string;
  firstName: string;
  lastName: string;
  role: UserRole;
  clearanceLevel: ClearanceLevel;
  isActive: boolean;
  isMfaEnabled: boolean;
  lastLogin?: Date;
  createdAt: Date;
  updatedAt: Date;
}

// JWT Payload
export interface JWTPayload {
  userId: string;
  email: string;
  role: UserRole;
  clearanceLevel: ClearanceLevel;
  iat?: number;
  exp?: number;
}

// API Response
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: any;
  };
  timestamp: string;
  requestId?: string;
}

// Pagination
export interface PaginationParams {
  page: number;
  limit: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

// Operation Status
export enum OperationStatus {
  PLANNING = 'planning',
  ACTIVE = 'active',
  ON_HOLD = 'on_hold',
  COMPLETED = 'completed',
  ARCHIVED = 'archived',
}

// Operation Priority
export enum OperationPriority {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
}

// Operation Interface
export interface Operation {
  id: string;
  name: string;
  codename: string;
  description: string;
  status: OperationStatus;
  priority: OperationPriority;
  clearanceLevel: ClearanceLevel;
  leadInvestigatorId: string;
  teamMemberIds: string[];
  startDate: Date;
  endDate?: Date;
  createdAt: Date;
  updatedAt: Date;
}

// Intelligence Source
export enum IntelligenceSource {
  HUMINT = 'humint', // Human Intelligence
  SIGINT = 'sigint', // Signals Intelligence
  OSINT = 'osint',   // Open Source Intelligence
  GEOINT = 'geoint', // Geospatial Intelligence
  FININT = 'finint', // Financial Intelligence
  TECHINT = 'techint', // Technical Intelligence
}

// Intelligence Confidence
export enum ConfidenceLevel {
  VERIFIED = 'verified',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  UNCONFIRMED = 'unconfirmed',
}

// Intelligence Report
export interface IntelligenceReport {
  id: string;
  title: string;
  summary: string;
  content: string;
  source: IntelligenceSource;
  confidence: ConfidenceLevel;
  operationId?: string;
  targetId?: string;
  tags: string[];
  clearanceLevel: ClearanceLevel;
  authorId: string;
  createdAt: Date;
  updatedAt: Date;
}

// Target
export interface Target {
  id: string;
  name: string;
  aliases: string[];
  type: string;
  description: string;
  riskLevel: string;
  status: string;
  operationIds: string[];
  metadata: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
}

// Notification Type
export enum NotificationType {
  ALERT = 'alert',
  INFO = 'info',
  WARNING = 'warning',
  SUCCESS = 'success',
}

// Notification
export interface Notification {
  id: string;
  userId: string;
  type: NotificationType;
  title: string;
  message: string;
  isRead: boolean;
  metadata?: Record<string, any>;
  createdAt: Date;
}

// Activity Log
export interface ActivityLog {
  id: string;
  userId: string;
  action: string;
  resourceType: string;
  resourceId: string;
  metadata?: Record<string, any>;
  ipAddress: string;
  userAgent: string;
  timestamp: Date;
}

// Error Response
export class AppError extends Error {
  statusCode: number;
  isOperational: boolean;
  code: string;

  constructor(message: string, statusCode: number, code: string, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
    this.isOperational = isOperational;
    Error.captureStackTrace(this, this.constructor);
  }
}
