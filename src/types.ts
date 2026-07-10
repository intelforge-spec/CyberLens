/**
 * CyberLens Shared Type Definitions
 */

export type IOCType = 'IP' | 'DOMAIN' | 'URL' | 'HASH';

export interface ThreatIntelligence {
  // Common fields
  abuseScore?: number; // 0-100
  country?: string;
  countryCode?: string;
  asn?: string;
  organization?: string;
  otxPulseCount?: number;
  reputation?: 'Clean' | 'Suspicious' | 'Malicious' | 'Unknown' | 'Conflicting Intelligence Sources';
  confidence?: 'Low' | 'Medium' | 'High' | string;
  reason?: string;
  conflictingSources?: string[];
  
  // Domain specific
  domainAge?: string;
  dnsInfo?: {
    a?: string[];
    mx?: string[];
    txt?: string[];
    ns?: string[];
  };

  // URL specific
  urlhausDetection?: boolean;
  urlscanResult?: {
    screenshot?: string;
    server?: string;
    mimeType?: string;
    effectiveUrl?: string;
  };
  redirectCount?: number;

  // Hash specific
  malwareBazaarMatch?: boolean;
  malwareFamily?: string;
}

export type RiskSeverity = 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';

export interface ScoreExplanation {
  severity: RiskSeverity;
  score: number;
  reasons: string[];
}

export interface AISummary {
  investigationSummary: string;
  threatAssessment: string;
  recommendedActions: string[];
}

export interface InvestigationRecord {
  id: string; // Dynamic ID
  ioc: string;
  type: IOCType;
  timestamp: string;
  threatIntel: ThreatIntelligence;
  riskScore: number;
  severity: RiskSeverity;
  reasons: string[];
  aiSummary: AISummary;
}

// Email Parser Interfaces
export interface EmailHeaderInfo {
  from: string;
  replyTo: string;
  returnPath: string;
  receivedChain: string[];
}

export interface EmailAuthValidation {
  spf: { status: 'PASS' | 'FAIL' | 'NONE'; details: string };
  dkim: { status: 'PASS' | 'FAIL' | 'NONE'; details: string };
  dmarc: { status: 'PASS' | 'FAIL' | 'NONE'; details: string };
}

export interface EmailUrlExtraction {
  url: string;
  urlhausHit: boolean;
  urlscanStatus: 'Clean' | 'Malicious' | 'Pending';
  otxPulses: number;
}

export interface EmailAttachmentExtraction {
  filename: string;
  size: string;
  md5: string;
  sha1: string;
  sha256: string;
  malwareBazaarMatch: boolean;
  malwareFamily?: string;
  otxPulses: number;
}

export interface EmailAnalysisRecord {
  id: string;
  filename: string;
  subject: string;
  timestamp: string;
  headers: EmailHeaderInfo;
  auth: EmailAuthValidation;
  urls: EmailUrlExtraction[];
  attachments: EmailAttachmentExtraction[];
  riskScore: number;
  severity: RiskSeverity;
  reasons: string[];
  aiSummary: AISummary;
}

// Analytics Interfaces
export interface DashboardStats {
  totalInvestigations: number;
  highCriticalCount: number;
  totalIpScanned: number;
  totalDomainScanned: number;
  totalUrlScanned: number;
  totalHashScanned: number;
  severityDistribution: {
    Informational: number;
    Low: number;
    Medium: number;
    High: number;
    Critical: number;
  };
}
