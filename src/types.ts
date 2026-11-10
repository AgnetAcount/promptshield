export type RiskLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ViolationCategory = 'injection' | 'exfiltration' | 'obfuscation' | 'delimiters' | string;

export interface Violation {
  ruleId: string;
  category: ViolationCategory;
  severity: RiskLevel;
  description: string;
  matched: string;
  score: number;
  index?: number;
}

export interface ScanResult {
  safe: boolean;
  riskScore: number;
  riskLevel: RiskLevel;
  violations: Violation[];
  scanTimeMs: number;
  textLength: number;
}

export interface Rule {
  id: string;
  category: ViolationCategory;
  severity: RiskLevel;
  score: number;
  description: string;
  check: (text: string, options?: ScanOptions) => Violation[] | null;
}

export interface ScanOptions {
  threshold?: number;
  categories?: ViolationCategory[];
  disabledRules?: string[];
  maxSampleLength?: number;
  customRules?: Rule[];
}

export interface SanitizeOptions {
  stripZeroWidth?: boolean;
  defangDelimiters?: boolean;
  defangMarkdownImages?: boolean;
  normalizeHomoglyphs?: boolean;
}
