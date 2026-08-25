export type OwaspMapping = {
  edition: '2025';
  category_id: string;
  category_name: string;
  cwe_ids: string[];
  coverage: 'limited_static';
  reference_url: string;
};

export type OwaspCategory = {
  category_id: string;
  category_name: string;
  summary: string;
  reference_url: string;
  coverage: 'limited_static' | 'not_assessed';
  finding_count: number;
  supported_rules: string[];
};

export type OwaspSummary = {
  edition: '2025';
  mapped_findings: number;
  disclaimer: string;
  categories: OwaspCategory[];
};

export type Finding = {
  id: string;
  rule_id: string;
  title: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  line: number;
  excerpt: string;
  evidence: string;
  status: string;
  ai_explanation: Record<string, string>;
  owasp: OwaspMapping | null;
};

export type ScanFile = {path: string; lines: number; content: string};
export type Scan = {
  id: string;
  status: string;
  filename: string;
  language: string;
  source: string;
  total_lines: number;
  files: ScanFile[];
  findings: Finding[];
  owasp: OwaspSummary;
};

export type ScanEvent = {
  sequence: number;
  stage: string;
  status: string;
  message: string;
  metrics: Record<string, number | string | string[]>;
  created_at: string;
};

export type FixProposal = {
  id: string;
  finding_id: string;
  file_path: string;
  before_code: string;
  replacement_code: string;
  unified_diff: string;
  confidence_note: string;
  can_apply: boolean;
  status: string;
  provider?: string;
};
