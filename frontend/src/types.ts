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
