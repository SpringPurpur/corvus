export type Severity = 'INFO' | 'HIGH' | 'CRITICAL'

export interface AppConfig {
  threshold_high:     number
  threshold_critical: number
  baseline_tcp:       number
  baseline_udp:       number
}

export interface Verdict {
  label: string       // anomaly severity tier: INFO / HIGH / CRITICAL
  confidence: number  // OIF composite score 0-1
  severity: Severity
}

export interface OifScores {
  fast: number
  medium: number
  slow: number
  composite: number
}

export interface AttributionEntry {
  feature:  string
  score:    number                          // relative contribution 0-1
  value:    number                          // raw flow value
  baseline: { median: number; iqr: number } // from RobustScaler fit on baseline corpus
}

export interface Alert {
  flow_id:     string
  ts:          number
  src_ip:      string
  dst_ip:      string
  src_port:    number
  dst_port:    number
  proto:       'TCP' | 'UDP'
  duration:    number
  fwd_pkts:    number
  verdict:     Verdict
  scores:      OifScores
  attribution: AttributionEntry[]
}

// WebSocket downstream message union
export type WsMessage =
  | { type: 'alert'; data: Alert }
  | { type: 'status'; capture: boolean; models: boolean; baselining?: boolean; progress?: number; protocol?: string }
  | { type: 'llm_response'; request_id: string; text: string }

// WebSocket upstream messages
export interface FeedbackMsg {
  type: 'feedback'
  flow_id: string
  corrected_label: string | null
  dismiss: boolean
  reason: string
}

export interface LlmRequestMsg {
  type: 'llm_request'
  request_id: string
  fn: 'explain' | 'parse_feedback' | 'ask'
  payload: Record<string, unknown>
}
