export type Severity = 'INFO' | 'HIGH' | 'CRITICAL'

export interface AppConfig {
  threshold_high:     number
  threshold_critical: number
  baseline_tcp:       number
  baseline_udp:       number
  min_tcp_pkts:       number   // minimum TCP packets before flow reaches OIF (default 4)
  filter_gateway:     boolean  // suppress Docker bridge gateway (172.20.0.1) flows
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
  oor?: number
}

export interface AttributionEntry {
  feature:  string
  score:    number                          // relative contribution 0-1
  value:    number                          // raw flow value
  baseline: { median: number; iqr: number } // from RobustScaler fit on baseline corpus
}

export interface PipelineTiming {
  t_enqueue_ns:  number   // C engine: ipc_writer_enqueue() ring copy time (ns)
  t_socket_ns:   number   // Python: after ctypes decode in socket_reader (ns)
  t_dequeue_ns:  number   // Python: when protocol worker dequeued the flow (ns)
  t_scored_ns:   number   // Python: after OIF scoring completes (ns)
  t_ws_ns:       number   // Python: before WebSocket broadcast (ns)
  t_browser_ms?: number   // Browser: Date.now() on frame receipt (ms)
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
  timing?:     PipelineTiming
}

export interface Feedback {
  flow_id:         string
  ts:              number
  corrected_label: string | null
  dismiss:         boolean
  reason:          string
  analyst_text?:   string
}

export interface OifMetrics {
  n_seen:         number
  n_trained:      number
  n_rejected:     number
  rejection_rate: number   // n_rejected / n_seen — rises during active attacks
  score_p50:      number   // median composite score
  score_p95:      number   // 95th-percentile composite score
  score_recent:   number[] // last ≤20 scores for sparkline
  ready:          boolean  // baseline complete
}

// WebSocket downstream message union
export type WsMessage =
  | { type: 'alert'; data: Alert }
  | { type: 'status'; capture: boolean; models: boolean; baselining?: boolean; progress?: number; protocol?: string }
  | { type: 'stats'; tcp: OifMetrics; udp: OifMetrics }
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
