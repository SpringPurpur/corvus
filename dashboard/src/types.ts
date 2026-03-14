export type Severity = 'INFO' | 'HIGH' | 'CRITICAL'

export type ShapTriple = [name: string, value: number, score: number]

export interface Verdict {
  label: string
  label_id: number
  confidence: number
  severity: Severity
}

export interface Alert {
  flow_id: string
  ts: number
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  proto: 'TCP' | 'UDP'
  duration: number
  fwd_pkts: number
  verdict: Verdict
  shap: ShapTriple[]
  anomaly: number
}

// WebSocket downstream message union
export type WsMessage =
  | { type: 'alert'; data: Alert }
  | { type: 'status'; capture: boolean; models: boolean }
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
