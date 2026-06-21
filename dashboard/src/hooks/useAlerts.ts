// useAlerts.ts - alert state with TCP/UDP split and a ring capped at 5 000.
// A larger ring keeps per-entity counts stable over longer monitoring sessions;
// at 500 the counts would visibly drop as old alerts were evicted, confusing
// analysts who don't know about the cap.
//
// Alerts arriving on the WebSocket are buffered in refs and flushed to React
// state at most every FLUSH_MS milliseconds.  This coalesces rapid-fire alert
// bursts (floods, scans) into a single setState per interval, reducing array
// copies from O(alerts/s × RING_SIZE) to O(flushes/s × RING_SIZE).

import { useCallback, useRef, useState } from 'react'
import type { Alert, OifMetrics, QueueDepth, WsMessage } from '../types'

const RING_SIZE = 5_000
const FLUSH_MS  = 150    // flush pending alerts to state at most ~7×/s

// Append a batch to the ring without creating an intermediate array.
// If prev + batch fits, just spread both. Otherwise slice only the tail of
// prev that fits alongside the batch, avoiding a double-allocation.
function appendRing(prev: Alert[], batch: Alert[]): Alert[] {
  const total = prev.length + batch.length
  if (total <= RING_SIZE) return [...prev, ...batch]
  const keep = RING_SIZE - batch.length
  return keep > 0 ? [...prev.slice(-keep), ...batch] : batch.slice(-RING_SIZE)
}

const emptyMetrics: OifMetrics = {
  n_seen: 0, n_trained: 0, n_rejected: 0,
  rejection_rate: 0, score_p50: 0, score_p95: 0,
  score_recent: [], ready: false,
}

interface AlertState {
  tcp: Alert[]
  udp: Alert[]
  captureUp: boolean
  modelsLoaded: boolean
  baselining: boolean
  baselineProgress: number
  tcpHealth: OifMetrics
  udpHealth: OifMetrics
  queueDepth: QueueDepth
}

interface UseAlertsReturn extends AlertState {
  handleMessage: (msg: WsMessage) => void
  loadHistory: () => void
  clearAlerts: () => void
}

export function useAlerts(): UseAlertsReturn {
  const [state, setState] = useState<AlertState>({
    tcp: [],
    udp: [],
    captureUp: false,
    modelsLoaded: false,
    baselining: true,
    baselineProgress: 0,
    tcpHealth: emptyMetrics,
    udpHealth: emptyMetrics,
    queueDepth: { tcp: 0, udp: 0, flow: 0, total: 0 },
  })

  // Pending alert buffers — alerts accumulate here between flushes so that
  // rapid-fire bursts produce a single setState rather than one per alert.
  const pendingRef    = useRef<{ tcp: Alert[]; udp: Alert[] }>({ tcp: [], udp: [] })
  const flushTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const flush = useCallback(() => {
    flushTimerRef.current = null
    const { tcp, udp } = pendingRef.current
    pendingRef.current = { tcp: [], udp: [] }
    if (tcp.length === 0 && udp.length === 0) return
    setState(s => ({
      ...s,
      tcp: tcp.length ? appendRing(s.tcp, tcp) : s.tcp,
      udp: udp.length ? appendRing(s.udp, udp) : s.udp,
    }))
  }, [])

  const loadHistory = useCallback(() => {
    fetch('/flows?limit=2000')
      .then((r) => r.json())
      .then((flows: Alert[]) => {
        if (!flows.length) return
        // History comes back newest-first; reverse so oldest is at the top,
        // matching the live feed append order. Then split by protocol.
        const sorted = [...flows].reverse()
        const tcp = sorted.filter((f) => f.proto === 'TCP').slice(-RING_SIZE)
        const udp = sorted.filter((f) => f.proto === 'UDP').slice(-RING_SIZE)
        setState((s) => ({
          ...s,
          tcp,
          udp,
          baselining: false,
        }))
      })
      .catch(() => {
        // History unavailable (first run, or inference not yet up) - silent
      })
  }, [])

  const handleMessage = useCallback((msg: WsMessage) => {
    if (msg.type === 'status') {
      setState((s) => ({
        ...s,
        captureUp:       msg.capture   ?? s.captureUp,
        modelsLoaded:    msg.models    ?? s.modelsLoaded,
        // Only clear the baselining banner if the server explicitly sends
        // baselining:false. A status message that omits the field (e.g. the
        // capture-up ping) must not prematurely hide the progress bar.
        baselining:      s.baselining ? (msg.baselining ?? true) : false,
        baselineProgress: msg.progress ?? s.baselineProgress,
      }))
      return
    }
    if (msg.type === 'stats') {
      setState((s) => ({
        ...s,
        tcpHealth: msg.tcp,
        udpHealth: msg.udp,
        queueDepth: msg.queue_depth ?? s.queueDepth,
      }))
      return
    }
    if (msg.type !== 'alert') return

    const alert = msg.data
    if (alert.proto === 'TCP') pendingRef.current.tcp.push(alert)
    else                        pendingRef.current.udp.push(alert)

    if (!flushTimerRef.current)
      flushTimerRef.current = setTimeout(flush, FLUSH_MS)
  }, [])

  const clearAlerts = useCallback(() => {
    setState(s => ({ ...s, tcp: [], udp: [] }))
  }, [])

  return { ...state, handleMessage, loadHistory, clearAlerts }
}
