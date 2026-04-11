// useAlerts.ts — alert state with TCP/UDP split and a ring buffer capped at 5 000.
// A larger ring keeps per-entity counts stable over longer monitoring sessions —
// at 500 the counts would visibly drop as old alerts were evicted, confusing
// analysts who don't know about the cap.

import { useCallback, useRef, useState } from 'react'
import type { Alert, OifMetrics, QueueDepth, WsMessage } from '../types'

const RING_SIZE = 5_000

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

  // Track per-minute alert count using a sliding timestamp window
  const tsWindowRef = useRef<number[]>([])

  const loadHistory = useCallback(() => {
    fetch('/flows?limit=2000')
      .then((r) => r.json())
      .then((flows: Alert[]) => {
        if (!flows.length) return
        // History comes back newest-first — reverse so oldest is at the top,
        // matching the live feed append order. Then split by protocol.
        const sorted = [...flows].reverse()
        const tcp = sorted.filter((f) => f.proto === 'TCP').slice(-RING_SIZE)
        const udp = sorted.filter((f) => f.proto === 'UDP').slice(-RING_SIZE)
        sorted.forEach((f) => tsWindowRef.current.push(f.ts))
        setState((s) => ({
          ...s,
          tcp,
          udp,
          // If we have stored flows, detection was already active — skip baselining
          // banner and mark models as loaded so the status dot lights up correctly.
          baselining: false,
          modelsLoaded: true,
        }))
      })
      .catch(() => {
        // History unavailable (first run, or inference not yet up) — silent
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
    tsWindowRef.current.push(alert.ts)

    setState((s) => {
      const key = alert.proto === 'TCP' ? 'tcp' : 'udp'
      const prev = s[key]
      // Ring buffer — drop oldest when full
      const next = prev.length >= RING_SIZE
        ? [...prev.slice(1), alert]
        : [...prev, alert]
      // Detection active once first alert arrives
      return { ...s, [key]: next, baselining: false }
    })
  }, [])

  const clearAlerts = useCallback(() => {
    setState(s => ({ ...s, tcp: [], udp: [] }))
  }, [])

  return { ...state, handleMessage, loadHistory, clearAlerts }
}
