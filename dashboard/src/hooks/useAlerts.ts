// useAlerts.ts — alert state with TCP/UDP split and a ring buffer capped at 500.

import { useCallback, useRef, useState } from 'react'
import type { Alert, WsMessage } from '../types'

const RING_SIZE = 500

interface AlertState {
  tcp: Alert[]
  udp: Alert[]
  captureUp: boolean
  modelsLoaded: boolean
  baselining: boolean
  baselineProgress: number
}

interface UseAlertsReturn extends AlertState {
  handleMessage: (msg: WsMessage) => void
}

export function useAlerts(): UseAlertsReturn {
  const [state, setState] = useState<AlertState>({
    tcp: [],
    udp: [],
    captureUp: false,
    modelsLoaded: false,
    baselining: true,
    baselineProgress: 0,
  })

  // Track per-minute alert count using a sliding timestamp window
  const tsWindowRef = useRef<number[]>([])

  const handleMessage = useCallback((msg: WsMessage) => {
    if (msg.type === 'status') {
      setState((s) => ({
        ...s,
        captureUp: msg.capture ?? s.captureUp,
        modelsLoaded: msg.models ?? s.modelsLoaded,
        baselining: msg.baselining ?? false,
        baselineProgress: msg.progress ?? s.baselineProgress,
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

  return { ...state, handleMessage }
}
