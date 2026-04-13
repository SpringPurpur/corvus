// useWebSocket.ts - manages the WebSocket connection to the inference engine.
//
// Reconnects automatically with exponential backoff (1s → 2s → 4s → … → 30s).
// All messages are MessagePack binary, never JSON. Incoming frames are decoded
// and dispatched via onMessage; outgoing frames are encoded before send.

import { useCallback, useEffect, useRef, useState } from 'react'
import { decode, encode } from '@msgpack/msgpack'
import type { WsMessage, FeedbackMsg, LlmRequestMsg } from '../types'

function wsUrl(): string {
  const base = `ws://${window.location.host}/ws`
  const key  = sessionStorage.getItem('corvus_api_key')
  return key ? `${base}?key=${encodeURIComponent(key)}` : base
}

interface UseWebSocketReturn {
  connected: boolean
  send: (msg: FeedbackMsg | LlmRequestMsg) => void
}

export function useWebSocket(
  onMessage: (msg: WsMessage) => void,
): UseWebSocketReturn {
  const [connected, setConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const backoffRef = useRef(1000)
  const onMessageRef = useRef(onMessage)
  const mountedRef = useRef(true)
  onMessageRef.current = onMessage

  const connect = useCallback(() => {
    if (!mountedRef.current) return
    const ws = new WebSocket(wsUrl())
    ws.binaryType = 'arraybuffer'
    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
      backoffRef.current = 1000
    }

    ws.onmessage = (ev) => {
      const t_browser_ms = Date.now()   // stamp immediately on frame receipt
      try {
        const msg = decode(ev.data as ArrayBuffer) as WsMessage
        // Inject browser receipt time into alert timing block
        if (msg.type === 'alert' && msg.data.timing) {
          msg.data.timing.t_browser_ms = t_browser_ms
        }
        onMessageRef.current(msg)
      } catch {
        // malformed frame - ignore
      }
    }

    ws.onclose = () => {
      setConnected(false)
      if (!mountedRef.current) return   // don't reconnect after unmount
      const delay = backoffRef.current
      backoffRef.current = Math.min(delay * 2, 30000)
      setTimeout(connect, delay)
    }

    ws.onerror = () => {
      ws.close()
    }
  }, [])

  useEffect(() => {
    mountedRef.current = true
    connect()
    return () => {
      mountedRef.current = false
      wsRef.current?.close()
    }
  }, [connect])

  const send = useCallback((msg: FeedbackMsg | LlmRequestMsg) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(encode(msg))
    }
  }, [])

  return { connected, send }
}
