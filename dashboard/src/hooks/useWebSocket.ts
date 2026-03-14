// useWebSocket.ts — manages the WebSocket connection to the inference engine.
//
// Reconnects automatically with exponential backoff (1s → 2s → 4s → … → 30s).
// All messages are MessagePack binary — never JSON. Incoming frames are decoded
// and dispatched via onMessage; outgoing frames are encoded before send.

import { useCallback, useEffect, useRef, useState } from 'react'
import { decode, encode } from '@msgpack/msgpack'
import type { WsMessage, FeedbackMsg, LlmRequestMsg } from '../types'

const WS_URL = `ws://${window.location.host}/ws`

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
  onMessageRef.current = onMessage

  const connect = useCallback(() => {
    const ws = new WebSocket(WS_URL)
    ws.binaryType = 'arraybuffer'
    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
      backoffRef.current = 1000
    }

    ws.onmessage = (ev) => {
      try {
        const msg = decode(ev.data as ArrayBuffer) as WsMessage
        onMessageRef.current(msg)
      } catch {
        // malformed frame — ignore
      }
    }

    ws.onclose = () => {
      setConnected(false)
      const delay = backoffRef.current
      backoffRef.current = Math.min(delay * 2, 30000)
      setTimeout(connect, delay)
    }

    ws.onerror = () => {
      ws.close()
    }
  }, [])

  useEffect(() => {
    connect()
    return () => {
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
