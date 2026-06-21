import { useEffect, useRef, useState } from 'react'
import { G3, alpha } from '../grid/g3'
import type { Alert, FeedbackMsg, LlmRequestMsg } from '../../types'

interface ChatMessage {
  id:     string
  role:   'user' | 'assistant'
  text?:  string   // user messages have text directly
  reqId?: string   // assistant messages look up text from llmResponses
}

interface Props {
  alert:        Alert | null
  allAlerts:    Alert[]
  send:         (msg: FeedbackMsg | LlmRequestMsg) => void
  llmResponses: Record<string, string>
  llmReady:     boolean
}

export function ModLLM({ alert: a, allAlerts, send, llmResponses, llmReady }: Props) {
  const [messages, setMessages]       = useState<ChatMessage[]>([])
  const [question, setQuestion]       = useState('')
  const [fullContext, setFullContext] = useState(false)
  const prevFlowIdRef                 = useRef<string | null>(null)
  const chatIdRef                     = useRef(0)
  const scrollRef                     = useRef<HTMLDivElement>(null)

  // Reset conversation when the selected alert changes
  useEffect(() => {
    if (a?.flow_id !== prevFlowIdRef.current) {
      prevFlowIdRef.current = a?.flow_id ?? null
      setMessages([])
      setQuestion('')
    }
  }, [a?.flow_id])

  // Auto-scroll only when a new message is added or the last pending response arrives
  const lastPendingReqId = messages[messages.length - 1]?.reqId ?? null
  const lastResponse     = lastPendingReqId ? llmResponses[lastPendingReqId] : null
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [messages.length, lastResponse])

  const explain = () => {
    if (!a) return
    const reqId = `llm-${a.flow_id}-${Date.now()}`
    send({
      type:       'llm_request',
      request_id: reqId,
      fn:         'explain',
      payload: {
        flow_id:     a.flow_id,
        src_ip:      a.src_ip,
        dst_ip:      a.dst_ip,
        src_port:    a.src_port,
        dst_port:    a.dst_port,
        proto:       a.proto,
        duration:    a.duration,
        fwd_pkts:    a.fwd_pkts,
        score:       a.verdict.confidence,
        severity:    a.verdict.severity,
        attribution: a.attribution,
        ...(fullContext ? { features: a.features ?? {} } : {}),
      },
    })
    setMessages(m => [...m, { id: reqId, role: 'assistant', reqId }])
  }

  const ask = () => {
    if (!question.trim() || !a) return
    const q      = question.trim()
    const reqId  = `ask-${++chatIdRef.current}-${Date.now()}`
    const msgId  = `user-${chatIdRef.current}`
    send({
      type:       'llm_request',
      request_id: reqId,
      fn:         'ask',
      payload:    { alerts_context: allAlerts.slice(0, 20), question: q },
    })
    setMessages(m => [
      ...m,
      { id: msgId, role: 'user',      text: q    },
      { id: reqId, role: 'assistant', reqId       },
    ])
    setQuestion('')
  }

  // True while the last assistant message has no response yet
  const lastMsg   = messages[messages.length - 1]
  const isLoading = lastMsg?.role === 'assistant' && !!lastMsg.reqId && !llmResponses[lastMsg.reqId ?? '']

  if (!a) return (
    <div style={{ padding: 20, color: G3.mute, fontSize: 11 }}>Select an anomaly to analyse</div>
  )

  if (!llmReady) return (
    <div style={{ padding: 16, color: G3.mute, fontSize: 11, lineHeight: 1.6 }}>
      LLM unavailable — set{' '}
      <span style={{ fontFamily: 'JetBrains Mono, ui-monospace, monospace', color: G3.mute2 }}>ANTHROPIC_API_KEY</span>
      {' '}in <span style={{ fontFamily: 'JetBrains Mono, ui-monospace, monospace', color: G3.mute2 }}>.env</span>
      {' '}and restart the inference container.
    </div>
  )

  return (
    <div style={{ padding: '10px 12px 12px', height: '100%', display: 'flex', flexDirection: 'column', minHeight: 0 }}>

      {/* Conversation feed */}
      <div
        ref={scrollRef}
        style={{ flex: 1, overflowY: 'auto', minHeight: 0, display: 'flex', flexDirection: 'column', gap: 8, paddingBottom: 4 }}
      >
        {messages.length === 0 && (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', textAlign: 'center', gap: 10, padding: 16 }}>
            <div style={{ width: 30, height: 30, borderRadius: 6, background: `linear-gradient(135deg, ${G3.accent}, ${G3.purple})`, opacity: 0.9 }} />
            <div style={{ fontSize: 10, color: G3.mute2, lineHeight: 1.5, maxWidth: 240 }}>
              Ask Claude to explain why this flow deviates from baseline, or use the button below to start.
            </div>
          </div>
        )}

        {messages.map(msg => {
          const text      = msg.role === 'user' ? msg.text : (msg.reqId ? llmResponses[msg.reqId] : undefined)
          const isPending = msg.role === 'assistant' && !!msg.reqId && !llmResponses[msg.reqId ?? '']

          return (
            <div key={msg.id} style={{ display: 'flex', justifyContent: msg.role === 'user' ? 'flex-end' : 'flex-start' }}>
              <div style={{
                maxWidth: '88%',
                padding: '6px 10px',
                borderRadius: msg.role === 'user' ? '10px 10px 2px 10px' : '10px 10px 10px 2px',
                background: msg.role === 'user' ? G3.accentSoft : G3.card2,
                border:     `1px solid ${msg.role === 'user' ? alpha(G3.accent, 25) : G3.line}`,
                fontSize: 11, lineHeight: 1.6,
                color: msg.role === 'user' ? G3.accent : G3.fg,
              }}>
                {isPending ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{
                      width: 14, height: 14,
                      border: `1.5px solid ${G3.line}`, borderTopColor: G3.accent,
                      borderRadius: '50%', animation: 'corvus-spin 0.8s linear infinite',
                    }} />
                    <span style={{ fontSize: 10, color: G3.mute }}>Analysing…</span>
                  </div>
                ) : text}
              </div>
            </div>
          )
        })}
      </div>

      {/* Controls */}
      <div style={{ flexShrink: 0, marginTop: 8, display: 'flex', flexDirection: 'column', gap: 6 }}>
        {/* Initial explain button */}
        {messages.length === 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <button onClick={explain} style={{
              flex: 1, padding: '6px 12px', fontSize: 10, fontWeight: 600,
              background: G3.accent, color: G3.bg, border: 'none', borderRadius: 5,
              cursor: 'pointer', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 6,
            }}>
              ✦ Explain anomaly
            </button>
            <label style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer', flexShrink: 0 }}>
              <input
                type="checkbox"
                checked={fullContext}
                onChange={e => setFullContext(e.target.checked)}
                style={{ width: 11, height: 11, accentColor: G3.accent }}
              />
              <span style={{ fontSize: 9, color: G3.mute, whiteSpace: 'nowrap' }}>Full features</span>
            </label>
          </div>
        )}

        {/* Follow-up input */}
        <div style={{ display: 'flex', gap: 5 }}>
          <input
            value={question}
            onChange={e => setQuestion(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && !isLoading) ask() }}
            placeholder={messages.length === 0 ? 'Or ask a custom question…' : 'Ask a follow-up…'}
            disabled={isLoading}
            style={{
              flex: 1, background: G3.card2, border: `1px solid ${G3.line}`,
              borderRadius: 5, padding: '5px 8px', fontSize: 10, color: G3.fg,
              outline: 'none', opacity: isLoading ? 0.5 : 1,
            }}
          />
          <button
            onClick={ask}
            disabled={isLoading || !question.trim()}
            style={{
              padding: '5px 10px', fontSize: 10,
              background: G3.accent, color: G3.bg, border: 'none', borderRadius: 5,
              cursor: isLoading || !question.trim() ? 'not-allowed' : 'pointer',
              opacity: isLoading || !question.trim() ? 0.5 : 1,
            }}
          >
            Ask
          </button>
        </div>

        {/* Footer row */}
        {messages.length > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 8, color: G3.mute, opacity: 0.6 }}>Claude · verify before acting</span>
            <button
              onClick={explain}
              disabled={isLoading}
              style={{
                padding: '3px 8px', fontSize: 9,
                background: 'transparent', color: G3.mute,
                border: `1px solid ${G3.line}`, borderRadius: 3, cursor: 'pointer',
              }}
            >
              Re-explain
            </button>
          </div>
        )}
      </div>

      <style>{`@keyframes corvus-spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}
