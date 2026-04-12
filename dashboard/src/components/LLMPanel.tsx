// LLMPanel.tsx — LLM explanation, feedback form, and analyst chat for an alert.

import { useCallback, useEffect, useRef, useState } from 'react'
import type { Alert, Feedback, FeedbackMsg, LlmRequestMsg } from '../types'
import { cn } from '../lib/utils'

interface Props {
  alert:        Alert
  allAlerts:    Alert[]
  send:         (msg: FeedbackMsg | LlmRequestMsg) => void
  llmResponses: Record<string, string>
}

export function LLMPanel({ alert, allAlerts, send, llmResponses }: Props) {
  const [question, setQuestion]               = useState('')
  const [feedback, setFeedback]               = useState<Feedback | null>(null)
  const [feedbackPending, setFeedbackPending] = useState(false)
  const [explaining, setExplaining]           = useState(false)
  const [fullContext, setFullContext]          = useState(false)
  const explainId  = `explain-${alert.flow_id}`
  const chatIdRef  = useRef(0)

  // Reset UI state and load any stored feedback when the selected alert changes.
  // Explanation is NOT auto-requested — the analyst triggers it explicitly.
  useEffect(() => {
    setFeedback(null)
    setFeedbackPending(false)
    setExplaining(false)
    fetch(`/feedback?flow_id=${alert.flow_id}`)
      .then((r) => r.json())
      .then((rows: Feedback[]) => { if (rows.length) setFeedback(rows[0]) })
      .catch(() => {})
  }, [alert.flow_id]) // eslint-disable-line react-hooks/exhaustive-deps

  const handleExplain = useCallback(() => {
    setExplaining(true)
    // When fullContext is off, strip features from the payload to keep token usage low.
    const alertPayload = fullContext
      ? alert
      : { ...alert, features: undefined }
    send({ type: 'llm_request', request_id: explainId, fn: 'explain', payload: { alert: alertPayload } })
  }, [alert, explainId, fullContext, send])

  const handleDismiss = useCallback(() => {
    setFeedbackPending(true)
    send({
      type: 'feedback', flow_id: alert.flow_id,
      corrected_label: null, dismiss: true, reason: 'Dismissed as false positive',
    })
    setFeedback({ flow_id: alert.flow_id, ts: Date.now() / 1000, corrected_label: null, dismiss: true, reason: 'Dismissed as false positive' })
  }, [alert.flow_id, send])

  const handleAsk = useCallback(() => {
    if (!question.trim()) return
    const reqId = `ask-${++chatIdRef.current}`
    // Use up to 20 alerts from the current tab for context, not just the selected one
    const context = allAlerts.slice(0, 20)
    send({ type: 'llm_request', request_id: reqId, fn: 'ask', payload: { alerts_context: context, question } })
    setQuestion('')
  }, [allAlerts, question, send])

  const handleParseFeedback = useCallback((text: string) => {
    if (!text.trim()) return
    const reqId = `feedback-${alert.flow_id}`
    send({
      type: 'llm_request', request_id: reqId, fn: 'parse_feedback',
      payload: { alert, analyst_text: text },
    })
  }, [alert, send])

  // When a parse_feedback response arrives, parse and display it
  const parseFeedbackId  = `feedback-${alert.flow_id}`
  const parsedFeedbackRaw = llmResponses[parseFeedbackId]
  useEffect(() => {
    if (!parsedFeedbackRaw) return
    try {
      const parsed = JSON.parse(parsedFeedbackRaw) as Partial<Feedback>
      setFeedback({
        flow_id:         alert.flow_id,
        ts:              Date.now() / 1000,
        corrected_label: parsed.corrected_label ?? null,
        dismiss:         parsed.dismiss ?? false,
        reason:          parsed.reason ?? '',
      })
    } catch { /* non-JSON response — ignore */ }
  }, [parsedFeedbackRaw, alert.flow_id])

  const explanation = llmResponses[explainId]
  const [feedbackText, setFeedbackText] = useState('')

  return (
    <div className="flex flex-col gap-3 p-4 text-sm h-full overflow-y-auto">

      {/* Explanation */}
      <section>
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            AI Explanation
          </h3>
          <label className="flex items-center gap-1.5 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={fullContext}
              onChange={(e) => setFullContext(e.target.checked)}
              className="h-3 w-3 accent-current"
            />
            <span className="text-[11px] text-muted-foreground">Full features</span>
          </label>
        </div>
        {explanation ? (
          <p className="text-xs leading-relaxed">{explanation}</p>
        ) : explaining ? (
          <p className="text-xs text-muted-foreground italic">Requesting explanation…</p>
        ) : (
          <button
            onClick={handleExplain}
            className="self-start px-3 py-1.5 rounded bg-muted hover:bg-muted/80 text-xs transition-colors"
          >
            Generate explanation
          </button>
        )}
      </section>

      {/* Feedback */}
      <section>
        <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
          Analyst Feedback
        </h3>

        {feedback ? (
          <div className="flex flex-col gap-1 text-xs">
            {feedback.dismiss && (
              <span style={{ color: 'var(--color-badge-warn-text)' }}>Marked as false positive</span>
            )}
            {feedback.corrected_label && (
              <span style={{ color: 'var(--color-bar-primary)' }}>Severity corrected → {feedback.corrected_label}</span>
            )}
            {feedback.reason && (
              <span className="text-muted-foreground">Reason: {feedback.reason}</span>
            )}
            <button
              onClick={() => setFeedback(null)}
              className="mt-1 self-start text-[11px] text-muted-foreground underline"
            >
              Edit
            </button>
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            <button
              onClick={handleDismiss}
              disabled={feedbackPending}
              className="self-start px-3 py-1.5 rounded bg-muted hover:bg-muted/80 text-xs transition-colors"
            >
              Dismiss as false positive
            </button>
            <div className="flex gap-2">
              <input
                value={feedbackText}
                onChange={(e) => setFeedbackText(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') { handleParseFeedback(feedbackText); setFeedbackText('') } }}
                placeholder="Correct severity or add note…"
                className={cn(
                  'flex-1 rounded bg-muted px-3 py-1.5 text-xs',
                  'placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-border',
                )}
              />
              <button
                onClick={() => { handleParseFeedback(feedbackText); setFeedbackText('') }}
                className="px-3 py-1.5 rounded bg-muted hover:bg-muted/80 text-xs transition-colors"
              >
                Submit
              </button>
            </div>
          </div>
        )}
      </section>

      {/* Ask */}
      <section className="flex flex-col gap-2">
        <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          Ask Claude
        </h3>
        <div className="flex gap-2">
          <input
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleAsk()}
            placeholder="Ask about this alert or current session…"
            className={cn(
              'flex-1 rounded bg-muted px-3 py-1.5 text-xs',
              'placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-border',
            )}
          />
          <button
            onClick={handleAsk}
            className="px-3 py-1.5 rounded bg-muted hover:bg-muted/80 text-xs transition-colors"
          >
            Ask
          </button>
        </div>
        {Object.entries(llmResponses)
          .filter(([id]) => id.startsWith('ask-'))
          .slice(-1)
          .map(([id, text]) => (
            <p key={id} className="text-xs leading-relaxed border-t pt-2 border-border">{text}</p>
          ))}
      </section>

    </div>
  )
}
