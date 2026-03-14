// LLMPanel.tsx — LLM explanation, feedback form, and analyst chat for an alert.

import { useCallback, useEffect, useRef, useState } from 'react'
import type { Alert, FeedbackMsg, LlmRequestMsg } from '../types'
import { cn } from '../lib/utils'

interface Props {
  alert: Alert
  send: (msg: FeedbackMsg | LlmRequestMsg) => void
  llmResponses: Record<string, string>
}

export function LLMPanel({ alert, send, llmResponses }: Props) {
  const [question, setQuestion] = useState('')
  const [submittedFeedback, setSubmittedFeedback] = useState(false)
  const explainId = `explain-${alert.flow_id}`
  const chatIdRef = useRef(0)

  // Request explanation when the panel mounts or alert changes
  useEffect(() => {
    setSubmittedFeedback(false)
    if (!llmResponses[explainId]) {
      const msg: LlmRequestMsg = {
        type: 'llm_request',
        request_id: explainId,
        fn: 'explain',
        payload: { alert },
      }
      send(msg)
    }
  }, [alert.flow_id]) // eslint-disable-line react-hooks/exhaustive-deps

  const handleDismiss = useCallback(() => {
    const msg: FeedbackMsg = {
      type: 'feedback',
      flow_id: alert.flow_id,
      corrected_label: null,
      dismiss: true,
      reason: '',
    }
    send(msg)
    setSubmittedFeedback(true)
  }, [alert.flow_id, send])

  const handleAsk = useCallback(() => {
    if (!question.trim()) return
    const reqId = `ask-${++chatIdRef.current}`
    const msg: LlmRequestMsg = {
      type: 'llm_request',
      request_id: reqId,
      fn: 'ask',
      payload: { alerts_context: [alert], question },
    }
    send(msg)
    setQuestion('')
  }, [alert, question, send])

  const explanation = llmResponses[explainId]

  return (
    <div className="flex flex-col gap-3 p-4 text-sm h-full overflow-y-auto">
      {/* Explanation */}
      <section>
        <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
          AI Explanation
        </h3>
        {explanation ? (
          <p className="text-xs leading-relaxed">{explanation}</p>
        ) : (
          <p className="text-xs text-muted-foreground italic">Requesting explanation…</p>
        )}
      </section>

      {/* Feedback */}
      <section>
        <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
          Analyst Feedback
        </h3>
        {submittedFeedback ? (
          <p className="text-xs text-emerald-400">Feedback submitted.</p>
        ) : (
          <button
            onClick={handleDismiss}
            className="px-3 py-1.5 rounded bg-muted hover:bg-muted/80 text-xs transition-colors"
          >
            Dismiss as false positive
          </button>
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
            placeholder="Ask about this alert…"
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
        {/* Show latest ask response */}
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
