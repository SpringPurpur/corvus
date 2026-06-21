import { useMemo } from 'react'
import { G3, alpha } from '../grid/g3'
import type { Alert } from '../../types'

const WINDOWS = [
  { key: 'fast'   as const, label: '256',   title: 'Fast window (256 flows)'     },
  { key: 'medium' as const, label: '1 024', title: 'Medium window (1 024 flows)' },
  { key: 'slow'   as const, label: '4 096', title: 'Slow window (4 096 flows)'   },
]

const DIVERGENCE_WINDOW = 60

function scoreColor(s: number, thHigh: number, thCrit: number): string {
  if (s >= thCrit) return G3.crit
  if (s >= thHigh) return G3.high
  return G3.ok
}

interface Props {
  alerts: Alert[]
  thHigh: number
  thCrit: number
}

export function ModConsensus({ alerts, thHigh, thCrit }: Props) {
  const { current, divergence } = useMemo(() => {
    if (!alerts.length) return { current: null, divergence: [] as number[] }
    const last    = alerts.reduce((best, a) => a.ts > best.ts ? a : best)
    const current = { fast: last.scores.fast, medium: last.scores.medium, slow: last.scores.slow }
    const recent  = alerts.slice(-DIVERGENCE_WINDOW)
    const divergence = recent.map(a => {
      const vals = [a.scores.fast, a.scores.medium, a.scores.slow]
      return Math.max(...vals) - Math.min(...vals)
    })
    return { current, divergence }
  }, [alerts])

  if (!current) {
    return (
      <div style={{ padding: 16, color: G3.mute, fontSize: 10, fontStyle: 'italic' }}>
        No alerts yet — waiting for baseline to complete
      </div>
    )
  }

  const SVG_W  = 240
  const SVG_H  = 22
  const maxDiv = Math.max(...divergence, 0.05)
  const n      = divergence.length
  const divPoints = divergence
    .map((v, i) => `${(i / Math.max(n - 1, 1)) * SVG_W},${SVG_H - (v / maxDiv) * SVG_H}`)
    .join(' ')
  const peakDiv  = Math.max(...divergence)
  const divColor = peakDiv >= (thCrit - thHigh) ? G3.high : G3.accent

  return (
    <div style={{ padding: 12, height: '100%', display: 'flex', flexDirection: 'column', gap: 10, minHeight: 0 }}>

      {/* 3-cell window heatmap */}
      <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
        {WINDOWS.map(({ key, label, title }) => {
          const score = current[key]
          const col   = scoreColor(score, thHigh, thCrit)
          return (
            <div
              key={key}
              title={`${title}: ${(score * 100).toFixed(1)}%`}
              style={{
                flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center',
                padding: '8px 4px',
                background: alpha(col, 13),
                border: `1px solid ${alpha(col, 27)}`,
                borderRadius: 5,
              }}
            >
              <div style={{
                fontSize: 14, fontWeight: 700, color: col,
                fontFamily: 'JetBrains Mono, ui-monospace, monospace', lineHeight: 1,
              }}>
                {(score * 100).toFixed(0)}%
              </div>
              <div style={{ fontSize: 8, color: G3.mute, marginTop: 4, lineHeight: 1 }}>{label}</div>
            </div>
          )
        })}
      </div>

      {/* Divergence sparkline */}
      <div style={{ flex: 1, minHeight: 0 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: G3.mute, marginBottom: 4 }}>
          <span>Window divergence (max − min)</span>
          <span style={{ fontFamily: 'JetBrains Mono, ui-monospace, monospace' }}>
            {(peakDiv * 100).toFixed(1)}% peak
          </span>
        </div>
        <svg viewBox={`0 0 ${SVG_W} ${SVG_H}`} style={{ width: '100%', height: 20 }} preserveAspectRatio="none">
          {n > 1 && (
            <polyline
              points={divPoints}
              fill="none"
              stroke={divColor}
              strokeWidth="1.5"
              strokeLinejoin="round"
              strokeLinecap="round"
            />
          )}
        </svg>
        <div style={{ fontSize: 8, color: G3.mute, marginTop: 4, opacity: 0.6 }}>
          Last {n} alert{n !== 1 ? 's' : ''} · high divergence → windows disagree · detector adapting
        </div>
      </div>
    </div>
  )
}
