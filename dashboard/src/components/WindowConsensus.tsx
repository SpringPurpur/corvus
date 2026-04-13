// WindowConsensus.tsx - per-window score heatmap + ensemble divergence sparkline.
//
// Shows the three OIF window scores (fast=256, medium=1024, slow=4096) for the
// most recent alert as colour-coded cells, and plots the spread between the
// three scores (max − min) over recent history as a sparkline.
//
// Interpreting the heatmap:
//   Fast only high  → burst / flash attack (short burst, forgotten quickly)
//   Slow only high  → sustained / slow-and-low threat (outlasted the fast window)
//   All three high  → prolonged, high-rate attack that filled all windows
//
// Interpreting divergence:
//   Low divergence  → all windows agree (either all normal or all anomalous)
//   High divergence -> windows disagree - detector is in a state of rapid
//                     adaptation, likely witnessing a novel traffic transition

import { useMemo } from 'react'
import type { Alert } from '../types'

const WINDOWS = [
  { key: 'fast'   as const, label: '256',  title: 'Fast window (256 flows)'     },
  { key: 'medium' as const, label: '1 024', title: 'Medium window (1 024 flows)' },
  { key: 'slow'   as const, label: '4 096', title: 'Slow window (4 096 flows)'   },
]

// Number of recent alerts to use for the divergence sparkline
const DIVERGENCE_WINDOW = 60

function scoreColor(s: number, thHigh: number, thCrit: number): string {
  if (s >= thCrit) return 'var(--color-score-crit)'
  if (s >= thHigh) return 'var(--color-score-high)'
  return 'var(--color-score-normal)'
}

interface Props {
  alerts:  Alert[]
  thHigh:  number
  thCrit:  number
}

export function WindowConsensus({ alerts, thHigh, thCrit }: Props) {
  const { current, divergence } = useMemo(() => {
    if (!alerts.length) return { current: null, divergence: [] as number[] }

    const last = alerts[alerts.length - 1]
    const current = {
      fast:   last.scores.fast,
      medium: last.scores.medium,
      slow:   last.scores.slow,
    }

    const recent = alerts.slice(-DIVERGENCE_WINDOW)
    const divergence = recent.map((a) => {
      const vals = [a.scores.fast, a.scores.medium, a.scores.slow]
      return Math.max(...vals) - Math.min(...vals)
    })

    return { current, divergence }
  }, [alerts])

  if (!current) {
    return (
      <div className="text-[10px] text-muted-foreground italic">
        No alerts yet - waiting for baseline to complete
      </div>
    )
  }

  // SVG sparkline dimensions (viewBox units, not px)
  const SVG_W = 240
  const SVG_H = 22
  const maxDiv   = Math.max(...divergence, 0.05)
  const n        = divergence.length
  const divPoints = divergence
    .map((v, i) => `${(i / Math.max(n - 1, 1)) * SVG_W},${SVG_H - (v / maxDiv) * SVG_H}`)
    .join(' ')

  // Colour the sparkline by the peak divergence value
  const peakDiv   = Math.max(...divergence)
  const divColor  = peakDiv >= (thCrit - thHigh)
    ? 'var(--color-score-high)'
    : 'var(--color-accent)'

  return (
    <div className="space-y-3">
      {/* 3-cell heatmap */}
      <div className="flex gap-1.5">
        {WINDOWS.map(({ key, label, title }) => {
          const score = current[key]
          const color = scoreColor(score, thHigh, thCrit)
          return (
            <div
              key={key}
              title={`${title}: ${(score * 100).toFixed(1)}%`}
              className="flex-1 flex flex-col items-center py-1.5"
              style={{
                background:   `color-mix(in srgb, ${color} 14%, transparent)`,
                border:       `1px solid color-mix(in srgb, ${color} 35%, transparent)`,
                borderRadius: 'var(--radius)',
              }}
            >
              <div
                className="text-[12px] font-bold tabular-nums leading-none"
                style={{ color }}
              >
                {(score * 100).toFixed(0)}%
              </div>
              <div className="text-[9px] text-muted-foreground mt-1 leading-none">
                {label}
              </div>
            </div>
          )
        })}
      </div>

      {/* Divergence sparkline */}
      <div>
        <div className="flex items-center justify-between text-[10px] text-muted-foreground mb-1">
          <span>Window divergence (max − min)</span>
          <span className="tabular-nums">{(peakDiv * 100).toFixed(1)}% peak</span>
        </div>
        <svg
          viewBox={`0 0 ${SVG_W} ${SVG_H}`}
          className="w-full h-5"
          preserveAspectRatio="none"
        >
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
        <div className="text-[9px] text-muted-foreground mt-0.5 opacity-60">
          Last {n} alert{n !== 1 ? 's' : ''}
          {' · '}
          High divergence → windows disagree · detector in adaptation
        </div>
      </div>
    </div>
  )
}