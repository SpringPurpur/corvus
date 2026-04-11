// HeatmapRibbon.tsx — 24 h per-window score heatmap for the Health tab.
//
// X-axis: time (last 24 h, 5-min buckets → up to 288 columns).
// Y-axis: 3 rows — fast (256), medium (1 024), slow (4 096) window scores.
//
// Each cell is coloured by the average OIF score in that bucket:
//   green  → below HIGH threshold   (detector is calm)
//   amber  → HIGH ≤ score < CRITICAL (elevated)
//   red    → CRITICAL or above       (active attack / high stress)
//
// The SVG uses preserveAspectRatio="none" so the column width self-adjusts to
// the container; cells are 1 viewBox unit wide. Row height is fixed in px.

import { useEffect, useState } from 'react'
import type { AppConfig } from '../types'

interface Bucket {
  ts:     number
  fast:   number
  medium: number
  slow:   number
}

const ROWS: { key: keyof Omit<Bucket, 'ts'>; label: string }[] = [
  { key: 'fast',   label: '256' },
  { key: 'medium', label: '1k'  },
  { key: 'slow',   label: '4k'  },
]

const ROW_H = 8   // height of one row in viewBox units
const GAP   = 1   // gap between rows in viewBox units
const SVG_H = ROWS.length * ROW_H + (ROWS.length - 1) * GAP  // 26

function cellColor(score: number, thHigh: number, thCrit: number): string {
  if (score >= thCrit) return 'var(--color-score-crit)'
  if (score >= thHigh) return 'var(--color-score-high)'
  return 'var(--color-score-normal)'
}

function fmtTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

interface Props {
  proto:  'TCP' | 'UDP'
  config: AppConfig
}

export function HeatmapRibbon({ proto, config }: Props) {
  const [buckets, setBuckets] = useState<Bucket[]>([])
  const { threshold_high: thHigh, threshold_critical: thCrit } = config

  useEffect(() => {
    const load = () => {
      const since = Math.floor(Date.now() / 1000) - 86_400
      fetch(`/window_history?proto=${proto}&since=${since}&bucket=300`)
        .then((r) => r.json())
        .then((rows: Bucket[]) => setBuckets(rows))
        .catch(() => {})
    }
    load()
    const id = setInterval(load, 60_000)
    return () => clearInterval(id)
  }, [proto])

  if (buckets.length === 0) {
    return (
      <p className="text-[10px] text-muted-foreground italic">
        No history yet — data accumulates as flows arrive
      </p>
    )
  }

  const n = buckets.length

  return (
    <div className="space-y-1">
      {/* Row-label + SVG side-by-side */}
      <div className="flex items-stretch gap-1.5">
        {/* Y-axis labels */}
        <div
          className="flex flex-col text-[9px] text-muted-foreground"
          style={{ gap: GAP * 4, paddingTop: 1 }}
        >
          {ROWS.map(({ label }) => (
            <span key={label} style={{ lineHeight: `${ROW_H * 4}px` }}>
              {label}
            </span>
          ))}
        </div>

        {/* Heatmap */}
        <svg
          viewBox={`0 0 ${n} ${SVG_H}`}
          className="flex-1"
          style={{ height: SVG_H * 4 }}
          preserveAspectRatio="none"
          aria-label={`${proto} window score heatmap — last 24 h`}
        >
          {ROWS.map(({ key }, rowIdx) =>
            buckets.map((b, colIdx) => (
              <rect
                key={`${rowIdx}-${colIdx}`}
                x={colIdx}
                y={rowIdx * (ROW_H + GAP)}
                width={1}
                height={ROW_H}
                style={{ fill: cellColor(b[key], thHigh, thCrit) }}
              />
            ))
          )}
        </svg>
      </div>

      {/* X-axis time labels */}
      <div className="flex justify-between text-[9px] text-muted-foreground opacity-60 pl-5">
        <span>{fmtTime(buckets[0].ts)}</span>
        <span>5 min buckets · last 24 h</span>
        <span>{fmtTime(buckets[n - 1].ts)}</span>
      </div>
    </div>
  )
}