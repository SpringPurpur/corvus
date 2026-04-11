import { useMemo } from 'react'
import type { Alert } from '../types'

interface Props {
  alerts:     Alert[]   // unfiltered ring-buffer (all severities)
  bucketSec?: number    // bucket width in seconds (default 5)
  windowSec?: number    // total visible window in seconds (default 120)
}

export function NetworkPulse({ alerts, bucketSec = 5, windowSec = 120 }: Props) {
  const { buckets, perMin } = useMemo(() => {
    const nBuckets = Math.ceil(windowSec / bucketSec)
    const counts   = new Array<number>(nBuckets).fill(0)
    const now      = Date.now() / 1000
    let perMin     = 0

    for (const a of alerts) {
      const ago = now - a.ts
      if (ago < 0 || ago >= windowSec) continue
      const idx = nBuckets - 1 - Math.floor(ago / bucketSec)
      counts[idx]++
      if (ago < 60) perMin++
    }
    return { buckets: counts, perMin }
  }, [alerts, bucketSec, windowSec])

  const maxVal = Math.max(...buckets, 1)
  const n      = buckets.length

  // Build SVG polyline points (width=200, height=24 viewBox units)
  const W = 200
  const H = 24
  const points = buckets
    .map((v, i) => `${(i / (n - 1)) * W},${H - (v / maxVal) * H}`)
    .join(' ')

  return (
    <div className="flex items-center gap-3 px-3 py-1 border-b bg-card/50 shrink-0">
      <span className="text-[10px] text-muted-foreground whitespace-nowrap tracking-wide">
        PULSE
      </span>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="flex-1 h-4"
        preserveAspectRatio="none"
      >
        <polyline
          points={points}
          fill="none"
          stroke="var(--color-accent)"
          strokeWidth="1.5"
          strokeLinejoin="round"
          strokeLinecap="round"
        />
      </svg>
      <span className="text-[10px] text-muted-foreground tabular-nums whitespace-nowrap">
        {perMin}/min
      </span>
    </div>
  )
}
