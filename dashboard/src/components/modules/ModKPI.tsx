import { useEffect, useMemo, useState } from 'react'
import { useModuleSize } from '../grid/GridContainer'
import { G3 } from '../grid/g3'
import type { Alert, OifMetrics, QueueDepth } from '../../types'

// ── Inline HeatmapRibbon ────────────────────────────────────────────────────

interface Bucket { ts: number; fast: number; medium: number; slow: number }

const RIBBON_ROWS: { key: keyof Omit<Bucket, 'ts'>; label: string }[] = [
  { key: 'fast',   label: '256' },
  { key: 'medium', label: '1k'  },
  { key: 'slow',   label: '4k'  },
]
const ROW_H = 7
const GAP   = 1
const SVG_H = RIBBON_ROWS.length * ROW_H + (RIBBON_ROWS.length - 1) * GAP  // 23

function cellColor(score: number, thHigh: number, thCrit: number): string {
  if (score >= thCrit) return G3.crit
  if (score >= thHigh) return G3.high
  return G3.ok
}

function fmtTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function HeatmapRibbon({ thHigh, thCrit, proto }: { thHigh: number; thCrit: number; proto: 'TCP' | 'UDP' }) {
  const [buckets, setBuckets] = useState<Bucket[]>([])

  useEffect(() => {
    setBuckets([])
    const load = () => {
      const since = Math.floor(Date.now() / 1000) - 86_400
      fetch(`/window_history?proto=${proto}&since=${since}&bucket=300`)
        .then(r => r.json())
        .then((rows: Bucket[]) => setBuckets(rows))
        .catch(() => {})
    }
    load()
    const id = setInterval(load, 60_000)
    return () => clearInterval(id)
  }, [proto])

  if (buckets.length === 0) {
    return (
      <div style={{ fontSize: 9, color: G3.mute, fontStyle: 'italic', padding: '4px 0' }}>
        No history yet — data accumulates as flows arrive
      </div>
    )
  }

  const n = buckets.length

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'stretch', gap: 6 }}>
        {/* Y-axis labels */}
        <div style={{ display: 'flex', flexDirection: 'column', fontSize: 8, color: G3.mute, fontFamily: 'JetBrains Mono, ui-monospace, monospace', justifyContent: 'space-around' }}>
          {RIBBON_ROWS.map(({ label }) => <span key={label}>{label}</span>)}
        </div>
        {/* SVG heatmap */}
        <svg
          viewBox={`0 0 ${n} ${SVG_H}`}
          style={{ flex: 1, height: 42 }}
          preserveAspectRatio="none"
        >
          {RIBBON_ROWS.map(({ key }, ri) =>
            buckets.map((b, ci) => (
              <rect
                key={`${ri}-${ci}`}
                x={ci} y={ri * (ROW_H + GAP)}
                width={1} height={ROW_H}
                fill={cellColor(b[key], thHigh, thCrit)}
              />
            ))
          )}
        </svg>
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 8, color: G3.mute, opacity: 0.6, marginTop: 2 }}>
        <span>{fmtTime(buckets[0].ts)}</span>
        <span>5 min buckets · last 24 h</span>
        <span>{fmtTime(buckets[n - 1].ts)}</span>
      </div>
    </div>
  )
}

// ── ModKPI ───────────────────────────────────────────────────────────────────

interface Props {
  alerts:           Alert[]
  tcpHealth:        OifMetrics
  udpHealth:        OifMetrics
  queueDepth:       QueueDepth
  modelsLoaded:     boolean
  baselining:       boolean
  baselineProgress: number
  thHigh:           number
  thCrit:           number
}

export function ModKPI({ alerts, queueDepth, modelsLoaded, baselining, baselineProgress, thHigh, thCrit }: Props) {
  const { w, h } = useModuleSize()
  const showRibbon = h >= 90
  const [ribbonProto, setRibbonProto] = useState<'TCP' | 'UDP'>('TCP')

  const { critical, high, recentCount } = useMemo(() => {
    const now = Date.now() / 1000
    return {
      critical:    alerts.filter(a => a.verdict.severity === 'CRITICAL').length,
      high:        alerts.filter(a => a.verdict.severity === 'HIGH').length,
      recentCount: alerts.filter(a => a.ts >= now - 60).length,
    }
  }, [alerts])

  const modelLabel = baselining
    ? `${Math.round(baselineProgress * 100)}%`
    : modelsLoaded ? 'Ready' : 'Pending'
  const modelColor = modelsLoaded && !baselining ? G3.ok
    : baselining ? G3.high
    : G3.mute2

  const items: [string, string | number, string][] = [
    ['Flows/min', recentCount,       G3.accent],
    ['Critical',  critical,          G3.crit],
    ['High',      high,              G3.high],
    ['Baseline',  modelLabel,        modelColor],
    ['Queue',     queueDepth.total,  G3.mute2],
  ]

  const visible   = w < 320 ? items.slice(0, 3) : w < 480 ? items.slice(0, 4) : items
  const valueSize = Math.max(14, Math.min(24, w / visible.length / 8))

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* KPI cards */}
      <div style={{ display: 'grid', gridTemplateColumns: `repeat(${visible.length}, 1fr)`, flex: showRibbon ? 'none' : 1 }}>
        {visible.map(([k, v, col], i) => (
          <div key={k} style={{
            padding: '8px 12px',
            borderRight: i < visible.length - 1 ? `1px solid ${G3.lineSoft}` : 'none',
            display: 'flex', flexDirection: 'column', justifyContent: 'center', minWidth: 0,
          }}>
            <div style={{ fontSize: 9, color: G3.mute, textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {k}
            </div>
            <div style={{ fontSize: valueSize, fontWeight: 700, color: col, fontFamily: 'JetBrains Mono, ui-monospace, monospace', lineHeight: 1.1 }}>
              {v}
            </div>
          </div>
        ))}
      </div>

      {/* 24h OIF window score ribbon */}
      {showRibbon && (
        <div style={{ padding: '6px 12px 8px', borderTop: `1px solid ${G3.lineSoft}`, flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
            <span style={{ fontSize: 8, color: G3.mute, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              OIF score · last 24 h
            </span>
            <div style={{ display: 'flex', gap: 2 }}>
              {(['TCP', 'UDP'] as const).map(p => (
                <button
                  key={p}
                  onClick={() => setRibbonProto(p)}
                  style={{
                    padding: '1px 5px', fontSize: 8, border: 'none', borderRadius: 2, cursor: 'pointer',
                    background: ribbonProto === p ? G3.accent : G3.line,
                    color:      ribbonProto === p ? G3.bg     : G3.mute,
                    fontFamily: 'JetBrains Mono, ui-monospace, monospace',
                  }}
                >{p}</button>
              ))}
            </div>
          </div>
          <HeatmapRibbon thHigh={thHigh} thCrit={thCrit} proto={ribbonProto} />
        </div>
      )}
    </div>
  )
}
