// ModelHealth.tsx — OIF detector health panel showing poisoning defence activity,
// score distributions, and memory/forgetting characteristics per protocol.
//
// Rejection rate is the key signal: a rising rate means anomalous flows are being
// withheld from training — the poisoning defence is active. A falling rate after
// an attack ends reflects the window forgetting the attack distribution.

import type { OifMetrics, AppConfig, Alert } from '../types'
import { WindowConsensus } from './WindowConsensus'
import { HeatmapRibbon } from './HeatmapRibbon'

// Histogram of composite scores binned into 20 buckets.
// Dashed threshold lines mark HIGH and CRITICAL cutoffs.
function ScoreHistogram({ alerts, thHigh, thCrit }: {
  alerts: Alert[]
  thHigh: number
  thCrit: number
}) {
  if (alerts.length === 0) return null

  const BINS = 20
  const W    = BINS * 10   // viewBox units
  const H    = 40

  const counts = new Array(BINS).fill(0)
  for (const a of alerts) {
    const bin = Math.min(Math.floor(a.verdict.confidence * BINS), BINS - 1)
    counts[bin]++
  }
  const maxCount = Math.max(...counts, 1)

  return (
    <div>
      <div className="text-[10px] text-muted-foreground mb-1">
        Score distribution{' '}
        <span className="tabular-nums">({alerts.length.toLocaleString()} flows)</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height: H }}>
        {counts.map((c, i) => {
          const barH  = Math.max((c / maxCount) * (H - 2), c > 0 ? 1 : 0)
          const binMid = (i + 0.5) / BINS
          const fill  =
            binMid >= thCrit ? 'var(--color-score-crit)' :
            binMid >= thHigh ? 'var(--color-score-high)' :
                               'var(--color-score-normal)'
          return (
            <rect key={i}
              x={i * 10 + 0.5} y={H - barH} width={9} height={barH}
              fill={fill} rx={1}
            >
              <title>
                {c} flow{c !== 1 ? 's' : ''} · {((i / BINS) * 100).toFixed(0)}–{(((i + 1) / BINS) * 100).toFixed(0)}%
              </title>
            </rect>
          )
        })}
        {/* HIGH threshold */}
        <line
          x1={thHigh * W} y1={0} x2={thHigh * W} y2={H}
          stroke="var(--color-score-high)" strokeWidth={1.5}
          strokeDasharray="3 2" opacity={0.9}
        />
        {/* CRITICAL threshold */}
        <line
          x1={thCrit * W} y1={0} x2={thCrit * W} y2={H}
          stroke="var(--color-score-crit)" strokeWidth={1.5}
          strokeDasharray="3 2" opacity={0.9}
        />
      </svg>
      <div className="flex justify-between text-[10px] text-muted-foreground mt-0.5">
        <span>0</span><span>0.5</span><span>1.0</span>
      </div>
    </div>
  )
}

interface Props {
  tcp:       OifMetrics
  udp:       OifMetrics
  config:    AppConfig
  tcpAlerts: Alert[]
  udpAlerts: Alert[]
}

function rejectionBadge(rate: number) {
  if (rate > 0.30) return {
    label: 'Attack likely active',
    bg:  'var(--color-badge-danger-bg)',
    fg:  'var(--color-badge-danger-text)',
    bdr: 'var(--color-badge-danger-bdr)',
  }
  if (rate > 0.10) return {
    label: 'Elevated',
    bg:  'var(--color-badge-warn-bg)',
    fg:  'var(--color-badge-warn-text)',
    bdr: 'var(--color-badge-warn-bdr)',
  }
  return {
    label: 'Nominal',
    bg:  'hsl(var(--muted))',
    fg:  'hsl(var(--muted-foreground))',
    bdr: 'hsl(var(--border))',
  }
}

function ScoreSparkline({ scores, thHigh, thCrit }: { scores: number[]; thHigh: number; thCrit: number }) {
  if (!scores.length) return <span className="text-xs text-muted-foreground italic">No data yet</span>

  return (
    <div className="flex items-end gap-0.5 h-8">
      {scores.map((s, i) => {
        const height = Math.max(s * 100, 4)
        const colour =
          s >= thCrit ? 'var(--color-score-crit)' :
          s >= thHigh ? 'var(--color-score-high)' :
                        'var(--color-score-normal)'
        return (
          <div
            key={i}
            title={`${(s * 100).toFixed(1)}%`}
            className="flex-1"
            style={{
              height: `${height}%`,
              backgroundColor: colour,
              borderRadius: 'calc(var(--radius) / 2)',
            }}
          />
        )
      })}
    </div>
  )
}

function ProtocolPanel({ label, proto, m, alerts, thHigh, thCrit, config }: {
  label: string; proto: 'TCP' | 'UDP'; m: OifMetrics; alerts: Alert[]
  thHigh: number; thCrit: number; config: AppConfig
}) {
  const badge   = rejectionBadge(m.rejection_rate)
  const trained  = m.n_seen > 0 ? (m.n_trained  / m.n_seen) * 100 : 0
  const rejected = m.n_seen > 0 ? (m.n_rejected / m.n_seen) * 100 : 0

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{label}</h3>
        <span
          className="text-[10px] px-2 py-0.5 border font-medium"
          style={{
            backgroundColor: badge.bg,
            color: badge.fg,
            borderColor: badge.bdr,
            borderRadius: 'var(--radius)',
          }}
        >
          {m.ready ? badge.label : 'Baselining…'}
        </span>
      </div>

      {/* Flow counts */}
      <div className="grid grid-cols-3 gap-2 text-xs text-center">
        <div>
          <div className="text-foreground font-medium tabular-nums">{m.n_seen.toLocaleString()}</div>
          <div className="text-muted-foreground text-[10px]">seen</div>
        </div>
        <div>
          <div className="font-medium tabular-nums" style={{ color: 'var(--color-count-trained)' }}>
            {m.n_trained.toLocaleString()}
          </div>
          <div className="text-muted-foreground text-[10px]">trained</div>
        </div>
        <div>
          <div className="font-medium tabular-nums" style={{ color: 'var(--color-count-rejected)' }}>
            {m.n_rejected.toLocaleString()}
          </div>
          <div className="text-muted-foreground text-[10px]">rejected</div>
        </div>
      </div>

      {/* Trained / rejected split bar */}
      <div>
        <div className="flex h-2 overflow-hidden bg-muted" style={{ borderRadius: 'var(--radius)' }}>
          <div
            className="transition-all"
            style={{ width: `${trained}%`, backgroundColor: 'var(--color-trained)' }}
          />
          <div
            className="transition-all"
            style={{ width: `${rejected}%`, backgroundColor: 'var(--color-rejected)' }}
          />
        </div>
        <div className="flex justify-between text-[10px] text-muted-foreground mt-0.5">
          <span>trained {trained.toFixed(1)}%</span>
          <span>rejected {rejected.toFixed(1)}%</span>
        </div>
      </div>

      {/* Score distribution */}
      <div className="flex items-center gap-3 text-xs">
        <div className="flex gap-2">
          <span className="text-muted-foreground">p50</span>
          <span className="tabular-nums font-medium">{(m.score_p50 * 100).toFixed(1)}%</span>
        </div>
        <div className="flex gap-2">
          <span className="text-muted-foreground">p95</span>
          <span className="tabular-nums font-medium">{(m.score_p95 * 100).toFixed(1)}%</span>
        </div>
      </div>

      {/* Score distribution histogram */}
      {alerts.length > 0 && (
        <ScoreHistogram alerts={alerts} thHigh={thHigh} thCrit={thCrit} />
      )}

      {/* Sparkline — last 20 composite scores */}
      <div>
        <div className="text-[10px] text-muted-foreground mb-1">Recent scores</div>
        <ScoreSparkline scores={m.score_recent} thHigh={thHigh} thCrit={thCrit} />
      </div>

      {/* Per-window consensus heatmap + divergence sparkline */}
      {alerts.length > 0 && (
        <div>
          <div className="text-[10px] text-muted-foreground mb-1.5">Window consensus</div>
          <WindowConsensus alerts={alerts} thHigh={thHigh} thCrit={thCrit} />
        </div>
      )}

      {/* 24 h heatmap ribbon */}
      <div>
        <div className="text-[10px] text-muted-foreground mb-1.5">Score history (24 h)</div>
        <HeatmapRibbon proto={proto} config={config} />
      </div>
    </div>
  )
}

export function ModelHealth({ tcp, udp, config, tcpAlerts, udpAlerts }: Props) {
  return (
    <div className="p-4 space-y-6 overflow-y-auto h-full text-sm">

      <ProtocolPanel label="TCP detector" proto="TCP" m={tcp} alerts={tcpAlerts}
        thHigh={config.threshold_high} thCrit={config.threshold_critical} config={config} />

      <div className="border-t border-border" />

      <ProtocolPanel label="UDP detector" proto="UDP" m={udp} alerts={udpAlerts}
        thHigh={config.threshold_high} thCrit={config.threshold_critical} config={config} />

      {/* Window memory reference */}
      <div className="border-t border-border pt-3 text-[10px] text-muted-foreground space-y-1">
        <div className="font-medium text-foreground text-xs mb-1">Window memory</div>
        <div>Fast  (256 flows) — adapts quickly, forgets quickly</div>
        <div>Medium (1 024 flows) — balanced adaptation</div>
        <div>Slow  (4 096 flows) — resistant to poisoning, slow to forget</div>
        <div className="pt-1 opacity-70">
          Composite = 20% fast + 30% medium + 50% slow.
          Flows scoring ≥ {(config.threshold_high * 100).toFixed(0)}% are withheld from training.
        </div>
      </div>
    </div>
  )
}
