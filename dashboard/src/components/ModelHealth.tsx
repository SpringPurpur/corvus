// ModelHealth.tsx — OIF detector health panel showing poisoning defence activity,
// score distributions, and memory/forgetting characteristics per protocol.
//
// Rejection rate is the key signal: a rising rate means anomalous flows are being
// withheld from training — the poisoning defence is active. A falling rate after
// an attack ends reflects the window forgetting the attack distribution.

import type { OifMetrics, AppConfig } from '../types'
import { cn } from '../lib/utils'

interface Props {
  tcp: OifMetrics
  udp: OifMetrics
  config: AppConfig
}

function rejectionBadge(rate: number) {
  if (rate > 0.30) return { label: 'Attack likely active', cls: 'bg-red-500/20 text-red-400 border-red-500/30' }
  if (rate > 0.10) return { label: 'Elevated',             cls: 'bg-amber-500/20 text-amber-400 border-amber-500/30' }
  return                  { label: 'Nominal',              cls: 'bg-muted text-muted-foreground border-border' }
}

function ScoreSparkline({ scores, thHigh, thCrit }: { scores: number[]; thHigh: number; thCrit: number }) {
  if (!scores.length) return <span className="text-xs text-muted-foreground italic">No data yet</span>

  return (
    <div className="flex items-end gap-0.5 h-8">
      {scores.map((s, i) => {
        const height = Math.max(s * 100, 4)
        const colour =
          s >= thCrit ? 'bg-red-500' :
          s >= thHigh ? 'bg-amber-500' :
                        'bg-blue-500'
        return (
          <div
            key={i}
            title={`${(s * 100).toFixed(1)}%`}
            className={cn('flex-1 rounded-sm', colour)}
            style={{ height: `${height}%` }}
          />
        )
      })}
    </div>
  )
}

function ProtocolPanel({ label, m, thHigh, thCrit }: {
  label: string; m: OifMetrics; thHigh: number; thCrit: number
}) {
  const badge   = rejectionBadge(m.rejection_rate)
  const trained = m.n_seen > 0 ? (m.n_trained / m.n_seen) * 100 : 0
  const rejected = m.n_seen > 0 ? (m.n_rejected / m.n_seen) * 100 : 0

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{label}</h3>
        <span className={cn('text-[10px] px-2 py-0.5 rounded-full border font-medium', badge.cls)}>
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
          <div className="text-emerald-400 font-medium tabular-nums">{m.n_trained.toLocaleString()}</div>
          <div className="text-muted-foreground text-[10px]">trained</div>
        </div>
        <div>
          <div className="text-amber-400 font-medium tabular-nums">{m.n_rejected.toLocaleString()}</div>
          <div className="text-muted-foreground text-[10px]">rejected</div>
        </div>
      </div>

      {/* Trained / rejected split bar */}
      <div>
        <div className="flex h-2 rounded-full overflow-hidden bg-muted">
          <div className="bg-emerald-500 transition-all" style={{ width: `${trained}%` }} />
          <div className="bg-amber-500 transition-all"   style={{ width: `${rejected}%` }} />
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

      {/* Sparkline — last 20 composite scores */}
      <div>
        <div className="text-[10px] text-muted-foreground mb-1">Recent scores</div>
        <ScoreSparkline scores={m.score_recent} thHigh={thHigh} thCrit={thCrit} />
      </div>
    </div>
  )
}

export function ModelHealth({ tcp, udp, config }: Props) {
  return (
    <div className="p-4 space-y-6 overflow-y-auto h-full text-sm">

      <ProtocolPanel label="TCP detector" m={tcp}
        thHigh={config.threshold_high} thCrit={config.threshold_critical} />

      <div className="border-t border-border" />

      <ProtocolPanel label="UDP detector" m={udp}
        thHigh={config.threshold_high} thCrit={config.threshold_critical} />

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