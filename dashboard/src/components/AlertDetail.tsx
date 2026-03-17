import type { Alert, AttributionEntry } from '../types'

interface Props {
  alert: Alert
}

function AttributionBar({ entry }: { entry: AttributionEntry }) {
  const pct = Math.min(entry.score * 100, 100)
  const hasBaseline = entry.baseline?.median !== undefined

  // Format raw value: show integers without decimals, floats to 2 dp
  const fmt = (n: number) =>
    Number.isInteger(n) ? n.toString() : n.toFixed(2)

  return (
    <div className="space-y-0.5">
      <div className="flex items-center gap-2 text-xs">
        <span className="w-36 truncate text-muted-foreground text-right">{entry.feature}</span>
        <div className="flex-1 bg-muted rounded-full h-2 overflow-hidden">
          <div className="h-full rounded-full bg-blue-500" style={{ width: `${pct}%` }} />
        </div>
        <span className="w-10 tabular-nums text-right text-muted-foreground">{(pct).toFixed(0)}%</span>
      </div>
      <div className="flex text-[10px] text-muted-foreground/70 pl-[152px] gap-3">
        <span>value <span className="text-foreground tabular-nums">{fmt(entry.value)}</span></span>
        {hasBaseline && (
          <span>
            baseline <span className="tabular-nums">{fmt(entry.baseline.median)}</span>
            <span className="opacity-60"> ±{fmt(entry.baseline.iqr)}</span>
          </span>
        )}
      </div>
    </div>
  )
}

export function AlertDetail({ alert }: Props) {
  const { verdict, scores, attribution, src_ip, src_port, dst_ip, dst_port, proto, duration, fwd_pkts } = alert

  return (
    <div className="p-4 space-y-4 text-sm overflow-y-auto h-full">
      {/* Flow info */}
      <section>
        <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Flow</h3>
        <div className="grid grid-cols-2 gap-1 text-xs">
          <span className="text-muted-foreground">Protocol</span><span>{proto}</span>
          <span className="text-muted-foreground">Source</span><span className="font-mono">{src_ip}:{src_port}</span>
          <span className="text-muted-foreground">Destination</span><span className="font-mono">{dst_ip}:{dst_port}</span>
          <span className="text-muted-foreground">Duration</span><span>{duration.toFixed(3)}s</span>
          <span className="text-muted-foreground">Fwd packets</span><span>{fwd_pkts}</span>
        </div>
      </section>

      {/* Anomaly verdict */}
      <section>
        <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Anomaly detection</h3>
        <div className="grid grid-cols-2 gap-1 text-xs">
          <span className="text-muted-foreground">Level</span>
          <span className="font-medium">{verdict.label}</span>
          <span className="text-muted-foreground">Composite score</span>
          <span className="tabular-nums">{(verdict.confidence * 100).toFixed(1)}%</span>
        </div>
      </section>

      {/* OIF window breakdown */}
      {scores && (
        <section>
          <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Window scores</h3>
          <div className="space-y-1">
            {([
              ['Fast  (256)',  scores.fast,      0.20],
              ['Medium (1k)',  scores.medium,    0.30],
              ['Slow  (4k)',   scores.slow,      0.50],
            ] as [string, number, number][]).map(([label, score, weight]) => (
              <div key={label} className="flex items-center gap-2 text-xs">
                <span className="w-24 text-muted-foreground text-right">{label}</span>
                <div className="flex-1 bg-muted rounded-full h-1.5 overflow-hidden">
                  <div
                    className="h-full rounded-full bg-indigo-500"
                    style={{ width: `${Math.min(score * 100, 100)}%` }}
                  />
                </div>
                <span className="w-10 tabular-nums text-right">{(score * 100).toFixed(1)}%</span>
                <span className="w-8 text-muted-foreground/60 text-right text-[10px]">×{weight}</span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Path attribution */}
      {attribution && attribution.length > 0 && (
        <section>
          <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
            Path attribution
          </h3>
          <p className="text-[10px] text-muted-foreground/60 mb-2">
            Features at shallower tree depth isolated this flow from baseline traffic in fewer cuts.
          </p>
          <div className="space-y-2">
            {attribution.map((entry) => (
              <AttributionBar key={entry.feature} entry={entry} />
            ))}
          </div>
        </section>
      )}
    </div>
  )
}
