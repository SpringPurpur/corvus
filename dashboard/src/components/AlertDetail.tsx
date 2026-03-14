import type { Alert } from '../types'

interface Props {
  alert: Alert
}

function ShapBar({ name, score }: { name: string; score: number }) {
  const abs = Math.abs(score)
  const pct = Math.min(abs * 100, 100)
  const colour = score >= 0 ? 'bg-red-500' : 'bg-blue-500'
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="w-36 truncate text-muted-foreground text-right">{name}</span>
      <div className="flex-1 bg-muted rounded-full h-2 overflow-hidden">
        <div
          className={`h-full rounded-full ${colour}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="w-12 tabular-nums text-right">{score.toFixed(3)}</span>
    </div>
  )
}

export function AlertDetail({ alert }: Props) {
  const { verdict, shap, anomaly, src_ip, src_port, dst_ip, dst_port, proto, duration, fwd_pkts } = alert

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

      {/* Verdict */}
      <section>
        <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Verdict</h3>
        <div className="grid grid-cols-2 gap-1 text-xs">
          <span className="text-muted-foreground">Label</span><span className="font-medium">{verdict.label}</span>
          <span className="text-muted-foreground">Confidence</span><span>{(verdict.confidence * 100).toFixed(1)}%</span>
          <span className="text-muted-foreground">Anomaly score</span><span>{anomaly.toFixed(4)}</span>
        </div>
      </section>

      {/* SHAP */}
      {shap.length > 0 && (
        <section>
          <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
            Top features
          </h3>
          <div className="space-y-2">
            {shap.map(([name, , score]) => (
              <ShapBar key={name} name={name} score={score} />
            ))}
          </div>
        </section>
      )}
    </div>
  )
}
