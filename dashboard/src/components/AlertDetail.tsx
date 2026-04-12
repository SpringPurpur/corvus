import type { Alert, AttributionEntry, PipelineTiming } from '../types'
import { FeatureRadar } from './FeatureRadar'

// Horizontal track showing where the flow's feature value sits relative to
// the baseline median ± IQR. The track is always scaled to include both
// the IQR zone and the actual value. Red dot = outside IQR, blue = inside.
function BaselinePositionBar({ value, median, iqr }: {
  value: number; median: number; iqr: number
}) {
  const halfSpan = Math.max(iqr * 2.5, Math.abs(value - median) * 1.25, 1e-9)
  const lo = median - halfSpan
  const hi = median + halfSpan
  const toX = (v: number) => Math.max(1, Math.min(99, ((v - lo) / (hi - lo)) * 100))

  const medX  = toX(median)
  const valX  = toX(value)
  const iqrLo = toX(median - iqr / 2)
  const iqrHi = toX(median + iqr / 2)
  const outside = Math.abs(value - median) > iqr / 2

  return (
    <svg viewBox="0 0 100 10" className="w-full" style={{ height: 8 }} aria-hidden>
      {/* Track */}
      <rect x={0} y={3.5} width={100} height={3} rx={1.5}
        fill="var(--color-muted, rgba(128,128,128,0.15))" />
      {/* IQR band */}
      <rect x={iqrLo} y={2} width={Math.max(iqrHi - iqrLo, 1)} height={6} rx={1}
        fill="var(--color-bar-secondary)" opacity={0.35} />
      {/* Median tick */}
      <line x1={medX} y1={1} x2={medX} y2={9}
        stroke="var(--color-muted-foreground, #888)" strokeWidth={0.8} opacity={0.6} />
      {/* Value dot */}
      <circle cx={valX} cy={5} r={2.5}
        fill={outside ? 'var(--color-score-crit)' : 'var(--color-bar-primary)'} />
    </svg>
  )
}

interface Props {
  alert:          Alert
  clockOffsetMs?: number   // server_ms − host_ms; corrects container/host clock skew
}

function AttributionBar({ entry }: { entry: AttributionEntry }) {
  const pct = Math.min(entry.score * 100, 100)
  const hasBaseline = entry.baseline?.median !== undefined

  const fmt = (n: number) =>
    Number.isInteger(n) ? n.toString() : n.toFixed(2)

  return (
    <div className="space-y-0.5">
      <div className="flex items-center gap-2 text-xs">
        <span className="w-36 truncate text-muted-foreground text-right">{entry.feature}</span>
        <div className="flex-1 bg-muted h-2 overflow-hidden" style={{ borderRadius: 'var(--radius)' }}>
          <div
            className="h-full"
            style={{ width: `${pct}%`, backgroundColor: 'var(--color-bar-primary)', borderRadius: 'var(--radius)' }}
          />
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
      {hasBaseline && (
        <div className="pl-[152px] pr-[48px] mt-0.5">
          <BaselinePositionBar
            value={entry.value}
            median={entry.baseline.median}
            iqr={entry.baseline.iqr}
          />
        </div>
      )}
    </div>
  )
}

export function AlertDetail({ alert, clockOffsetMs = 0 }: Props) {
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
              ['Fast  (256)',  scores.fast,   0.20],
              ['Medium (1k)',  scores.medium, 0.30],
              ['Slow  (4k)',   scores.slow,   0.50],
            ] as [string, number, number][]).map(([label, score, weight]) => (
              <div key={label} className="flex items-center gap-2 text-xs">
                <span className="w-24 text-muted-foreground text-right">{label}</span>
                <div className="flex-1 bg-muted h-1.5 overflow-hidden" style={{ borderRadius: 'var(--radius)' }}>
                  <div
                    className="h-full"
                    style={{
                      width: `${Math.min(score * 100, 100)}%`,
                      backgroundColor: 'var(--color-bar-secondary)',
                      borderRadius: 'var(--radius)',
                    }}
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

      {/* Feature radar */}
      {attribution && attribution.length >= 3 && (
        <section>
          <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
            Feature deviation
          </h3>
          <FeatureRadar attribution={attribution} severity={verdict.severity} />
        </section>
      )}

      {/* Pipeline latency */}
      {alert.timing?.t_socket_ns && (
        <section>
          <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
            Pipeline latency
          </h3>
          <LatencyBreakdown timing={alert.timing} clockOffsetMs={clockOffsetMs} />
        </section>
      )}
    </div>
  )
}

function LatencyBreakdown({ timing, clockOffsetMs = 0 }: { timing: PipelineTiming & { t_infer_ns?: number }; clockOffsetMs?: number }) {
  const { t_enqueue_ns, t_socket_ns, t_dequeue_ns, t_scored_ns, t_ws_ns, t_browser_ms, t_infer_ns } = timing

  const ns2ms = (ns: number) => ns / 1_000_000

  // t_enqueue_ns is only valid if it looks like a real nanosecond timestamp
  // (> 1e15 ns ≈ year 2001). Old monitor binaries write flag bytes there
  // (values 1, 257, 65793) which are truthy but not valid timestamps.
  const NS_PLAUSIBLE = 1_000_000_000_000_000
  const ipc_start = (t_enqueue_ns && t_enqueue_ns > NS_PLAUSIBLE) ? t_enqueue_ns : null

  if (!t_socket_ns) return null

  // Build stages from whatever timestamps are available.
  // New containers emit t_dequeue_ns + t_scored_ns (split queue/OIF).
  // Old containers emit t_infer_ns (combined queue+OIF).
  const stages: [string, number][] = []
  if (ipc_start) {
    stages.push(['IPC + decode', ns2ms(t_socket_ns) - ns2ms(ipc_start)])
  }
  if (t_dequeue_ns && t_scored_ns) {
    stages.push(['Queue wait',  ns2ms(t_dequeue_ns) - ns2ms(t_socket_ns)])
    stages.push(['OIF scoring', ns2ms(t_scored_ns)  - ns2ms(t_dequeue_ns)])
  } else if (t_infer_ns) {
    stages.push(['Queue + OIF', ns2ms(t_infer_ns) - ns2ms(t_socket_ns)])
  }
  const lastNs = t_scored_ns ?? t_infer_ns ?? t_socket_ns
  if (t_ws_ns && t_browser_ms) {
    // Subtract clockOffsetMs to convert the container timestamp to host time
    // before differencing with Date.now(). Without this, WSL2/Hyper-V clock
    // skew (container ahead of host) produces negative "WS → browser" values.
    stages.push(['WS → browser', t_browser_ms - (ns2ms(t_ws_ns) - clockOffsetMs)])
  }
  if (stages.length === 0) return null
  const pipelineStart = ipc_start ?? t_socket_ns
  const total = t_browser_ms
    ? t_browser_ms - (ns2ms(pipelineStart) - clockOffsetMs)
    : ns2ms(lastNs) - ns2ms(pipelineStart)
  const maxStage = Math.max(...stages.map(([, v]) => v), 0.001)  // prevent /0

  return (
    <div className="space-y-1">
      {stages.map(([label, ms]) => (
        <div key={label} className="flex items-center gap-2 text-xs">
          <span className="w-28 text-muted-foreground text-right shrink-0">{label}</span>
          <div className="flex-1 bg-muted h-1.5 overflow-hidden" style={{ borderRadius: 'var(--radius)' }}>
            <div
              className="h-full"
              style={{
                width: `${Math.min(Math.max((ms / maxStage) * 100, 0), 100)}%`,
                backgroundColor: 'var(--color-bar-latency)',
                borderRadius: 'var(--radius)',
              }}
            />
          </div>
          <span className="w-14 tabular-nums text-right">{ms.toFixed(2)} ms</span>
        </div>
      ))}
      <div className="flex justify-between text-[10px] text-muted-foreground/70 pt-1 border-t border-border">
        <span>Total</span>
        <span className="tabular-nums font-medium text-foreground">{total.toFixed(2)} ms</span>
      </div>
    </div>
  )
}
