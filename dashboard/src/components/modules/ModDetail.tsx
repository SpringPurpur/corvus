import { useModuleSize } from '../grid/GridContainer'
import { G3, sevCol, sevBg } from '../grid/g3'
import type { Alert, AttributionEntry, FeedbackMsg, LlmRequestMsg } from '../../types'

// ── Inline FeatureRadar ──────────────────────────────────────────────────────

const MAX_FEATURES = 6
const MAX_DEV      = 4
const CX = 100, CY = 100, R = 72
const PREFIX_RE    = /^(fwd_|bwd_|flow_)/

function abbrev(name: string): string {
  return name.replace(PREFIX_RE, '').replace(/_/g, ' ').slice(0, 12)
}

function FeatureRadar({ attribution, severity }: { attribution: AttributionEntry[]; severity: string }) {
  const entries = attribution.slice(0, MAX_FEATURES)
  const N = entries.length
  if (N < 3) return null

  const angle = (i: number) => (2 * Math.PI * i) / N - Math.PI / 2

  const devFrac = entries.map(e => {
    const iqr = e.baseline?.iqr ?? 0
    if (iqr < 1e-9) return Math.min(e.score, 1)
    const dev = Math.abs(e.value - (e.baseline?.median ?? 0)) / iqr
    return Math.min(dev / MAX_DEV, 1)
  })

  const toPoints = (fracs: number[]) =>
    fracs.map((f, i) => {
      const a = angle(i)
      return `${(CX + R * f * Math.cos(a)).toFixed(2)},${(CY + R * f * Math.sin(a)).toFixed(2)}`
    }).join(' ')

  const normalFrac = Array<number>(N).fill(1 / MAX_DEV)
  const allAxes    = entries.map((_, i) => angle(i))
  const fillColor  = severity === 'CRITICAL' ? G3.crit : severity === 'HIGH' ? G3.high : G3.accent

  return (
    <svg viewBox="0 0 200 200" style={{ width: '100%', maxHeight: 180 }} aria-label="Feature deviation radar">
      {allAxes.map((a, i) => (
        <line key={i} x1={CX} y1={CY}
          x2={(CX + R * Math.cos(a)).toFixed(2)}
          y2={(CY + R * Math.sin(a)).toFixed(2)}
          stroke={G3.line} strokeWidth="0.5" opacity={0.7}
        />
      ))}
      {[0.25, 0.5, 0.75, 1].map(level => (
        <polygon key={level} points={toPoints(Array<number>(N).fill(level))}
          fill="none" stroke={G3.line}
          strokeWidth={level === 1 ? 0.75 : 0.4} opacity={0.45}
        />
      ))}
      <polygon points={toPoints(normalFrac)}
        fill={G3.ok} fillOpacity={0.12}
        stroke={G3.ok} strokeWidth="1" strokeOpacity={0.5}
      />
      <polygon points={toPoints(devFrac)}
        fill={fillColor} fillOpacity={0.20}
        stroke={fillColor} strokeWidth="1.5" strokeLinejoin="round"
      />
      {entries.map((e, i) => {
        const a      = angle(i)
        const lx     = CX + (R + 16) * Math.cos(a)
        const ly     = CY + (R + 16) * Math.sin(a)
        const anchor = Math.cos(a) > 0.15 ? 'start' : Math.cos(a) < -0.15 ? 'end' : 'middle'
        return (
          <text key={i} x={lx.toFixed(2)} y={ly.toFixed(2)}
            textAnchor={anchor} dominantBaseline="middle"
            fontSize="7.5" fill={G3.mute}
          >
            <title>{e.feature}</title>
            {abbrev(e.feature)}
          </text>
        )
      })}
      <text x="100" y="197" textAnchor="middle" fontSize="6" fill={G3.mute} opacity="0.55">
        grey = 1 IQR · outer = {MAX_DEV} IQRs
      </text>
    </svg>
  )
}

// ── ModDetail ────────────────────────────────────────────────────────────────

interface Props {
  alert: Alert | null
  send:  (msg: FeedbackMsg | LlmRequestMsg) => void
}

export function ModDetail({ alert: a, send }: Props) {
  const { w } = useModuleSize()

  if (!a) return (
    <div style={{ padding: 20, color: G3.mute, fontSize: 11 }}>
      Select an anomaly from the stream
    </div>
  )

  const col      = sevCol(a.verdict.severity)
  const statCols = w < 280 ? 1 : 2

  const dur = a.duration < 1
    ? `${(a.duration * 1000).toFixed(0)}ms`
    : `${a.duration.toFixed(2)}s`

  const handleDismiss = () => {
    send({
      type:            'feedback',
      flow_id:         a.flow_id,
      corrected_label: null,
      dismiss:         true,
      reason:          'Dismissed as false positive',
    })
  }

  const stats: [string, string | number, string][] = [
    ['Score',    a.verdict.confidence.toFixed(2), col],
    ['Packets',  a.fwd_pkts,                      G3.fg],
    ['Duration', dur,                              G3.fg],
    ['Protocol', a.proto,                          G3.fg],
  ]

  const hasRadar = a.attribution?.length >= 3

  return (
    <div style={{ padding: 12, overflowY: 'auto', height: '100%' }}>
      {/* Severity badge */}
      <span style={{
        display: 'inline-block', padding: '2px 8px', borderRadius: 999,
        background: sevBg(a.verdict.severity), color: col,
        fontSize: 9, fontWeight: 600, letterSpacing: '0.04em',
      }}>
        ● {a.verdict.severity}
      </span>

      {/* Endpoint */}
      <div style={{ fontSize: 10, color: G3.mute2, fontFamily: 'JetBrains Mono, ui-monospace, monospace', marginTop: 8, marginBottom: 2, wordBreak: 'break-all' }}>
        {a.src_ip}:{a.src_port} → {a.dst_ip}:{a.dst_port}
      </div>

      {/* Stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: `repeat(${statCols}, 1fr)`, gap: 5, marginBottom: 12 }}>
        {stats.map(([k, v, c]) => (
          <div key={k} style={{ padding: '5px 8px', background: G3.card2, borderRadius: 4 }}>
            <div style={{ fontSize: 8, color: G3.mute, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{k}</div>
            <div style={{ fontSize: 13, fontWeight: 600, color: c, fontFamily: 'JetBrains Mono, ui-monospace, monospace' }}>{v}</div>
          </div>
        ))}
      </div>

      {/* OIF attribution */}
      {a.attribution?.length > 0 && (
        <>
          <div style={{ fontSize: 9, color: G3.mute, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
            Top OIF drivers
          </div>
          {a.attribution.slice(0, 4).map(f => (
            <div key={f.feature} style={{ marginBottom: 6 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, marginBottom: 2, gap: 6 }}>
                <span style={{ fontFamily: 'JetBrains Mono, ui-monospace, monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: G3.mute2 }}>
                  {f.feature}
                </span>
                <span style={{ color: G3.mute, fontFamily: 'JetBrains Mono, ui-monospace, monospace', flexShrink: 0 }}>
                  {typeof f.value === 'number' ? f.value.toFixed(3) : f.value}
                </span>
              </div>
              <div style={{ height: 3, background: G3.line, borderRadius: 2 }}>
                <div style={{
                  width: `${Math.min(f.score * 100, 100)}%`, height: '100%',
                  background: f.score > 0.7 ? G3.crit : G3.high,
                  borderRadius: 2,
                }} />
              </div>
              {f.baseline?.median !== undefined && (
                <div style={{ fontSize: 8, color: G3.mute, marginTop: 1 }}>
                  baseline median {f.baseline.median.toFixed(3)} ± {(f.baseline.iqr / 2).toFixed(3)}
                </div>
              )}
            </div>
          ))}

          {/* Feature radar */}
          {hasRadar && (
            <>
              <div style={{ fontSize: 9, color: G3.mute, textTransform: 'uppercase', letterSpacing: '0.06em', marginTop: 12, marginBottom: 6 }}>
                Feature deviation radar
              </div>
              <FeatureRadar attribution={a.attribution} severity={a.verdict.severity} />
            </>
          )}
        </>
      )}

      {/* Actions */}
      <div style={{ display: 'flex', gap: 4, marginTop: 12, flexWrap: 'wrap' }}>
        <button
          onClick={handleDismiss}
          style={{
            padding: '5px 8px', fontSize: 10,
            background: 'transparent', color: G3.mute2,
            border: `1px solid ${G3.line}`, borderRadius: 4, cursor: 'pointer',
          }}
        >
          Dismiss FP
        </button>
      </div>

      {/* Flow ID */}
      <div style={{ fontSize: 8, color: G3.mute, fontFamily: 'JetBrains Mono, ui-monospace, monospace', marginTop: 12, opacity: 0.5 }}>
        {a.flow_id}
      </div>
    </div>
  )
}
