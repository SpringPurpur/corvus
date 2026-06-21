import { useModuleSize } from '../grid/GridContainer'
import { G3 } from '../grid/g3'
import type { OifMetrics } from '../../types'

// Fixed OIF window sizes
const WINDOWS = [
  { label: 'fast',   target: 256  },
  { label: 'med',    target: 1024 },
] as const

interface Props {
  tcpHealth:   OifMetrics
  udpHealth:   OifMetrics
  baselineTcp: number
  baselineUdp: number
}

export function ModHealth({ tcpHealth, udpHealth, baselineTcp, baselineUdp }: Props) {
  const { w } = useModuleSize()

  const protos: [string, OifMetrics, number][] = [
    ['TCP', tcpHealth, baselineTcp],
    ['UDP', udpHealth, baselineUdp],
  ]

  return (
    <div style={{ padding: 10, height: '100%', display: 'flex', flexDirection: 'column', gap: 8, overflow: 'hidden' }}>
      {protos.map(([proto, h, slowTarget]) => {
        const rejCol = h.rejection_rate > 0.15 ? G3.crit : h.rejection_rate > 0.05 ? G3.high : G3.ok
        const recent = h.score_recent.length > 0 ? h.score_recent : Array(20).fill(0)
        const max    = Math.max(...recent, 0.01)
        const pts    = recent
          .map((v, i) => `${i * (100 / Math.max(recent.length - 1, 1))},${12 - (v / max) * 10}`)
          .join(' ')

        const allWindows = [...WINDOWS, { label: 'slow', target: slowTarget }]

        return (
          <div key={proto} style={{ flex: 1, minHeight: 0 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, marginBottom: 2 }}>
              <span style={{ color: G3.fg, fontWeight: 600 }}>{proto}</span>
              <span style={{ color: rejCol, fontFamily: 'JetBrains Mono, ui-monospace, monospace' }}>
                {(h.rejection_rate * 100).toFixed(1)}% rej
              </span>
            </div>

            {/* Per-window baseline progress bars */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 2, marginBottom: 4 }}>
              {allWindows.map(({ label, target }) => {
                const pct = Math.min(h.n_trained / target, 1)
                const col = pct >= 1 ? G3.ok : pct >= 0.5 ? G3.high : G3.mute
                return (
                  <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <span style={{ fontSize: 8, color: G3.mute, fontFamily: 'JetBrains Mono, ui-monospace, monospace', width: 26, flexShrink: 0 }}>{label}</span>
                    <div style={{ flex: 1, height: 3, background: G3.line, borderRadius: 2 }}>
                      <div style={{ width: `${pct * 100}%`, height: '100%', background: col, borderRadius: 2, transition: 'width 0.4s' }} />
                    </div>
                    <span style={{ fontSize: 8, color: G3.mute, fontFamily: 'JetBrains Mono, ui-monospace, monospace', width: 22, textAlign: 'right', flexShrink: 0 }}>
                      {pct >= 1 ? '✓' : `${Math.round(pct * 100)}%`}
                    </span>
                  </div>
                )
              })}
            </div>

            {/* Rejection-rate sparkline */}
            <svg viewBox="0 0 100 14" preserveAspectRatio="none" style={{ width: '100%', height: 12, display: 'block' }}>
              <polyline points={pts} fill="none" stroke={rejCol} strokeWidth="1" vectorEffect="non-scaling-stroke" />
            </svg>
          </div>
        )
      })}

      {w > 160 && (
        <div style={{ fontSize: 9, color: G3.mute, fontFamily: 'JetBrains Mono, ui-monospace, monospace', lineHeight: 1.5 }}>
          TCP p50 <span style={{ color: G3.fg }}>{tcpHealth.score_p50.toFixed(2)}</span>
          {' '}· p95 <span style={{ color: G3.fg }}>{tcpHealth.score_p95.toFixed(2)}</span>
        </div>
      )}
    </div>
  )
}
