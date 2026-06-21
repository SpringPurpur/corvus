import { useMemo, useState } from 'react'
import { useModuleSize } from '../grid/GridContainer'
import { G3 } from '../grid/g3'
import type { Alert } from '../../types'

// Well-known ports to always show; supplemented by top ports from real traffic
const ANCHOR_PORTS = [443, 80, 22, 445, 53, 3389, 8080, 8443]

interface Props { alerts: Alert[] }

interface Cell {
  v:       number
  col:     string
  tooltip: string
}

function fmtTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

export function ModHeatmap({ alerts }: Props) {
  const { w, h } = useModuleSize()
  const maxRows = h < 140 ? 3 : h < 200 ? 5 : 8
  const buckets = w < 400 ? 12 : w < 700 ? 20 : 30
  const showPortLabels = w > 100
  const showTimeLabels = h > 80

  const [tooltip, setTooltip] = useState<{ text: string; x: number; y: number } | null>(null)

  // Build port list: top ports from traffic merged with anchor list
  const ports = useMemo<number[]>(() => {
    const counts = new Map<number, number>()
    for (const a of alerts) counts.set(a.dst_port, (counts.get(a.dst_port) ?? 0) + 1)
    const byTraffic = Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1])
      .map(([p]) => p)
    return [...new Set([...byTraffic, ...ANCHOR_PORTS])].slice(0, maxRows)
  }, [alerts, maxRows])

  const tsRange = useMemo(() => {
    if (alerts.length === 0) return { min: 0, span: 1 }
    const tss = alerts.map(a => a.ts)
    const min = Math.min(...tss)
    const max = Math.max(...tss)
    return { min, span: Math.max(max - min, 1) }
  }, [alerts])

  // Time labels for columns (first, some midpoints, last)
  const timeLabels = useMemo(() => {
    if (alerts.length === 0) return []
    const indices = buckets <= 12
      ? [0, buckets - 1]
      : [0, Math.floor(buckets / 2), buckets - 1]
    return indices.map(i => ({
      i,
      label: fmtTime(tsRange.min + tsRange.span * ((i + 0.5) / buckets)),
    }))
  }, [alerts, buckets, tsRange])

  // For each port × bucket: intensity + color + tooltip
  const grid = useMemo<Cell[][]>(() =>
    ports.map(port =>
      Array.from({ length: buckets }, (_, bi) => {
        const lo    = tsRange.min + tsRange.span * (bi / buckets)
        const hi    = tsRange.min + tsRange.span * ((bi + 1) / buckets)
        const cells = alerts.filter(a => a.dst_port === port && a.ts >= lo && a.ts < hi)

        if (cells.length === 0) return { v: 0, col: G3.line, tooltip: '' }

        const hasCrit  = cells.some(a => a.verdict.severity === 'CRITICAL')
        const hasHigh  = cells.some(a => a.verdict.severity === 'HIGH')
        const v        = Math.min(cells.length / 5, 1)
        const col      = hasCrit ? G3.crit : hasHigh ? G3.high : G3.accent

        // Build tooltip: unique src IPs + counts
        const srcCounts = new Map<string, number>()
        for (const a of cells) srcCounts.set(a.src_ip, (srcCounts.get(a.src_ip) ?? 0) + 1)
        const topSrcs = Array.from(srcCounts.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, 4)
          .map(([ip, c]) => `${ip} ×${c}`)
        const critN   = cells.filter(a => a.verdict.severity === 'CRITICAL').length
        const timeStr = `${fmtTime(lo)} – ${fmtTime(hi)}`
        const parts   = [
          `Port ${port} · ${timeStr}`,
          `${cells.length} flow${cells.length !== 1 ? 's' : ''}${critN ? ` · ${critN} critical` : ''}`,
          ...topSrcs,
        ]

        return { v, col, tooltip: parts.join('\n') }
      }),
    ),
    [alerts, ports, buckets, tsRange],
  )

  return (
    <div style={{ padding: 10, height: '100%', width: '100%', display: 'flex', flexDirection: 'column', gap: 4, boxSizing: 'border-box' }}>
      <div style={{ display: 'grid', gridTemplateColumns: showPortLabels ? '38px 1fr' : '1fr', gap: 6, flex: 1, minHeight: 0 }}>
        {/* Port labels */}
        {showPortLabels && (
          <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-around', fontSize: 9, color: G3.mute, fontFamily: 'JetBrains Mono, ui-monospace, monospace' }}>
            {ports.map(p => <span key={p}>{p}</span>)}
          </div>
        )}

        {/* Heat cells */}
        <div style={{ display: 'grid', gridTemplateRows: `repeat(${ports.length}, 1fr)`, gap: 2, minHeight: 0 }}>
          {grid.map((row, ri) => (
            <div key={ports[ri]} style={{ display: 'grid', gridTemplateColumns: `repeat(${buckets}, 1fr)`, gap: 2 }}>
              {row.map((cell, ci) => (
                <div
                  key={ci}
                  onMouseEnter={cell.tooltip ? e => {
                    const rect = e.currentTarget.getBoundingClientRect()
                    setTooltip({ text: cell.tooltip, x: rect.left, y: rect.top })
                  } : undefined}
                  onMouseLeave={cell.tooltip ? () => setTooltip(null) : undefined}
                  style={{
                    background:   cell.col,
                    opacity:      cell.v > 0 ? 0.3 + cell.v * 0.7 : 0.1,
                    borderRadius: 1,
                    cursor:       cell.tooltip ? 'pointer' : 'default',
                  }}
                  title={cell.tooltip || undefined}
                />
              ))}
            </div>
          ))}
        </div>
      </div>

      {/* Time labels */}
      {showTimeLabels && timeLabels.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: showPortLabels ? '38px 1fr' : '1fr', gap: 6 }}>
          {showPortLabels && <div />}
          <div style={{ position: 'relative', height: 12 }}>
            {timeLabels.map(({ i, label }) => (
              <span
                key={i}
                style={{
                  position: 'absolute',
                  left: `${(i / buckets) * 100}%`,
                  fontSize: 8, color: G3.mute,
                  fontFamily: 'JetBrains Mono, ui-monospace, monospace',
                  transform: 'translateX(-50%)',
                  whiteSpace: 'nowrap',
                }}
              >
                {label}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Floating tooltip overlay */}
      {tooltip && (
        <div style={{
          position: 'fixed',
          left:     tooltip.x + 10,
          top:      tooltip.y - 10,
          background: G3.card2,
          border:   `1px solid ${G3.line}`,
          borderRadius: 5,
          padding: '6px 10px',
          fontSize: 10,
          color: G3.mute2,
          fontFamily: 'JetBrains Mono, ui-monospace, monospace',
          lineHeight: 1.7,
          zIndex: 1000,
          pointerEvents: 'none',
          whiteSpace: 'pre',
          boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
          maxWidth: 280,
        }}>
          {tooltip.text}
        </div>
      )}
    </div>
  )
}
