import { useMemo } from 'react'
import { useModuleSize } from '../grid/GridContainer'
import { G3, sevCol, alpha } from '../grid/g3'
import type { Alert } from '../../types'

interface Props {
  alerts: Alert[]
  t:      number
  setT:   (t: number) => void
}

interface Lane { ip: string; peak: string; events: Alert[] }

export function ModTimeline({ alerts, t, setT }: Props) {
  const { w, h } = useModuleSize()
  const laneCount  = h < 180 ? 3 : h < 280 ? 5 : 7
  const showLabels = w > 380

  // Build per-IP swim lanes (HIGH+ only, most events first)
  const lanes = useMemo<Lane[]>(() => {
    const map = new Map<string, Alert[]>()
    for (const a of alerts) {
      if (a.verdict.severity === 'INFO') continue
      const prev = map.get(a.src_ip) ?? []
      prev.push(a)
      map.set(a.src_ip, prev)
    }
    return Array.from(map.entries())
      .sort((a, b) => b[1].length - a[1].length)
      .slice(0, laneCount)
      .map(([ip, as]) => {
        const peak = as.reduce((m, a) =>
          a.verdict.confidence > m.verdict.confidence ? a : m, as[0])
        return { ip, peak: peak.verdict.severity as string, events: as }
      })
  }, [alerts, laneCount])

  // Map flow timestamps to [0,100] x-axis
  const tsRange = useMemo(() => {
    if (alerts.length === 0) return { min: 0, span: 1 }
    const tss = alerts.map(a => a.ts)
    const min = Math.min(...tss)
    const max = Math.max(...tss)
    return { min, span: Math.max(max - min, 1) }
  }, [alerts])

  const toX = (ts: number) =>
    Math.min(95, Math.max(2, ((ts - tsRange.min) / tsRange.span) * 100))

  // Mini histogram: divide time range into 40 buckets
  const histogram = useMemo(() => {
    return Array.from({ length: 40 }, (_, i) => {
      const lo   = tsRange.min + tsRange.span * (i / 40)
      const hi   = tsRange.min + tsRange.span * ((i + 1) / 40)
      const buck = alerts.filter(a => a.verdict.severity !== 'INFO' && a.ts >= lo && a.ts < hi)
      const hasCrit = buck.some(a => a.verdict.severity === 'CRITICAL')
      const hasHigh = buck.some(a => a.verdict.severity === 'HIGH')
      return {
        h:   Math.min(buck.length / 4, 1),
        col: hasCrit ? G3.crit : hasHigh ? G3.high : G3.accent,
      }
    })
  }, [alerts, tsRange])

  return (
    <div style={{ padding: 10, height: '100%', width: '100%', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      {/* Swim lanes */}
      <div style={{ flex: 1, position: 'relative', minHeight: 0 }}>
        {lanes.length === 0 && (
          <div style={{ color: G3.mute, fontSize: 10, padding: 8 }}>No events to display</div>
        )}
        {lanes.map(lane => {
          return (
            <div key={lane.ip} style={{
              display: 'grid',
              gridTemplateColumns: showLabels ? '80px 1fr' : '1fr',
              alignItems: 'center',
              height: `${100 / laneCount}%`,
              borderBottom: `1px solid ${G3.lineSoft}`,
            }}>
              {showLabels && (
                <span style={{ fontFamily: 'JetBrains Mono, ui-monospace, monospace', fontSize: 9, color: G3.mute2, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {lane.ip}
                </span>
              )}
              <div style={{ position: 'relative', height: '65%', background: G3.card2, borderRadius: 3 }}>
                {/* Scrubber line */}
                <div style={{ position: 'absolute', top: 0, bottom: 0, left: `${t}%`, width: 1, background: G3.accent, opacity: 0.6 }} />
                {/* Event dots */}
                {lane.events.map(a => {
                  const x = toX(a.ts)
                  const c = sevCol(a.verdict.severity)
                  const r = a.verdict.severity === 'CRITICAL' ? 5 : 4
                  return (
                    <div
                      key={a.flow_id}
                      title={`${a.src_ip} → ${a.dst_ip}:${a.dst_port} (${a.verdict.confidence.toFixed(2)})`}
                      style={{
                        position: 'absolute', left: `${x}%`, top: '50%',
                        transform: 'translate(-50%, -50%)',
                        width: r * 2, height: r * 2, borderRadius: '50%',
                        background: c, boxShadow: `0 0 0 3px ${alpha(c, 20)}`,
                        cursor: 'default',
                      }}
                    />
                  )
                })}
              </div>
            </div>
          )
        })}
      </div>

      {/* Mini histogram */}
      <div style={{ marginTop: 6, position: 'relative', height: 16, background: G3.card2, borderRadius: 3, display: 'flex', alignItems: 'end', padding: 1, gap: 1 }}>
        {histogram.map((bar, i) => (
          <div key={i} style={{ flex: 1, height: `${Math.max(bar.h * 100, 8)}%`, background: bar.col, opacity: 0.6, borderRadius: 1 }} />
        ))}
        <div style={{ position: 'absolute', top: -2, bottom: -2, left: `${t}%`, width: 2, background: G3.accent, borderRadius: 1 }} />
      </div>

      <input
        type="range" min={0} max={100} value={t}
        onChange={e => setT(+e.target.value)}
        style={{ width: '100%', marginTop: 2, accentColor: G3.accent }}
      />
    </div>
  )
}
