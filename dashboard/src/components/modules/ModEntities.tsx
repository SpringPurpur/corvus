import React, { useMemo } from 'react'
import { useModuleSize } from '../grid/GridContainer'
import { G3, sevCol } from '../grid/g3'
import type { Alert } from '../../types'

interface Props {
  alerts:          Alert[]
  setSelected:     (a: Alert | null) => void
  entityFilter:    string | null
  setEntityFilter: (ip: string | null) => void
  showAll:         boolean
  setShowAll:      (v: boolean) => void
  protoFilter:     Set<'TCP' | 'UDP'>
  setProtoFilter:  (v: Set<'TCP' | 'UDP'>) => void
}

interface EntityRow {
  ip:    string
  peak:  string
  score: number
  spark: number[]
}

export function ModEntities({ alerts, setSelected, entityFilter, setEntityFilter, showAll, setShowAll, protoFilter, setProtoFilter }: Props) {
  const { w } = useModuleSize()
  const showSpark = w > 220
  const showScore = w > 180

  const entities = useMemo<EntityRow[]>(() => {
    let filtered = showAll ? [...alerts] : alerts.filter(a => a.verdict.severity !== 'INFO')
    if (protoFilter.size < 2) filtered = filtered.filter(a => protoFilter.has(a.proto as 'TCP' | 'UDP'))
    const map = new Map<string, Alert[]>()
    for (const a of filtered) {
      const prev = map.get(a.src_ip) ?? []
      prev.push(a)
      map.set(a.src_ip, prev)
    }
    return Array.from(map.entries())
      .map(([ip, as]) => {
        const byScore = [...as].sort((a, b) => b.verdict.confidence - a.verdict.confidence)
        const peak    = byScore[0]
        const spark   = [...as].sort((a, b) => a.ts - b.ts).slice(-8).map(a => a.verdict.confidence)
        return { ip, peak: peak.verdict.severity, score: peak.verdict.confidence, spark }
      })
      .sort((a, b) => b.score - a.score)
      .slice(0, 12)
  }, [alerts, showAll, protoFilter])

  const btnStyle = (active: boolean): React.CSSProperties => ({
    padding: '2px 7px', fontSize: 9, cursor: 'pointer', borderRadius: 3,
    border: `1px solid ${active ? G3.accent : G3.line}`,
    background: active ? G3.accent : G3.card2,
    color: active ? G3.bg : G3.mute2,
    whiteSpace: 'nowrap', flexShrink: 0,
  })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ padding: '4px 10px 2px', flexShrink: 0, display: 'flex', justifyContent: 'flex-end', gap: 4 }}>
        <button onClick={() => setShowAll(!showAll)} style={btnStyle(showAll)}
          title={showAll ? 'Showing all severities' : 'Showing HIGH+ only'}>
          {showAll ? 'All' : 'HIGH+'}
        </button>
        {(['TCP', 'UDP'] as const).map(p => (
          <button key={p} style={btnStyle(protoFilter.has(p))} onClick={() => {
            const next = new Set(protoFilter)
            next.has(p) ? next.delete(p) : next.add(p)
            setProtoFilter(next)
          }}>{p}</button>
        ))}
      </div>
    <div style={{ flex: 1, overflowY: 'auto', padding: '0 10px 4px' }}>
      {entities.length === 0 && (
        <div style={{ padding: 16, color: G3.mute, fontSize: 11 }}>No hosts seen yet</div>
      )}
      {entities.map(e => {
        const col      = sevCol(e.peak)
        const max      = Math.max(...e.spark, 0.01)
        const isActive = entityFilter === e.ip
        return (
          <div
            key={e.ip}
            onClick={() => {
              if (entityFilter === e.ip) {
                setEntityFilter(null)
                setSelected(null)
              } else {
                setEntityFilter(e.ip)
                setSelected(alerts.findLast(a => a.src_ip === e.ip) ?? null)
              }
            }}
            style={{
              display: 'grid',
              gridTemplateColumns: `minmax(0, 1fr)${showSpark ? ' minmax(40px, 1fr)' : ''}${showScore ? ' 42px' : ''}`,
              gap: 8, alignItems: 'center', padding: '5px 4px',
              borderBottom: `1px solid ${G3.lineSoft}`,
              cursor: 'pointer', userSelect: 'none',
              background: isActive ? G3.accentSoft : 'transparent',
            }}
          >
            <span style={{
              fontFamily: 'JetBrains Mono, ui-monospace, monospace', fontSize: 10,
              color: isActive ? G3.accent : G3.fg,
              whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
            }}>
              {e.ip}
            </span>

            {showSpark && (
              <svg viewBox="0 0 40 12" preserveAspectRatio="none" style={{ width: '100%', height: 14 }}>
                {e.spark.map((c, i) => {
                  const h = c > 0 ? Math.max((c / max) * 11, 1) : 0
                  return <rect key={i} x={i * 5 + 0.5} y={12 - h} width={4} height={h} fill={col} rx={0.5} />
                })}
              </svg>
            )}

            {showScore && (
              <span style={{
                fontSize: 10, color: col,
                fontFamily: 'JetBrains Mono, ui-monospace, monospace',
                textAlign: 'right',
              }}>
                {e.score.toFixed(2)}
              </span>
            )}
          </div>
        )
      })}
    </div>
    </div>
  )
}
