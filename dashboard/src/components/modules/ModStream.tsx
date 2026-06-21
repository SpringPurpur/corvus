import { useMemo, useState } from 'react'
import { useModuleSize } from '../grid/GridContainer'
import { G3, sevCol, sevBg, alpha } from '../grid/g3'
import type { Alert } from '../../types'

interface Props {
  alerts:          Alert[]
  selected:        Alert | null
  setSelected:     (a: Alert | null) => void
  entityFilter:    string | null
  setEntityFilter: (ip: string | null) => void
  showAll:         boolean
  setShowAll:      (v: boolean) => void
  protoFilter:     Set<'TCP' | 'UDP'>
  setProtoFilter:  (v: Set<'TCP' | 'UDP'>) => void
}

export function ModStream({ alerts, selected, setSelected, entityFilter, setEntityFilter, showAll, setShowAll, protoFilter, setProtoFilter }: Props) {
  const { w } = useModuleSize()
  const showTime     = w > 260
  const showEndpoint = w > 380

  const [searchQuery, setSearchQuery] = useState('')
  const [paused, setPaused]           = useState(false)
  const [frozenList, setFrozenList]   = useState<Alert[] | null>(null)
  const [checked, setChecked]         = useState<Set<string>>(new Set())

  const allFiltered = useMemo(() => {
    let list = showAll ? [...alerts] : alerts.filter(a => a.verdict.severity !== 'INFO')
    if (protoFilter.size < 2) list = list.filter(a => protoFilter.has(a.proto as 'TCP' | 'UDP'))
    if (entityFilter) list = list.filter(a => a.src_ip === entityFilter)
    if (searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase()
      list = list.filter(a =>
        a.src_ip.includes(q) || a.dst_ip.includes(q) ||
        String(a.src_port).includes(q) || String(a.dst_port).includes(q),
      )
    }
    return list.sort((a, b) => b.ts - a.ts).slice(0, 300)
  }, [alerts, showAll, protoFilter, entityFilter, searchQuery])

  const displayed      = paused && frozenList ? frozenList : allFiltered
  const newWhilePaused = paused && frozenList ? Math.max(0, allFiltered.length - frozenList.length) : 0

  const togglePause = () => {
    if (!paused) { setFrozenList(allFiltered) }
    else         { setFrozenList(null) }
    setPaused(p => !p)
  }

  const displayedIds = displayed.map(a => a.flow_id)
  const allChecked   = displayedIds.length > 0 && displayedIds.every(id => checked.has(id))

  const toggleAll = () => {
    if (allChecked) setChecked(new Set())
    else            setChecked(new Set(displayedIds))
  }

  const toggleOne = (flowId: string) => {
    setChecked(prev => {
      const next = new Set(prev)
      if (next.has(flowId)) next.delete(flowId)
      else next.add(flowId)
      return next
    })
  }

  const bulkDismiss = (ids: string[]) => {
    fetch('/feedback/bulk', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        flow_ids:        ids,
        dismiss:         true,
        corrected_label: null,
        reason:          'Dismissed as false positive',
      }),
    }).catch(() => {})
    setChecked(new Set())
  }

  const btn = (active = false): React.CSSProperties => ({
    padding: '2px 7px', fontSize: 9,
    background:   active ? G3.accent : G3.card2,
    color:        active ? G3.bg     : G3.mute2,
    border:       `1px solid ${active ? G3.accent : G3.line}`,
    borderRadius: 3, cursor: 'pointer', whiteSpace: 'nowrap', flexShrink: 0,
  })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>

      {/* Toolbar */}
      <div style={{ display: 'flex', gap: 4, padding: '4px 8px', borderBottom: `1px solid ${G3.lineSoft}`, flexShrink: 0, alignItems: 'center' }}>
        <input
          type="checkbox"
          checked={allChecked}
          onChange={toggleAll}
          style={{ width: 11, height: 11, accentColor: G3.accent, flexShrink: 0, cursor: 'pointer' }}
          aria-label="Select all"
        />

        {entityFilter && (
          <button
            onClick={() => setEntityFilter(null)}
            style={{ ...btn(true), background: G3.accentSoft, color: G3.accent, border: `1px solid ${alpha(G3.accent, 25)}`, maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis' }}
          >
            {entityFilter} ×
          </button>
        )}

        <input
          type="text"
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          placeholder="Search IP / port…"
          style={{
            flex: 1, background: G3.card2, border: `1px solid ${G3.line}`,
            borderRadius: 3, padding: '2px 6px', fontSize: 9, color: G3.fg,
            outline: 'none', minWidth: 0, fontFamily: 'JetBrains Mono, ui-monospace, monospace',
          }}
        />

        <span style={{
          fontSize: 9, color: newWhilePaused > 0 ? G3.high : G3.mute,
          flexShrink: 0, fontFamily: 'JetBrains Mono, ui-monospace, monospace',
        }}>
          {newWhilePaused > 0 ? `+${newWhilePaused}` : displayed.length}
        </span>

        <button onClick={togglePause} style={btn(paused)} title={paused ? 'Resume live feed' : 'Pause feed'}>{paused ? '▶' : '⏸'}</button>
        <button onClick={() => setShowAll(!showAll)} style={btn(showAll)} title={showAll ? 'Showing all severities' : 'Showing HIGH+ only'}>{showAll ? 'All' : 'HIGH+'}</button>
        {(['TCP', 'UDP'] as const).map(p => (
          <button key={p} style={btn(protoFilter.has(p))} onClick={() => {
            const next = new Set(protoFilter)
            next.has(p) ? next.delete(p) : next.add(p)
            setProtoFilter(next)
          }}>{p}</button>
        ))}
      </div>

      {/* Bulk action bar */}
      {checked.size > 0 && (
        <div style={{ display: 'flex', gap: 6, padding: '3px 8px', background: G3.card2, borderBottom: `1px solid ${G3.lineSoft}`, flexShrink: 0, alignItems: 'center' }}>
          <span style={{ fontSize: 9, color: G3.mute2, flex: 1 }}>{checked.size} selected</span>
          <button onClick={() => bulkDismiss([...checked])} style={btn()}>Dismiss selected</button>
          <button onClick={() => bulkDismiss(displayedIds)} style={btn()}>Dismiss all</button>
          <button onClick={() => setChecked(new Set())} style={{ ...btn(), color: G3.mute }}>Clear</button>
        </div>
      )}

      {/* Feed */}
      <div style={{ overflowY: 'auto', flex: 1 }}>
        {displayed.length === 0 && (
          <div style={{ padding: 20, color: G3.mute, fontSize: 11 }}>
            {alerts.length === 0 ? 'Waiting for traffic…' : 'No matching anomalies'}
          </div>
        )}

        {displayed.map(a => {
          const col    = sevCol(a.verdict.severity)
          const active = selected?.flow_id === a.flow_id
          const ts     = new Date(a.ts * 1000).toLocaleTimeString([], {
            hour: '2-digit', minute: '2-digit', second: '2-digit',
          })

          return (
            <div
              key={a.flow_id}
              onClick={() => setSelected(a)}
              style={{
                display: 'grid',
                gridTemplateColumns: `14px ${showTime ? '54px ' : ''}60px 1fr auto`,
                gap: 6, padding: '5px 8px',
                borderBottom: `1px solid ${G3.lineSoft}`,
                alignItems: 'center', cursor: 'pointer', minWidth: 0,
                background:  active ? G3.accentSoft : 'transparent',
                borderLeft:  active ? `2px solid ${G3.accent}` : '2px solid transparent',
              }}
            >
              <div onClick={e => e.stopPropagation()}>
                <input
                  type="checkbox"
                  checked={checked.has(a.flow_id)}
                  onChange={() => toggleOne(a.flow_id)}
                  style={{ width: 11, height: 11, accentColor: G3.accent, cursor: 'pointer' }}
                />
              </div>

              {showTime && (
                <span style={{ fontSize: 9, color: G3.mute, fontFamily: 'JetBrains Mono, ui-monospace, monospace', whiteSpace: 'nowrap' }}>
                  {ts}
                </span>
              )}

              <span style={{
                fontSize: 9, fontWeight: 600, color: col, background: sevBg(a.verdict.severity),
                padding: '2px 6px', borderRadius: 3, textAlign: 'center', whiteSpace: 'nowrap',
              }}>
                {a.verdict.severity}
              </span>

              <div style={{ minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
                  <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono, ui-monospace, monospace', color: col, fontWeight: 600 }}>
                    {a.verdict.confidence.toFixed(2)}
                  </span>
                  <span style={{ fontSize: 10, color: G3.mute, fontStyle: 'italic', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {a.verdict.severity === 'INFO' ? `${a.proto} flow` : `${a.proto} anomaly`}
                  </span>
                </div>
                {showEndpoint && (
                  <div style={{ fontSize: 9, color: G3.mute2, fontFamily: 'JetBrains Mono, ui-monospace, monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 1 }}>
                    {a.src_ip} → {a.dst_ip}:{a.dst_port}
                  </div>
                )}
              </div>

              <div style={{ width: w > 500 ? 60 : 36, height: 3, background: G3.line, borderRadius: 2, flexShrink: 0 }}>
                <div style={{ width: `${Math.min(a.verdict.confidence * 100, 100)}%`, height: '100%', background: col, borderRadius: 2 }} />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
