import { cn } from '../lib/utils'
import type { Alert, Severity } from '../types'
import type { Dispatch, SetStateAction } from 'react'

const SEV_VAR: Record<Severity, { bg: string; text: string }> = {
  INFO:     { bg: 'var(--color-sev-info-bg)',  text: 'var(--color-sev-info-text)'  },
  HIGH:     { bg: 'var(--color-sev-high-bg)',  text: 'var(--color-sev-high-text)'  },
  CRITICAL: { bg: 'var(--color-sev-crit-bg)',  text: 'var(--color-sev-crit-text)'  },
}

function SevBadge({ sev }: { sev: Severity }) {
  const { bg, text } = SEV_VAR[sev]
  return (
    <span
      className="px-1.5 py-0.5 text-[11px] font-medium"
      style={{ backgroundColor: bg, color: text, borderRadius: 'var(--radius)' }}
    >
      {sev}
    </span>
  )
}

interface Props {
  alerts:           Alert[]
  selected:         Alert | null
  onSelect:         (a: Alert) => void
  showAll:          boolean
  onToggleShowAll:  () => void
  entityFilter:     string | null
  checked:          Set<string>
  onCheckedChange:  Dispatch<SetStateAction<Set<string>>>
  onBulkDismiss:    (flowIds: string[]) => void
  paused:           boolean
  onTogglePause:    () => void
  newWhilePaused:   number
  searchQuery:      string
  onSearchChange:   (q: string) => void
}

export function AlertFeed({
  alerts, selected, onSelect,
  showAll, onToggleShowAll, entityFilter,
  checked, onCheckedChange, onBulkDismiss,
  paused, onTogglePause, newWhilePaused,
  searchQuery, onSearchChange,
}: Props) {
  const visible = showAll
    ? alerts
    : alerts.filter((a) => a.verdict.severity !== 'INFO')

  const visibleIds = visible.map((a) => a.flow_id)
  const allChecked = visibleIds.length > 0 && visibleIds.every((id) => checked.has(id))
  const someChecked = checked.size > 0

  const toggleAll = () => {
    if (allChecked) {
      onCheckedChange(new Set())
    } else {
      onCheckedChange(new Set(visibleIds))
    }
  }

  const toggleOne = (flowId: string) => {
    onCheckedChange((prev) => {
      const next = new Set(prev)
      if (next.has(flowId)) next.delete(flowId)
      else next.add(flowId)
      return next
    })
  }

  const isEmpty = visible.length === 0

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Filter / search / pause strip */}
      <div className="flex items-center gap-2 px-3 py-1.5 border-b bg-card shrink-0">
        {/* Search */}
        <input
          type="text"
          value={searchQuery}
          onChange={e => onSearchChange(e.target.value)}
          placeholder="Search IP or port…"
          className="flex-1 bg-muted px-2 py-0.5 text-[10px] font-mono focus:outline-none focus:ring-1 focus:ring-border min-w-0"
          style={{ borderRadius: 'var(--radius)' }}
        />
        {/* Flow count / pause indicator */}
        <span className="text-[10px] text-muted-foreground shrink-0">
          {paused && newWhilePaused > 0
            ? <span style={{ color: 'var(--color-badge-warn-text)' }}>{newWhilePaused} new</span>
            : `${visible.length} flow${visible.length !== 1 ? 's' : ''}`}
        </span>
        {/* Pause button */}
        <button
          onClick={onTogglePause}
          title={paused ? 'Resume live feed' : 'Pause feed'}
          className="text-[10px] px-2 py-0.5 transition-colors shrink-0"
          style={{
            background: paused ? 'var(--color-badge-warn-bg)' : 'transparent',
            color: paused ? 'var(--color-badge-warn-text)' : 'var(--color-muted-foreground, #888)',
            border: '1px solid',
            borderColor: paused ? 'var(--color-badge-warn-bdr)' : 'var(--border, #333)',
            borderRadius: 'var(--radius)',
          }}
        >
          {paused ? '▶ Resume' : '⏸ Pause'}
        </button>
        {/* All / alerts toggle */}
        <button
          onClick={onToggleShowAll}
          className="text-[10px] px-2 py-0.5 transition-colors shrink-0"
          style={{
            background: showAll ? 'var(--color-accent)' : 'transparent',
            color: showAll ? '#fff' : 'var(--color-muted-foreground, #888)',
            border: '1px solid',
            borderColor: showAll ? 'var(--color-accent)' : 'var(--border, #333)',
            borderRadius: 'var(--radius)',
          }}
        >
          {showAll ? 'All flows' : 'Alerts only'}
        </button>
      </div>

      {/* Bulk action bar — only visible when rows are checked */}
      {someChecked && (
        <div className="flex items-center gap-2 px-3 py-1.5 border-b bg-muted/60 shrink-0">
          <span className="text-[11px] text-muted-foreground flex-1">
            {checked.size} selected
          </span>
          <button
            onClick={() => onBulkDismiss([...checked])}
            className="text-[11px] px-2.5 py-1 rounded bg-muted hover:bg-muted/80 transition-colors"
          >
            Dismiss selected
          </button>
          <button
            onClick={() => onBulkDismiss(visibleIds)}
            className="text-[11px] px-2.5 py-1 rounded bg-muted hover:bg-muted/80 transition-colors"
          >
            Dismiss all visible
          </button>
          <button
            onClick={() => onCheckedChange(new Set())}
            className="text-[11px] px-2 py-1 rounded text-muted-foreground hover:text-foreground transition-colors"
          >
            Clear
          </button>
        </div>
      )}

      {isEmpty ? (
        <div className="flex items-center justify-center flex-1 text-muted-foreground text-sm">
          {alerts.length === 0 ? 'Waiting for traffic…' : 'No HIGH / CRITICAL alerts yet'}
        </div>
      ) : (
        <div className="overflow-y-auto flex-1">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-card border-b">
              <tr className="text-muted-foreground">
                <th className="px-3 py-2 w-6">
                  <input
                    type="checkbox"
                    checked={allChecked}
                    onChange={toggleAll}
                    className="h-3 w-3 accent-current"
                    aria-label="Select all visible"
                  />
                </th>
                <th className="text-left px-3 py-2 font-medium">Time</th>
                <th className="text-left px-3 py-2 font-medium">Severity</th>
                <th className="text-left px-3 py-2 font-medium">Anomaly</th>
                <th className="text-left px-3 py-2 font-medium">Source</th>
                <th className="text-left px-3 py-2 font-medium">Destination</th>
                <th className="text-right px-3 py-2 font-medium">Pkts</th>
              </tr>
            </thead>
            <tbody>
              {[...visible].reverse().map((a) => (
                <tr
                  key={a.flow_id}
                  onClick={() => onSelect(a)}
                  className={cn(
                    'border-b border-border/50 cursor-pointer hover:bg-muted/40 transition-colors',
                    selected?.flow_id === a.flow_id && 'bg-muted/60',
                  )}
                >
                  <td className="px-3 py-1.5" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={checked.has(a.flow_id)}
                      onChange={() => toggleOne(a.flow_id)}
                      className="h-3 w-3 accent-current"
                      aria-label={`Select flow ${a.flow_id}`}
                    />
                  </td>
                  <td className="px-3 py-1.5 text-muted-foreground tabular-nums">
                    {new Date(a.ts * 1000).toLocaleTimeString()}
                  </td>
                  <td className="px-3 py-1.5">
                    <SevBadge sev={a.verdict.severity} />
                  </td>
                  <td className="px-3 py-1.5 font-medium">{a.verdict.label}</td>
                  <td className="px-3 py-1.5 font-mono">{a.src_ip}:{a.src_port}</td>
                  <td className="px-3 py-1.5 font-mono">{a.dst_ip}:{a.dst_port}</td>
                  <td className="px-3 py-1.5 text-right tabular-nums">{a.fwd_pkts}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
