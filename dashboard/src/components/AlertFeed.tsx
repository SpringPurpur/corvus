import { cn } from '../lib/utils'
import type { Alert, Severity } from '../types'

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
}

export function AlertFeed({ alerts, selected, onSelect, showAll, onToggleShowAll, entityFilter }: Props) {
  // Apply bucket filter: hide INFO rows unless showAll is true
  const visible = showAll
    ? alerts
    : alerts.filter((a) => a.verdict.severity !== 'INFO')

  const isEmpty = visible.length === 0

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Filter control strip */}
      <div className="flex items-center justify-between px-3 py-1.5 border-b bg-card shrink-0">
        <span className="text-[10px] text-muted-foreground">
          {entityFilter ? `Filtered: ${entityFilter}` : `${visible.length} flow${visible.length !== 1 ? 's' : ''}`}
        </span>
        <button
          onClick={onToggleShowAll}
          className="text-[10px] px-2 py-0.5 rounded transition-colors"
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

      {isEmpty ? (
        <div className="flex items-center justify-center flex-1 text-muted-foreground text-sm">
          {alerts.length === 0 ? 'Waiting for traffic…' : 'No HIGH / CRITICAL alerts yet'}
        </div>
      ) : (
        <div className="overflow-y-auto flex-1">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-card border-b">
              <tr className="text-muted-foreground">
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
