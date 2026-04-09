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
      style={{
        backgroundColor: bg,
        color: text,
        borderRadius: 'var(--radius)',
      }}
    >
      {sev}
    </span>
  )
}

interface Props {
  alerts: Alert[]
  selected: Alert | null
  onSelect: (a: Alert) => void
}

export function AlertFeed({ alerts, selected, onSelect }: Props) {
  if (alerts.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
        Waiting for traffic…
      </div>
    )
  }

  return (
    <div className="overflow-y-auto h-full">
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
          {[...alerts].reverse().map((a) => (
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
  )
}
