import type { Alert } from '../types'

interface Props {
  alerts: Alert[]
}

export function StatsBar({ alerts }: Props) {
  // Top 5 source IPs by alert count
  const ipCounts: Record<string, number> = {}
  for (const a of alerts) {
    ipCounts[a.src_ip] = (ipCounts[a.src_ip] ?? 0) + 1
  }
  const topIPs = Object.entries(ipCounts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5)

  // Label distribution
  const labelCounts: Record<string, number> = {}
  for (const a of alerts) {
    labelCounts[a.verdict.label] = (labelCounts[a.verdict.label] ?? 0) + 1
  }
  const topLabels = Object.entries(labelCounts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5)

  return (
    <footer className="border-t px-4 py-2 bg-card flex gap-8 text-xs text-muted-foreground">
      <div className="flex gap-3">
        <span className="font-medium text-foreground">Top sources:</span>
        {topIPs.map(([ip, n]) => (
          <span key={ip} className="font-mono">{ip} <span className="text-foreground">{n}</span></span>
        ))}
        {topIPs.length === 0 && <span className="italic">—</span>}
      </div>
      <div className="flex gap-3">
        <span className="font-medium text-foreground">Classes:</span>
        {topLabels.map(([label, n]) => (
          <span key={label}>{label} <span className="text-foreground">{n}</span></span>
        ))}
        {topLabels.length === 0 && <span className="italic">—</span>}
      </div>
    </footer>
  )
}
