// IncidentList.tsx — streaming incident grouping over the alert ring buffer.
//
// Algorithm: sort alerts by timestamp, then sweep through them keyed by
// (src_ip, dst_ip, dst_port, proto). A gap larger than `gapSec` between
// consecutive alerts on the same key closes the current incident and opens
// a new one. O(n log n) for the sort, O(n) for the sweep — <1 ms on 5 k
// alerts. No server side needed.
//
// Three gap presets: 30 s (port-scan granularity), 2 m (default session
// window), 5 m (slow attacks such as Slowloris / slow POST).

import { useMemo, useState } from 'react'
import type { Alert, Severity } from '../types'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Incident {
  id:           string     // unique key for React — src→dst:port/proto@firstSeen
  src_ip:       string
  dst_ip:       string
  dst_port:     number
  proto:        'TCP' | 'UDP'
  flowCount:    number
  firstSeen:    number
  lastSeen:     number
  duration:     number     // lastSeen − firstSeen (seconds)
  peakSeverity: Severity
  peakScore:    number
  alerts:       Alert[]
}

// ── Grouping ──────────────────────────────────────────────────────────────────

function groupIncidents(alerts: Alert[], gapSec: number): Incident[] {
  const sorted = [...alerts].sort((a, b) => a.ts - b.ts)
  const open   = new Map<string, Incident>()
  const closed: Incident[] = []

  for (const a of sorted) {
    const key = `${a.src_ip}→${a.dst_ip}:${a.dst_port}/${a.proto}`
    const inc = open.get(key)

    if (!inc || a.ts - inc.lastSeen > gapSec) {
      // Close the previous incident on this key (if any)
      if (inc) {
        inc.duration = inc.lastSeen - inc.firstSeen
        closed.push(inc)
      }
      // Open a new incident
      open.set(key, {
        id:           `${key}@${a.ts.toFixed(3)}`,
        src_ip:       a.src_ip,
        dst_ip:       a.dst_ip,
        dst_port:     a.dst_port,
        proto:        a.proto,
        flowCount:    1,
        firstSeen:    a.ts,
        lastSeen:     a.ts,
        duration:     0,
        peakSeverity: a.verdict.severity,
        peakScore:    a.verdict.confidence,
        alerts:       [a],
      })
    } else {
      // Extend existing incident
      inc.flowCount++
      inc.lastSeen = a.ts
      if (a.verdict.confidence > inc.peakScore) {
        inc.peakScore    = a.verdict.confidence
        inc.peakSeverity = a.verdict.severity
      }
      inc.alerts.push(a)
    }
  }

  // Close all still-open incidents
  for (const inc of open.values()) {
    inc.duration = inc.lastSeen - inc.firstSeen
    closed.push(inc)
  }

  // Newest last-seen first
  return closed.sort((a, b) => b.lastSeen - a.lastSeen)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDuration(secs: number): string {
  if (secs < 1)    return '<1s'
  if (secs < 60)   return `${secs.toFixed(0)}s`
  if (secs < 3600) return `${(secs / 60).toFixed(1)}m`
  return `${(secs / 3600).toFixed(1)}h`
}

const SEV_COLOUR: Record<Severity, { bg: string; text: string }> = {
  INFO:     { bg: 'var(--color-sev-info-bg)',  text: 'var(--color-sev-info-text)'  },
  HIGH:     { bg: 'var(--color-sev-high-bg)',  text: 'var(--color-sev-high-text)'  },
  CRITICAL: { bg: 'var(--color-sev-crit-bg)',  text: 'var(--color-sev-crit-text)'  },
}

const SEV_BORDER: Record<Severity, string> = {
  INFO:     'transparent',
  HIGH:     'var(--color-badge-warn-bdr)',
  CRITICAL: 'var(--color-badge-danger-bdr)',
}

function SevBadge({ sev }: { sev: Severity }) {
  const { bg, text } = SEV_COLOUR[sev]
  return (
    <span
      className="px-1.5 py-0.5 text-[10px] font-medium shrink-0"
      style={{ backgroundColor: bg, color: text, borderRadius: 'var(--radius)' }}
    >
      {sev}
    </span>
  )
}

const GAP_PRESETS = [
  { label: '30 s', value: 30  },
  { label: '2 m',  value: 120 },
  { label: '5 m',  value: 300 },
]

// ── Component ─────────────────────────────────────────────────────────────────

interface Props {
  alerts: Alert[]   // all alerts — TCP + UDP combined
}

export function IncidentList({ alerts }: Props) {
  const [gapSec, setGapSec]     = useState(120)
  const [showAll, setShowAll]   = useState(false)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())

  const allIncidents = useMemo(() => groupIncidents(alerts, gapSec), [alerts, gapSec])

  const incidents = useMemo(
    () => showAll ? allIncidents : allIncidents.filter(i => i.peakSeverity !== 'INFO'),
    [allIncidents, showAll],
  )

  const critCount = incidents.filter(i => i.peakSeverity === 'CRITICAL').length
  const highCount = incidents.filter(i => i.peakSeverity === 'HIGH').length

  const toggleExpand = (id: string) =>
    setExpanded(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })

  return (
    <div className="flex flex-col h-full overflow-hidden">

      {/* Control strip */}
      <div className="flex items-center gap-3 px-4 py-2 border-b bg-card shrink-0 flex-wrap">

        {/* Summary */}
        <div className="flex gap-3 text-[11px]">
          <span className="text-muted-foreground">
            {incidents.length} incident{incidents.length !== 1 ? 's' : ''}
          </span>
          {critCount > 0 && (
            <span style={{ color: 'var(--color-sev-crit-text)' }}>
              {critCount} CRITICAL
            </span>
          )}
          {highCount > 0 && (
            <span style={{ color: 'var(--color-sev-high-text)' }}>
              {highCount} HIGH
            </span>
          )}
        </div>

        {/* Gap presets */}
        <div className="flex items-center gap-1 ml-auto">
          <span className="text-[10px] text-muted-foreground mr-1">gap</span>
          {GAP_PRESETS.map(p => (
            <button
              key={p.value}
              onClick={() => setGapSec(p.value)}
              className="text-[10px] px-2 py-0.5 transition-colors"
              style={{
                background:   gapSec === p.value ? 'var(--color-accent)' : 'transparent',
                color:        gapSec === p.value ? '#fff' : 'var(--color-muted-foreground, #888)',
                border:       '1px solid',
                borderColor:  gapSec === p.value ? 'var(--color-accent)' : 'var(--border, #333)',
                borderRadius: 'var(--radius)',
              }}
            >
              {p.label}
            </button>
          ))}
        </div>

        {/* Severity filter */}
        <button
          onClick={() => setShowAll(v => !v)}
          className="text-[10px] px-2 py-0.5 transition-colors"
          style={{
            background:   showAll ? 'var(--color-accent)' : 'transparent',
            color:        showAll ? '#fff' : 'var(--color-muted-foreground, #888)',
            border:       '1px solid',
            borderColor:  showAll ? 'var(--color-accent)' : 'var(--border, #333)',
            borderRadius: 'var(--radius)',
          }}
        >
          {showAll ? 'All flows' : 'Alerts only'}
        </button>
      </div>

      {/* Incident list */}
      {incidents.length === 0 ? (
        <div className="flex items-center justify-center flex-1 text-sm text-muted-foreground">
          {alerts.length === 0 ? 'Waiting for traffic…' : 'No incidents to display'}
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto">
          {incidents.map(inc => {
            const isOpen   = expanded.has(inc.id)
            const sevText  = SEV_COLOUR[inc.peakSeverity].text
            const sevBdr   = SEV_BORDER[inc.peakSeverity]

            return (
              <div
                key={inc.id}
                className="border-b border-border/50"
                style={isOpen ? { borderLeft: `2px solid ${sevBdr}` } : undefined}
              >
                {/* Incident header */}
                <button
                  onClick={() => toggleExpand(inc.id)}
                  className="w-full text-left px-4 py-2.5 hover:bg-muted/40 transition-colors"
                >
                  <div className="flex items-center gap-2 text-xs min-w-0">
                    <SevBadge sev={inc.peakSeverity} />

                    {/* Flow path */}
                    <span className="font-mono text-[11px] truncate flex-1 min-w-0">
                      {inc.src_ip}
                      <span className="text-muted-foreground mx-1">→</span>
                      {inc.dst_ip}
                      <span className="text-muted-foreground">:{inc.dst_port}</span>
                      <span className="text-muted-foreground ml-1 text-[10px]">
                        {inc.proto}
                      </span>
                    </span>

                    {/* Flow count badge */}
                    <span
                      className="text-[10px] tabular-nums px-1.5 py-0.5 shrink-0"
                      style={{
                        backgroundColor: 'var(--color-muted)',
                        color:           sevText,
                        borderRadius:    'var(--radius)',
                      }}
                    >
                      {inc.flowCount} flow{inc.flowCount !== 1 ? 's' : ''}
                    </span>

                    {/* Duration */}
                    <span className="text-[10px] text-muted-foreground tabular-nums w-10 text-right shrink-0">
                      {fmtDuration(inc.duration)}
                    </span>

                    {/* Last seen */}
                    <span className="text-[10px] text-muted-foreground tabular-nums w-16 text-right shrink-0">
                      {new Date(inc.lastSeen * 1000).toLocaleTimeString()}
                    </span>

                    {/* Expand chevron */}
                    <span
                      className="text-[10px] text-muted-foreground shrink-0 transition-transform duration-150"
                      style={{ display: 'inline-block', transform: isOpen ? 'rotate(90deg)' : 'none' }}
                    >
                      ▶
                    </span>
                  </div>

                  {/* Peak score bar */}
                  <div
                    className="mt-1.5 h-0.5 overflow-hidden bg-border"
                    style={{ borderRadius: 'var(--radius)' }}
                  >
                    <div
                      className="h-full transition-all"
                      style={{
                        width:           `${(inc.peakScore * 100).toFixed(1)}%`,
                        backgroundColor: sevText,
                        borderRadius:    'var(--radius)',
                      }}
                    />
                  </div>
                </button>

                {/* Expanded: individual alert table */}
                {isOpen && (
                  <div className="px-4 pb-3 bg-muted/20">
                    <table className="w-full text-[11px]">
                      <thead>
                        <tr className="text-muted-foreground border-b border-border/40">
                          <th className="text-left py-1 font-medium">Time</th>
                          <th className="text-left py-1 font-medium">Src port</th>
                          <th className="text-left py-1 font-medium">Severity</th>
                          <th className="text-right py-1 font-medium">Score</th>
                          <th className="text-right py-1 font-medium">Pkts</th>
                        </tr>
                      </thead>
                      <tbody>
                        {[...inc.alerts].reverse().map(a => (
                          <tr key={a.flow_id} className="border-b border-border/20">
                            <td className="py-1 tabular-nums text-muted-foreground">
                              {new Date(a.ts * 1000).toLocaleTimeString()}
                            </td>
                            <td className="py-1 font-mono">{a.src_port}</td>
                            <td className="py-1"><SevBadge sev={a.verdict.severity} /></td>
                            <td className="py-1 tabular-nums text-right">
                              {(a.verdict.confidence * 100).toFixed(1)}%
                            </td>
                            <td className="py-1 tabular-nums text-right">{a.fwd_pkts}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
