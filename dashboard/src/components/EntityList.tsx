import { useMemo } from 'react'
import type { Alert, Severity } from '../types'

interface EntityEntry {
  ip:           string
  flowCount:    number
  critCount:    number
  highCount:    number
  maxScore:     number
  lastSeen:     number
  peakSeverity: Severity
}

// Use the same semantic colour vars as the rest of the UI
const SEV_DOT: Record<Severity, string> = {
  INFO:     'var(--color-sev-info-text)',
  HIGH:     'var(--color-sev-high-text)',
  CRITICAL: 'var(--color-sev-crit-text)',
}

const SEV_BAR: Record<Severity, string> = {
  INFO:     'var(--color-score-normal)',
  HIGH:     'var(--color-score-high)',
  CRITICAL: 'var(--color-score-crit)',
}

interface Props {
  alerts:    Alert[]
  activeIp:  string | null
  onSelect:  (ip: string | null) => void
}

export function EntityList({ alerts, activeIp, onSelect }: Props) {
  const entities = useMemo<EntityEntry[]>(() => {
    const map = new Map<string, EntityEntry>()
    for (const a of alerts) {
      const ip = a.src_ip
      if (!map.has(ip)) {
        map.set(ip, {
          ip,
          flowCount: 0, critCount: 0, highCount: 0,
          maxScore: 0, lastSeen: 0, peakSeverity: 'INFO',
        })
      }
      const e = map.get(ip)!
      e.flowCount++
      if (a.verdict.confidence > e.maxScore) e.maxScore = a.verdict.confidence
      if (a.ts > e.lastSeen) e.lastSeen = a.ts
      if (a.verdict.severity === 'CRITICAL') {
        e.critCount++
        e.peakSeverity = 'CRITICAL'
      } else if (a.verdict.severity === 'HIGH' && e.peakSeverity !== 'CRITICAL') {
        e.highCount++
        e.peakSeverity = 'HIGH'
      }
    }
    return [...map.values()].sort((a, b) => b.maxScore - a.maxScore)
  }, [alerts])

  return (
    <div
      className="flex flex-col h-full overflow-hidden border-r shrink-0"
      style={{ width: 164 }}
    >
      <div className="px-3 py-2 text-[11px] font-semibold text-muted-foreground border-b bg-card shrink-0 tracking-wide uppercase">
        Entities
      </div>

      <div className="flex-1 overflow-y-auto">
        {entities.length === 0 ? (
          <div className="px-3 py-4 text-xs text-muted-foreground">No traffic yet</div>
        ) : (
          entities.map((e) => {
            const isActive = activeIp === e.ip
            return (
              <button
                key={e.ip}
                onClick={() => onSelect(isActive ? null : e.ip)}
                className="w-full text-left px-3 py-2 border-b border-border/40 transition-colors hover:bg-muted/40"
                style={isActive ? { background: 'var(--color-muted, rgba(255,255,255,0.07))' } : undefined}
              >
                {/* IP row */}
                <div className="flex items-center gap-1.5 mb-0.5">
                  <span
                    className="w-1.5 h-1.5 rounded-full shrink-0"
                    style={{ backgroundColor: SEV_DOT[e.peakSeverity] }}
                  />
                  <span className="font-mono text-[11px] truncate leading-none">
                    {e.ip}
                  </span>
                </div>

                {/* Counts row */}
                <div className="flex items-center justify-between text-[10px] text-muted-foreground mb-1">
                  <span>{e.flowCount} flow{e.flowCount !== 1 ? 's' : ''}</span>
                  {e.critCount > 0 && (
                    <span style={{ color: SEV_DOT.CRITICAL }}>{e.critCount}×CRIT</span>
                  )}
                  {e.critCount === 0 && e.highCount > 0 && (
                    <span style={{ color: SEV_DOT.HIGH }}>{e.highCount}×HIGH</span>
                  )}
                </div>

                {/* Score bar */}
                <div className="h-0.5 rounded-full overflow-hidden bg-border">
                  <div
                    className="h-full rounded-full transition-all duration-300"
                    style={{
                      width: `${Math.round(e.maxScore * 100)}%`,
                      backgroundColor: SEV_BAR[e.peakSeverity],
                    }}
                  />
                </div>
              </button>
            )
          })
        )}
      </div>
    </div>
  )
}
