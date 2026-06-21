import { useMemo, useState } from 'react'
import { G3, sevCol } from '../grid/g3'
import type { Alert } from '../../types'

const MAX_NODES = 16
const CX = 200, CY = 200, R = 155

function abbrevIp(ip: string): string {
  const p = ip.split('.')
  return p.length === 4 ? `${p[2]}.${p[3]}` : ip.slice(-9)
}

interface Props { alerts: Alert[] }

export function ModTopology({ alerts }: Props) {
  const [hoveredIp, setHoveredIp] = useState<string | null>(null)

  const { nodes, edges } = useMemo(() => {
    const ipCount = new Map<string, number>()
    const ipSev   = new Map<string, string>()

    for (const a of alerts) {
      const sev = a.verdict.severity
      ipCount.set(a.src_ip, (ipCount.get(a.src_ip) ?? 0) + 1)
      ipCount.set(a.dst_ip, (ipCount.get(a.dst_ip) ?? 0) + 1)
      const prev = ipSev.get(a.src_ip) ?? 'INFO'
      if (sev === 'CRITICAL' || (sev === 'HIGH' && prev !== 'CRITICAL')) {
        ipSev.set(a.src_ip, sev)
      }
    }

    const topIps = Array.from(ipCount.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, MAX_NODES)
      .map(([ip]) => ip)

    const ipSet = new Set(topIps)

    const edgeMap = new Map<string, { count: number; sev: string }>()
    for (const a of alerts) {
      if (!ipSet.has(a.src_ip) || !ipSet.has(a.dst_ip) || a.src_ip === a.dst_ip) continue
      const key  = `${a.src_ip}→${a.dst_ip}`
      const prev = edgeMap.get(key) ?? { count: 0, sev: 'INFO' }
      const sev  =
        prev.sev === 'CRITICAL' ? 'CRITICAL' :
        a.verdict.severity === 'CRITICAL' ? 'CRITICAL' :
        a.verdict.severity === 'HIGH' ? 'HIGH' : prev.sev
      edgeMap.set(key, { count: prev.count + 1, sev })
    }

    const n = topIps.length
    const nodes = topIps.map((ip, i) => {
      const angle = (2 * Math.PI * i / n) - Math.PI / 2
      const count = ipCount.get(ip) ?? 1
      const sev   = ipSev.get(ip) ?? 'INFO'
      return {
        ip,
        x:     CX + R * Math.cos(angle),
        y:     CY + R * Math.sin(angle),
        r:     Math.max(5, Math.min(14, 4 + Math.log2(count) * 1.8)),
        sev,
        count,
      }
    })

    const nodeByIp = new Map(nodes.map(nd => [nd.ip, nd]))
    const edges = Array.from(edgeMap.entries()).flatMap(([key, { count, sev }]) => {
      const [src, dst] = key.split('→')
      const sn = nodeByIp.get(src)
      const dn = nodeByIp.get(dst)
      if (!sn || !dn) return []
      return [{ src, dst, x1: sn.x, y1: sn.y, x2: dn.x, y2: dn.y, count, sev }]
    })

    return { nodes, edges }
  }, [alerts])

  if (alerts.length === 0) {
    return <div style={{ padding: 20, color: G3.mute, fontSize: 11 }}>No flows yet</div>
  }

  return (
    <div style={{ width: '100%', height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 8 }}>
      <svg viewBox="0 0 400 400" style={{ width: '100%', height: '100%' }}>
        {/* Edges */}
        {edges.map(e => {
          const col     = sevCol(e.sev)
          const isHov   = hoveredIp === e.src || hoveredIp === e.dst
          const opacity = hoveredIp
            ? (isHov ? 0.85 : 0.04)
            : Math.min(0.55, 0.08 + e.count * 0.06)
          return (
            <line
              key={`${e.src}→${e.dst}`}
              x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2}
              stroke={col}
              strokeWidth={Math.min(3, 0.5 + e.count * 0.25)}
              opacity={opacity}
            >
              <title>{`${e.src} → ${e.dst}  (${e.count} flow${e.count !== 1 ? 's' : ''})`}</title>
            </line>
          )
        })}

        {/* Nodes */}
        {nodes.map(nd => {
          const col    = sevCol(nd.sev)
          const active = hoveredIp === nd.ip
          return (
            <g
              key={nd.ip}
              onMouseEnter={() => setHoveredIp(nd.ip)}
              onMouseLeave={() => setHoveredIp(null)}
              style={{ cursor: 'default' }}
            >
              {active && (
                <circle cx={nd.x} cy={nd.y} r={nd.r + 7}
                  fill={col} fillOpacity={0.12}
                  stroke={col} strokeWidth={1} opacity={0.5}
                />
              )}
              <circle
                cx={nd.x} cy={nd.y} r={nd.r}
                fill={col} fillOpacity={active ? 0.7 : 0.35}
                stroke={col} strokeWidth={active ? 2 : 1}
              />
              <title>{`${nd.ip}  ·  ${nd.count} alert${nd.count !== 1 ? 's' : ''}  ·  peak ${nd.sev}`}</title>
              <text
                x={nd.x}
                y={nd.y + nd.r + 9}
                textAnchor="middle"
                fontSize="8"
                fill={active ? G3.fg : G3.mute}
                style={{ pointerEvents: 'none' }}
              >
                {abbrevIp(nd.ip)}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
