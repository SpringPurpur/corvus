// NetworkTopology.tsx — Force-directed graph of flow source → destination IPs.
//
// Layout: simplified Fruchterman–Reingold (repulsion + spring forces,
// 150 iterations, temperature cooling). Runs synchronously on graph structure
// change — typically < 5 ms for lab-scale node counts (≤ 30 IPs).
//
// Nodes  = unique IP addresses (src or dst), radius ∝ sqrt(flowCount).
// Edges  = unique src→dst pairs collapsed across all alerts.
//          stroke-width ∝ log2(flowCount); colour = peak severity.
// Filter = HIGH + CRITICAL only by default; toggle includes INFO flows.

import { useEffect, useMemo, useRef, useState } from 'react'
import type { Alert, Severity } from '../types'

// ── Colour map ────────────────────────────────────────────────────────────────

const SEV_COLOUR: Record<Severity, string> = {
  INFO:     'var(--color-score-normal)',
  HIGH:     'var(--color-score-high)',
  CRITICAL: 'var(--color-score-crit)',
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface TopoNode {
  id:        string
  flowCount: number
  peakSev:   Severity
  peakScore: number
}

interface TopoEdge {
  source:    string
  target:    string
  flowCount: number
  peakSev:   Severity
}

// ── Layout helpers ────────────────────────────────────────────────────────────

function nodeRadius(flowCount: number): number {
  return Math.max(7, Math.min(22, 5 + Math.sqrt(flowCount) * 1.8))
}

/** Shorten a line endpoint so edges don't overlap the node circle. */
function shrinkFrom(
  from: { x: number; y: number },
  to:   { x: number; y: number },
  r: number,
): { x: number; y: number } {
  const dx = to.x - from.x, dy = to.y - from.y
  const d  = Math.sqrt(dx * dx + dy * dy) || 1
  return { x: from.x + (dx / d) * r, y: from.y + (dy / d) * r }
}

/** Deterministic seed position from IP string so layout converges consistently. */
function seedPos(id: string, w: number, h: number) {
  let hash = 0
  for (let i = 0; i < id.length; i++) hash = (hash * 31 + id.charCodeAt(i)) >>> 0
  return {
    x: w * 0.15 + ((hash % 1000) / 1000) * w * 0.70,
    y: h * 0.15 + (((hash >> 10) % 1000) / 1000) * h * 0.70,
  }
}

function layoutGraph(
  nodes: { id: string }[],
  edges: { source: string; target: string }[],
  w: number,
  h: number,
): Map<string, { x: number; y: number }> {
  if (!nodes.length || !w || !h) return new Map()

  const pos  = new Map(nodes.map(n => [n.id, { ...seedPos(n.id, w, h) }]))
  const k    = Math.sqrt((w * h) / Math.max(nodes.length, 1)) * 0.8
  const ITER = 150

  for (let iter = 0; iter < ITER; iter++) {
    const temp = k * (1 - iter / ITER)
    const disp = new Map(nodes.map(n => [n.id, { x: 0, y: 0 }]))

    // Repulsion between every pair of nodes
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a  = pos.get(nodes[i].id)!
        const b  = pos.get(nodes[j].id)!
        const dx = a.x - b.x || 0.01, dy = a.y - b.y || 0.01
        const d  = Math.sqrt(dx * dx + dy * dy) || 0.01
        const f  = (k * k) / d
        const ux = (dx / d) * f, uy = (dy / d) * f
        disp.get(nodes[i].id)!.x += ux;  disp.get(nodes[i].id)!.y += uy
        disp.get(nodes[j].id)!.x -= ux;  disp.get(nodes[j].id)!.y -= uy
      }
    }

    // Spring attraction along edges
    for (const e of edges) {
      const a = pos.get(e.source), b = pos.get(e.target)
      if (!a || !b) continue
      const dx = b.x - a.x, dy = b.y - a.y
      const d  = Math.sqrt(dx * dx + dy * dy) || 0.01
      const f  = (d * d) / k
      const ux = (dx / d) * f, uy = (dy / d) * f
      disp.get(e.source)!.x += ux;  disp.get(e.source)!.y += uy
      disp.get(e.target)!.x -= ux;  disp.get(e.target)!.y -= uy
    }

    // Apply displacement (capped by temperature) and clamp to canvas
    for (const n of nodes) {
      const p = pos.get(n.id)!, d = disp.get(n.id)!
      const mag = Math.sqrt(d.x * d.x + d.y * d.y) || 0.01
      p.x = Math.max(40, Math.min(w - 40, p.x + (d.x / mag) * Math.min(mag, temp)))
      p.y = Math.max(40, Math.min(h - 40, p.y + (d.y / mag) * Math.min(mag, temp)))
    }
  }

  return pos
}

// ── Component ─────────────────────────────────────────────────────────────────

interface Props {
  alerts: Alert[]   // all alerts — TCP + UDP combined
}

export function NetworkTopology({ alerts }: Props) {
  const [showAll, setShowAll]       = useState(false)
  const [hovered, setHovered]       = useState<TopoNode | null>(null)
  const [hoverPos, setHoverPos]     = useState({ x: 0, y: 0 })
  const containerRef                = useRef<HTMLDivElement>(null)
  const [dims, setDims]             = useState({ w: 800, h: 500 })

  // Track container size
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const obs = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect
      if (width > 0 && height > 0) setDims({ w: width, h: height })
    })
    obs.observe(el)
    return () => obs.disconnect()
  }, [])

  // Filter alerts
  const filtered = useMemo(
    () => showAll ? alerts : alerts.filter(a => a.verdict.severity !== 'INFO'),
    [alerts, showAll],
  )

  // Build node and edge maps
  const { nodes, edges } = useMemo(() => {
    const nodeMap = new Map<string, TopoNode>()
    const edgeMap = new Map<string, TopoEdge>()

    const upsertNode = (ip: string, sev: Severity, score: number) => {
      const n = nodeMap.get(ip)
      if (!n) {
        nodeMap.set(ip, { id: ip, flowCount: 1, peakSev: sev, peakScore: score })
      } else {
        n.flowCount++
        if (score > n.peakScore) { n.peakScore = score; n.peakSev = sev }
      }
    }

    for (const a of filtered) {
      const sev = a.verdict.severity, sc = a.verdict.confidence
      upsertNode(a.src_ip, sev, sc)
      upsertNode(a.dst_ip, sev, sc)
      const key = `${a.src_ip}→${a.dst_ip}`
      const e   = edgeMap.get(key)
      if (!e) {
        edgeMap.set(key, { source: a.src_ip, target: a.dst_ip, flowCount: 1, peakSev: sev })
      } else {
        e.flowCount++
        if (sev === 'CRITICAL' || (sev === 'HIGH' && e.peakSev !== 'CRITICAL')) e.peakSev = sev
      }
    }

    return { nodes: [...nodeMap.values()], edges: [...edgeMap.values()] }
  }, [filtered])

  // Stable fingerprint of graph structure — only re-layout when topology changes,
  // not when flow counts change on existing edges.
  const graphKey = useMemo(
    () =>
      nodes.map(n => n.id).sort().join(',') + '|' +
      edges.map(e => `${e.source}→${e.target}`).sort().join(','),
    [nodes, edges],
  )

  const positions = useMemo(
    () => layoutGraph(nodes, edges, dims.w, dims.h),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [graphKey, dims.w, dims.h],
  )

  const isEmpty = nodes.length === 0

  return (
    <div className="flex flex-col h-full overflow-hidden">

      {/* Control strip */}
      <div className="flex items-center gap-4 px-4 py-2 border-b bg-card shrink-0 text-xs">
        <span className="text-muted-foreground tabular-nums">
          {nodes.length} node{nodes.length !== 1 ? 's' : ''}
          {' · '}
          {edges.length} edge{edges.length !== 1 ? 's' : ''}
          {' · '}
          {filtered.length.toLocaleString()} flow{filtered.length !== 1 ? 's' : ''}
        </span>
        <button
          onClick={() => setShowAll(v => !v)}
          className="ml-auto text-[10px] px-2 py-0.5 rounded transition-colors"
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

      {/* Canvas */}
      <div ref={containerRef} className="flex-1 relative overflow-hidden">
        {isEmpty ? (
          <div className="flex items-center justify-center h-full text-sm text-muted-foreground">
            {alerts.length === 0 ? 'Waiting for traffic…' : 'No alerts to display'}
          </div>
        ) : (
          <svg width={dims.w} height={dims.h} className="absolute inset-0">
            <defs>
              {(['INFO', 'HIGH', 'CRITICAL'] as Severity[]).map(sev => (
                <marker
                  key={sev}
                  id={`arr-${sev}`}
                  markerWidth={8} markerHeight={6}
                  refX={7} refY={3}
                  orient="auto"
                >
                  <polygon
                    points="0 0, 8 3, 0 6"
                    fill={SEV_COLOUR[sev]}
                    opacity={0.8}
                  />
                </marker>
              ))}
            </defs>

            {/* Edges */}
            {edges.map(e => {
              const s = positions.get(e.source)
              const t = positions.get(e.target)
              if (!s || !t) return null
              const sR = nodeRadius(nodes.find(n => n.id === e.source)?.flowCount ?? 1)
              const tR = nodeRadius(nodes.find(n => n.id === e.target)?.flowCount ?? 1)
              const { x: x1, y: y1 } = shrinkFrom(s, t, sR + 2)
              const { x: x2, y: y2 } = shrinkFrom(t, s, tR + 10)
              const sw = Math.max(1, Math.min(4, 1 + Math.log2(e.flowCount + 1)))
              return (
                <line
                  key={`${e.source}→${e.target}`}
                  x1={x1} y1={y1} x2={x2} y2={y2}
                  stroke={SEV_COLOUR[e.peakSev]}
                  strokeWidth={sw}
                  strokeOpacity={0.5}
                  markerEnd={`url(#arr-${e.peakSev})`}
                />
              )
            })}

            {/* Nodes */}
            {nodes.map(n => {
              const p = positions.get(n.id)
              if (!p) return null
              const r = nodeRadius(n.flowCount)
              return (
                <g
                  key={n.id}
                  style={{ cursor: 'default' }}
                  onMouseEnter={ev => {
                    setHovered(n)
                    const rect = containerRef.current!.getBoundingClientRect()
                    setHoverPos({ x: ev.clientX - rect.left + 14, y: ev.clientY - rect.top - 8 })
                  }}
                  onMouseLeave={() => setHovered(null)}
                >
                  <circle
                    cx={p.x} cy={p.y} r={r}
                    fill={SEV_COLOUR[n.peakSev]}   fillOpacity={0.18}
                    stroke={SEV_COLOUR[n.peakSev]} strokeWidth={1.5}
                  />
                  <text
                    x={p.x} y={p.y + r + 11}
                    textAnchor="middle"
                    fontSize={9}
                    fill="var(--color-muted-foreground, #888)"
                    className="select-none pointer-events-none"
                  >
                    {n.id}
                  </text>
                </g>
              )
            })}
          </svg>
        )}

        {/* Hover tooltip */}
        {hovered && (
          <div
            className="absolute z-10 pointer-events-none border bg-card px-2.5 py-1.5 text-xs shadow-lg"
            style={{
              left:         hoverPos.x,
              top:          hoverPos.y,
              borderColor:  SEV_COLOUR[hovered.peakSev],
              borderRadius: 'var(--radius)',
            }}
          >
            <div className="font-mono font-semibold">{hovered.id}</div>
            <div className="text-muted-foreground mt-0.5">
              {hovered.flowCount} flow{hovered.flowCount !== 1 ? 's' : ''}
              {' · '}peak {(hovered.peakScore * 100).toFixed(1)}%
            </div>
            <div style={{ color: SEV_COLOUR[hovered.peakSev] }}>{hovered.peakSev}</div>
          </div>
        )}
      </div>
    </div>
  )
}