import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import Tree from 'react-d3-tree'
import type { CustomNodeElementProps, RawNodeDatum } from 'react-d3-tree'
import { apiFetch } from '../../lib/utils'
import { G3 } from '../grid/g3'

// ── types ─────────────────────────────────────────────────────────────────────

interface ApiNode {
  type:       'split' | 'leaf'
  feature?:   string
  threshold?: number
  samples:    number
  depth?:     number
  left?:      ApiNode
  right?:     ApiNode
}

interface Snapshot {
  proto:       string
  model:       number
  window_size: number
  tree_index:  number
  max_depth:   number
  n_trained:   number
  tree:        ApiNode
}

// ── constants ─────────────────────────────────────────────────────────────────

const POLL_MS = 3000

// Fixed palette — independent of CSS theme variables so SVG attrs work
const C = {
  splitFill:   '#1e3a5f',
  splitStroke: '#93c4e0',
  leafFill:    '#1b4332',
  leafStroke:  '#95d5b2',
  edge:        '#374151',
  branchL:     '#52b788',
  branchR:     '#e63946',
  text:        '#f8fafc',
  muted:       '#94a3b8',
} as const

const WINDOW_LABELS: Record<number, string> = {
  0: 'Fast — 256',
  1: 'Medium — 1 024',
  2: 'Slow — 4 096',
}

// ── data transform ────────────────────────────────────────────────────────────

function fmt(t: number): string {
  if (t === 0) return '0'
  if (Math.abs(t) >= 1e4 || Math.abs(t) < 0.01) return t.toExponential(2)
  return String(parseFloat(t.toPrecision(4)))
}

function toD3(node: ApiNode, branch = ''): RawNodeDatum {
  if (node.type === 'leaf') {
    return {
      name: 'leaf',
      attributes: { n: node.samples, _b: branch },
    }
  }
  return {
    name: node.feature!,
    attributes: { thr: fmt(node.threshold!), n: node.samples, _b: branch },
    children: [toD3(node.left!, '≤'), toD3(node.right!, '>')],
  }
}

// ── custom SVG node ───────────────────────────────────────────────────────────

function NodeEl({ nodeDatum }: CustomNodeElementProps) {
  const isLeaf   = nodeDatum.name === 'leaf'
  const branch   = String(nodeDatum.attributes?._b ?? '')
  const n        = nodeDatum.attributes?.n
  const thr      = String(nodeDatum.attributes?.thr ?? '')
  const branchColor = branch === '≤' ? C.branchL : branch === '>' ? C.branchR : 'transparent'

  return (
    <g>
      {branch !== '' && (
        <text y={-30} textAnchor="middle" fontSize={9} fontWeight="700" fill={branchColor}>
          {branch}
        </text>
      )}
      {isLeaf ? (
        <>
          <rect x={-38} y={-20} width={76} height={40} rx={5}
            fill={C.leafFill} stroke={C.leafStroke} strokeWidth={1.5} />
          <text y={-5} textAnchor="middle" fontSize={10} fontWeight="700" fill={C.leafStroke}>leaf</text>
          <text y={10} textAnchor="middle" fontSize={9} fill={C.muted}>n = {n}</text>
        </>
      ) : (
        <>
          <rect x={-54} y={-28} width={108} height={56} rx={5}
            fill={C.splitFill} stroke={C.splitStroke} strokeWidth={1.5} />
          <text y={-12} textAnchor="middle" fontSize={10} fontWeight="700" fill={C.text}>
            {nodeDatum.name}
          </text>
          <text y={2} textAnchor="middle" fontSize={9} fill={C.splitStroke}>≤ {thr}</text>
          <text y={17} textAnchor="middle" fontSize={8} fill={C.muted}>n = {n}</text>
        </>
      )}
    </g>
  )
}

// ── control helpers ───────────────────────────────────────────────────────────

const btnBase: React.CSSProperties = {
  border: 'none', cursor: 'pointer', borderRadius: 4,
  fontSize: 10, padding: '2px 8px', lineHeight: '18px',
}

function ToggleBtn({
  active, onClick, children,
}: {
  active: boolean; onClick: () => void; children: React.ReactNode
}) {
  return (
    <button
      onClick={onClick}
      style={{
        ...btnBase,
        background: active
          ? `color-mix(in srgb, ${G3.accent} 18%, transparent)`
          : 'transparent',
        border: `1px solid ${active ? G3.accent : G3.line}`,
        color:  active ? G3.accent : G3.mute,
        fontWeight: active ? 600 : 400,
      }}
    >
      {children}
    </button>
  )
}

// ── module ────────────────────────────────────────────────────────────────────

export function ModTree() {
  const [proto,   setProto]   = useState<'TCP' | 'UDP'>('TCP')
  const [model,   setModel]   = useState(2)
  const [treeIdx, setTreeIdx] = useState(0)
  const [depth,   setDepth]   = useState(4)

  const [snapshot,  setSnapshot]  = useState<Snapshot | null>(null)
  const [error,     setError]     = useState<string | null>(null)
  const [updatedAt, setUpdatedAt] = useState(0)

  const nTrainedRef  = useRef(-1)
  const containerRef = useRef<HTMLDivElement>(null)
  const [translate,  setTranslate] = useState({ x: 240, y: 70 })

  // Center tree horizontally whenever container width changes
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const obs = new ResizeObserver(entries => {
      const w = entries[0].contentRect.width
      setTranslate(t => ({ ...t, x: w / 2 }))
    })
    obs.observe(el)
    return () => obs.disconnect()
  }, [])

  // 3 s poll with n_trained guard
  useEffect(() => {
    let dead = false
    nTrainedRef.current = -1  // reset on any control change

    const poll = async () => {
      if (dead) return
      try {
        const r = await apiFetch(
          `/dev/tree_snapshot?proto=${proto}&model=${model}&tree=${treeIdx}&max_depth=${depth}`
        )
        if (dead) return
        if (r.status === 503) { setError('Baseline not complete yet'); return }
        if (!r.ok)            { setError(`HTTP ${r.status}`);          return }
        const data: Snapshot = await r.json()
        if (dead) return
        setError(null)
        if (data.n_trained !== nTrainedRef.current) {
          nTrainedRef.current = data.n_trained
          setSnapshot(data)
          setUpdatedAt(Date.now())
        }
      } catch {
        if (!dead) setError('Inference engine unreachable')
      }
    }

    poll()
    const id = setInterval(poll, POLL_MS)
    return () => { dead = true; clearInterval(id) }
  }, [proto, model, treeIdx, depth])

  // "Xs ago" label — updated every 5 s
  const [elapsed, setElapsed] = useState('')
  useEffect(() => {
    if (!updatedAt) return
    const tick = () => {
      const s = Math.floor((Date.now() - updatedAt) / 1000)
      setElapsed(s < 60 ? `${s}s ago` : `${Math.floor(s / 60)}m ago`)
    }
    tick()
    const id = setInterval(tick, 5000)
    return () => clearInterval(id)
  }, [updatedAt])

  const d3Data = useMemo(
    () => snapshot ? toD3(snapshot.tree) : null,
    [snapshot],
  )

  const renderNode = useCallback(
    (props: CustomNodeElementProps) => <NodeEl {...props} />,
    [],
  )

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      {/* ── Controls ── */}
      <div style={{
        padding: '6px 10px', flexShrink: 0,
        borderBottom: `1px solid ${G3.line}`,
        display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap',
      }}>

        {/* Protocol */}
        <div style={{ display: 'flex', gap: 3 }}>
          {(['TCP', 'UDP'] as const).map(p => (
            <ToggleBtn key={p} active={proto === p} onClick={() => setProto(p)}>{p}</ToggleBtn>
          ))}
        </div>

        <div style={{ width: 1, height: 16, background: G3.line }} />

        {/* Window */}
        <div style={{ display: 'flex', gap: 3 }}>
          {([0, 1, 2] as const).map(i => (
            <ToggleBtn key={i} active={model === i} onClick={() => setModel(i)}>
              {['256', '1K', '4K'][i]}
            </ToggleBtn>
          ))}
        </div>

        <div style={{ width: 1, height: 16, background: G3.line }} />

        {/* Tree index */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <span style={{ fontSize: 9, color: G3.mute }}>Tree</span>
          <button
            style={{ ...btnBase, border: `1px solid ${G3.line}`, background: 'transparent', color: G3.mute, padding: '2px 6px' }}
            onClick={() => setTreeIdx(i => Math.max(0, i - 1))}
          >‹</button>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: G3.fg, minWidth: 20, textAlign: 'center' }}>
            {treeIdx}
          </span>
          <button
            style={{ ...btnBase, border: `1px solid ${G3.line}`, background: 'transparent', color: G3.mute, padding: '2px 6px' }}
            onClick={() => setTreeIdx(i => Math.min(31, i + 1))}
          >›</button>
        </div>

        <div style={{ width: 1, height: 16, background: G3.line }} />

        {/* Depth */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <span style={{ fontSize: 9, color: G3.mute }}>Depth</span>
          <input
            type="range" min={1} max={7} value={depth}
            onChange={e => setDepth(Number(e.target.value))}
            style={{ width: 60, accentColor: G3.accent, cursor: 'pointer' }}
          />
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: G3.fg, minWidth: 10 }}>
            {depth}
          </span>
        </div>
      </div>

      {/* ── Status ── */}
      {snapshot && !error && (
        <div style={{
          padding: '3px 10px', flexShrink: 0, fontSize: 9, color: G3.mute,
          borderBottom: `1px solid color-mix(in srgb, ${G3.line} 40%, transparent)`,
          display: 'flex', gap: 14,
        }}>
          <span>{WINDOW_LABELS[snapshot.model]}</span>
          <span>
            n_trained:&nbsp;
            <span style={{ fontFamily: 'JetBrains Mono, monospace', color: G3.fg }}>
              {snapshot.n_trained.toLocaleString()}
            </span>
          </span>
          {elapsed && <span>updated {elapsed}</span>}
          <span style={{ marginLeft: 'auto', color: G3.mute }}>
            scroll to zoom · drag to pan
          </span>
        </div>
      )}

      {/* ── Tree canvas ── */}
      <div ref={containerRef} style={{ flex: 1, minHeight: 0, position: 'relative' }}>
        {(error || !d3Data) && (
          <div style={{
            position: 'absolute', inset: 0,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: error ? G3.high : G3.mute, fontSize: 11, fontStyle: 'italic',
          }}>
            {error ?? 'Loading…'}
          </div>
        )}
        {d3Data && (
          <Tree
            data={d3Data}
            orientation="vertical"
            pathFunc="step"
            translate={translate}
            zoom={0.85}
            scaleExtent={{ min: 0.2, max: 3 }}
            nodeSize={{ x: 140, y: 100 }}
            separation={{ siblings: 1.1, nonSiblings: 1.4 }}
            renderCustomNodeElement={renderNode}
            pathClassFunc={() => 'oif-link'}
            enableLegacyTransitions
            transitionDuration={300}
          />
        )}
      </div>
    </div>
  )
}
