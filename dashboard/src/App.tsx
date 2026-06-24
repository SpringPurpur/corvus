import { useEffect, useMemo, useRef, useState } from 'react'
import type { Alert, AppConfig, WsMessage, FeedbackMsg, LlmRequestMsg } from './types'
import { useWebSocket } from './hooks/useWebSocket'
import { useAlerts }    from './hooks/useAlerts'
import { SettingsPanel } from './components/SettingsPanel'
import { ThemeProvider }  from './context/ThemeContext'

import { apiFetch } from './lib/utils'
import { G3, alpha } from './components/grid/g3'
import { GridContainer } from './components/grid/GridContainer'
import { Module } from './components/grid/Module'
import type { ModuleSize, ModuleConstraint } from './components/grid/Module'

import { ModKPI }       from './components/modules/ModKPI'
import { ModPulse }     from './components/modules/ModPulse'
import { ModHealth }    from './components/modules/ModHealth'
import { ModEntities }  from './components/modules/ModEntities'
import { ModStream }    from './components/modules/ModStream'
import { ModDetail }    from './components/modules/ModDetail'
import { ModLLM }       from './components/modules/ModLLM'
import { ModTimeline }  from './components/modules/ModTimeline'
import { ModHeatmap }   from './components/modules/ModHeatmap'
import { ModConsensus } from './components/modules/ModConsensus'
import { ModTopology }  from './components/modules/ModTopology'
import { ModTree }      from './components/modules/ModTree'

// ─── module registry ────────────────────────────────────────────────────────

type ModuleId =
  | 'kpi' | 'pulse' | 'health' | 'entities'
  | 'stream' | 'detail' | 'llm'
  | 'timeline' | 'heatmap' | 'consensus' | 'topology' | 'tree'

const ALL_IDS: ModuleId[] = [
  'kpi', 'pulse', 'health', 'entities',
  'stream', 'detail', 'llm',
  'timeline', 'heatmap', 'consensus', 'topology', 'tree',
]

const CONSTRAINTS: Record<ModuleId, ModuleConstraint> = {
  kpi:       { min: { cols: 4, rows: 2 }, max: { cols: 12, rows: 3 } },
  pulse:     { min: { cols: 4, rows: 2 }, max: { cols: 12, rows: 4 } },
  health:    { min: { cols: 2, rows: 1 }, max: { cols: 6,  rows: 3 } },
  entities:  { min: { cols: 3, rows: 2 }, max: { cols: 6,  rows: 6 } },
  stream:    { min: { cols: 4, rows: 2 }, max: { cols: 12, rows: 6 } },
  detail:    { min: { cols: 3, rows: 2 }, max: { cols: 6,  rows: 6 } },
  llm:       { min: { cols: 3, rows: 2 }, max: { cols: 8,  rows: 6 } },
  timeline:  { min: { cols: 6, rows: 2 }, max: { cols: 12, rows: 4 } },
  heatmap:   { min: { cols: 4, rows: 1 }, max: { cols: 12, rows: 3 } },
  consensus: { min: { cols: 3, rows: 2 }, max: { cols: 8,  rows: 4 } },
  topology:  { min: { cols: 3, rows: 2 }, max: { cols: 8,  rows: 5 } },
  tree:      { min: { cols: 4, rows: 3 }, max: { cols: 12, rows: 7 } },
}

const DEFAULT_SIZES: Record<ModuleId, ModuleSize> = {
  kpi:       { cols: 12, rows: 2 },
  pulse:     { cols: 7,  rows: 2 },
  health:    { cols: 2,  rows: 2 },
  entities:  { cols: 3,  rows: 2 },
  stream:    { cols: 5,  rows: 3 },
  detail:    { cols: 3,  rows: 3 },
  llm:       { cols: 4,  rows: 3 },
  timeline:  { cols: 8,  rows: 2 },
  heatmap:   { cols: 12, rows: 2 },
  consensus: { cols: 4,  rows: 2 },
  topology:  { cols: 4,  rows: 3 },
  tree:      { cols: 6,  rows: 4 },
}

const DEFAULT_ORDER: ModuleId[] = [
  'kpi',
  'pulse', 'health', 'entities',
  'stream', 'detail', 'llm',
  'consensus', 'topology', 'tree', 'timeline',
  'heatmap',
]

// topology, consensus, tree are hidden by default to keep the initial view clean
const DEFAULT_HIDDEN = new Set<ModuleId>(['topology', 'consensus', 'tree'])

// Accumulated LLM responses keyed by request_id — grows per session, stable ref
const llmResponses: Record<string, string> = {}

// ─── module metadata ─────────────────────────────────────────────────────────

type ModuleMeta = {
  title:    string
  subtitle: string
  about:    string
  badge?:   (alerts: Alert[]) => React.ReactNode
  hot?:     (alerts: Alert[]) => boolean
}

const MODULE_META: Record<ModuleId, ModuleMeta> = {
  kpi: {
    title:    'At-a-glance',
    subtitle: 'Live counts · 24 h OIF ribbon',
    about:    'Shows top-level metrics for the current session: flows detected in the last 60 seconds, total critical and high severity alerts, OIF baseline status, and inference queue depth. When resized to 2+ rows, a 24-hour OIF score ribbon appears below — three coloured rows (fast 256 / medium 1 024 / slow 4 096 windows) in 5-minute buckets, green → amber → red as scores rise.',
  },
  pulse: {
    title:    'Network pulse',
    subtitle: 'OIF composite score over time',
    about:    'Plots the OIF composite anomaly score over the last 10 minutes. Fetches /window_history for both TCP and UDP in 30-second buckets (refreshed every 30 s), merging them by taking the max peak score per bucket so the area always reflects the worst-case anomaly level across both protocols. The monochromatic fill fades with a glowing top-edge stroke. Individual alerts in the window are overlaid as small coloured dots positioned on the y-axis by their OIF confidence score and coloured by severity — up to 60 dots sampled uniformly across the window.',
    badge:    () => <span style={{ marginLeft: 6, fontSize: 9, color: G3.ok }}>● live</span>,
  },
  health: {
    title:    'Model health',
    subtitle: 'OIF rejection rate per protocol',
    about:    'Shows the health of each OIF protocol model (TCP and UDP separately). The primary metric is rejection rate — the fraction of recently scored flows whose composite score exceeded the anomaly threshold. Green < 5%, amber 5–15%, red > 15%. The sparkline shows the last 20 composite scores, and p50/p95 percentiles give a quick distribution read.',
  },
  entities: {
    title:    'Top hosts',
    subtitle: 'by peak anomaly score · click to filter stream',
    about:    'Groups all ingested flows by source IP and ranks hosts by their peak OIF anomaly confidence score. The bar sparkline shows each host\'s last 8 confidence scores over time. Click an IP to filter the Anomaly Stream to only flows from that host — click again to clear the filter.',
  },
  stream: {
    title:    'Anomaly stream',
    subtitle: 'filter · pause · bulk dismiss',
    about:    'Live feed of anomalous flows, newest first. By default shows only HIGH and CRITICAL alerts — click "HIGH+" to also include INFO flows. Use the search box to filter by any IP address or port number. The ⏸ button freezes the list so you can inspect rows without new alerts pushing them out of view; a "+N" badge counts new arrivals while paused. Checkboxes allow bulk-dismissal of false positives, which sends a POST /feedback/bulk to the inference engine and re-trains the OIF model on the corrected labels.',
    hot:      (alerts) => alerts.some(a => a.verdict.severity === 'CRITICAL'),
    badge:    (alerts) => {
      const n = alerts.filter(a => a.verdict.severity === 'CRITICAL').length
      return n > 0
        ? <span style={{ marginLeft: 6, fontSize: 9, padding: '1px 5px', background: G3.critBg, color: G3.crit, borderRadius: 2 }}>{n} critical</span>
        : null
    },
  },
  detail: {
    title:    'Anomaly detail',
    subtitle: 'attribution bars · feature radar',
    about:    'Shows full metadata for the selected alert: severity badge, source → destination endpoint, four stat cards (OIF score, packet count, flow duration, protocol), and OIF path-depth attribution bars. Each attribution bar shows the feature name, its raw value, and how much it contributed to the anomaly score. The baseline median ± IQR/2 subtext shows where normal traffic sits. When 3 or more attribution features are present, a spider/radar chart appears — each axis encodes how many IQRs that feature\'s value sits away from the baseline median (grey band = 1 IQR normal range; outer ring = 4 IQRs).',
  },
  llm: {
    title:    'LLM analysis',
    subtitle: 'conversation · on-demand · Claude',
    about:    'On-demand Claude analysis of the selected anomaly. Press "Explain anomaly" to send the selected alert\'s OIF attribution and flow metadata to the Claude API for a plain-English explanation of why this flow was flagged. After the first explanation you can ask follow-up questions — the conversation retains context across turns. The "Full features" checkbox includes the full raw feature vector in the prompt for richer but more token-intensive analysis. Approximately 800 tokens per explain call.',
  },
  timeline: {
    title:    'Swim-lane timeline',
    subtitle: 'per-IP lanes · range slider to scrub',
    about:    'Shows one horizontal swim-lane per active source IP (up to 7 lanes depending on widget height, most active hosts first). Each dot represents an anomalous flow positioned by its timestamp on a normalised 0–100% axis. Dot size and colour encode severity (CRITICAL larger, red; HIGH smaller, amber). The mini histogram at the bottom shows alert density across 40 time buckets, also coloured by peak severity. The range slider moves a vertical reference cursor across all lanes simultaneously — useful for correlating which IPs had activity at a specific moment in the session.',
  },
  heatmap: {
    title:    'Port × time heatmap',
    subtitle: 'dst port rows · time columns · hover for detail',
    about:    'A two-dimensional heatmap: rows are destination ports (top active ports from traffic plus ANCHOR_PORTS = 443, 80, 22, 445, 53, 3389, 8080, 8443), columns are equal-width time buckets across the session window. Each cell\'s colour encodes the maximum severity of alerts in that slot (cyan = mixed/low, amber = HIGH, red = CRITICAL), and opacity encodes the alert count. Hover a non-empty cell to see a tooltip listing the time range, flow count, critical count, and the top contributing source IPs.',
  },
  consensus: {
    title:    'Window consensus',
    subtitle: 'fast / medium / slow OIF agreement',
    about:    'Compares the three OIF window sizes on the most recent alert. Fast (256 flows), medium (1 024 flows), and slow (4 096 flows) windows each maintain an independent Isolation Forest. The three cells show each window\'s score as a percentage, coloured green / amber / red against the configured thresholds. The divergence sparkline below tracks max − min spread across the last 60 alerts: low divergence means all windows agree (either all calm or all alarmed); high divergence means the detector is in a transient state, often seen when a novel attack pattern first appears or when normal traffic behaviour shifts abruptly.',
  },
  topology: {
    title:    'Network topology',
    subtitle: 'flow graph · hover to highlight connections',
    about:    'Visualises network flows as a graph. The most active IP addresses (up to 16) are placed in a circle; edges connect source → destination pairs seen in the ingested flows. Node radius scales logarithmically with alert count; node and edge colour encode peak severity (cyan = mixed, amber = HIGH, red = CRITICAL). Edge opacity scales with flow count between that pair. Hover a node to dim all unrelated edges and highlight that host\'s direct connections. Abbreviated labels show the last two octets of each IPv4 address.',
  },
  tree: {
    title:    'OIF tree viewer',
    subtitle: 'live isolation tree · scroll to zoom · drag to pan',
    about:    'Renders a single decision tree from the Online Isolation Forest in real-time. Select protocol (TCP/UDP), window size (Fast 256 / Medium 1 024 / Slow 4 096), tree index (0–31), and max depth (1–7). The tree polls /dev/tree_snapshot every 3 s but only re-renders when n_trained changes, so there is no visual flicker during idle periods. Blue nodes are internal split nodes (feature name + split threshold + sample count); green nodes are leaves. Branch labels ≤ (green) and > (red) indicate the split direction. Scroll to zoom, drag to pan.',
  },
}

// ─── modules picker panel ────────────────────────────────────────────────────

function ModulesPicker({
  hiddenModules,
  setHiddenModules,
  onClose,
}: {
  hiddenModules: Set<ModuleId>
  setHiddenModules: (fn: (prev: Set<ModuleId>) => Set<ModuleId>) => void
  onClose: () => void
}) {
  return (
    <div
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 500 }}
      onClick={e => { if (e.target === e.currentTarget) onClose() }}
    >
      <div style={{ background: G3.card, border: `1px solid ${G3.line}`, borderRadius: 10, padding: 20, width: 360, maxHeight: '80vh', overflow: 'auto', boxShadow: '0 8px 32px rgba(0,0,0,0.5)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ fontSize: 13, fontWeight: 600, color: G3.fg, margin: 0 }}>Dashboard Modules</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: G3.mute2, cursor: 'pointer', fontSize: 18, lineHeight: 1 }}>×</button>
        </div>
        <div style={{ fontSize: 10, color: G3.mute, marginBottom: 12 }}>
          Toggle modules on or off. Drag module headers to reorder, resize from the bottom-right corner.
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {ALL_IDS.map(id => {
            const meta   = MODULE_META[id]
            const hidden = hiddenModules.has(id)
            return (
              <label
                key={id}
                style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  padding: '8px 10px', borderRadius: 6, cursor: 'pointer',
                  background: hidden ? 'transparent' : G3.card2,
                  border:     `1px solid ${hidden ? G3.line + '50' : G3.line}`,
                  opacity:    hidden ? 0.6 : 1,
                  transition: 'opacity 120ms, background 120ms',
                }}
              >
                <input
                  type="checkbox"
                  checked={!hidden}
                  onChange={() => {
                    setHiddenModules(prev => {
                      const next = new Set(prev)
                      if (hidden) next.delete(id)
                      else next.add(id)
                      return next
                    })
                  }}
                  style={{ width: 13, height: 13, accentColor: G3.accent, flexShrink: 0, cursor: 'pointer' }}
                />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: G3.fg, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{meta.title}</div>
                  <div style={{ fontSize: 9, color: G3.mute, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{meta.subtitle}</div>
                </div>
              </label>
            )
          })}
        </div>
      </div>
    </div>
  )
}

// ─── status dot ─────────────────────────────────────────────────────────────

function StatusDot({ ok, warn, label, pulse }: { ok: boolean; warn?: boolean; label: string; pulse?: boolean }) {
  const color = ok ? G3.ok : warn ? G3.high : G3.mute
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, color: G3.mute2 }}>
      <span style={{
        width: 6, height: 6, borderRadius: '50%',
        background: color,
        display: 'inline-block',
        animation: pulse ? 'corvus-pulse 2s infinite' : 'none',
      }} />
      {label}
    </div>
  )
}

// ─── main app ────────────────────────────────────────────────────────────────

function AppInner() {
  const [selected, setSelected]           = useState<Alert | null>(null)
  const [entityFilter, setEntityFilter]   = useState<string | null>(null)
  const [showAll, setShowAll]             = useState(false)
  const [protoFilter, setProtoFilter]     = useState<Set<'TCP' | 'UDP'>>(new Set(['TCP', 'UDP']))
  const [showSettings, setShowSettings]   = useState(false)
  const [showModules, setShowModules]     = useState(false)
  const [hiddenModules, setHiddenModules] = useState<Set<ModuleId>>(() => {
    try {
      const s = localStorage.getItem('corvus-grid-v1')
      if (s) {
        const p = JSON.parse(s)
        if (Array.isArray(p.hidden)) return new Set<ModuleId>(p.hidden)
      }
    } catch { /* ignore */ }
    return DEFAULT_HIDDEN
  })
  const [, forceRender]                   = useState(0)
  const [llmReady, setLlmReady]       = useState(false)
  const [needsApiKey, setNeedsApiKey] = useState(false)
  const [apiKeyInput, setApiKeyInput]     = useState('')
  const [t, setT]                         = useState(62)
  const [thHigh, setThHigh]               = useState(0.5)
  const [thCrit, setThCrit]               = useState(0.7)
  const [baselineTcp, setBaselineTcp]     = useState(4096)
  const [baselineUdp, setBaselineUdp]     = useState(4096)

  // Grid state — persisted to localStorage under 'corvus-grid-v1'
  const [order, setOrder] = useState<ModuleId[]>(() => {
    try {
      const s = localStorage.getItem('corvus-grid-v1')
      if (s) {
        const p = JSON.parse(s)
        if (Array.isArray(p.order) && p.order.every((x: unknown) => ALL_IDS.includes(x as ModuleId)))
          return p.order as ModuleId[]
      }
    } catch { /* ignore */ }
    return DEFAULT_ORDER
  })
  const [sizes, setSizes] = useState<Record<ModuleId, ModuleSize>>(() => {
    try {
      const s = localStorage.getItem('corvus-grid-v1')
      if (s) {
        const p = JSON.parse(s)
        if (p.sizes && typeof p.sizes === 'object') return { ...DEFAULT_SIZES, ...p.sizes }
      }
    } catch { /* ignore */ }
    return DEFAULT_SIZES
  })
  const dragIdRef         = useRef<ModuleId | null>(null)
  const [dragId, setDragId] = useState<ModuleId | null>(null)
  const [overId, setOverId] = useState<ModuleId | null>(null)

  const notifyEnabledRef  = useRef(false)
  const notifyCooldownRef = useRef(false)
  const notifyQueuedRef   = useRef(0)

  const {
    tcp, udp, tcpHealth, udpHealth,
    captureUp, modelsLoaded, baselining, baselineProgress,
    queueDepth, handleMessage, loadHistory, clearAlerts,
  } = useAlerts()

  const allAlerts = useMemo(() => [...tcp, ...udp], [tcp, udp])

  // Persist grid layout to localStorage whenever it changes
  useEffect(() => {
    try {
      localStorage.setItem('corvus-grid-v1', JSON.stringify({
        order,
        sizes,
        hidden: [...hiddenModules],
      }))
    } catch { /* ignore quota errors */ }
  }, [order, sizes, hiddenModules])

  // Visible order excludes hidden modules
  const visibleOrder = order.filter(id => !hiddenModules.has(id))

  // ── startup ──────────────────────────────────────────────────────────────

  useEffect(() => {
    apiFetch('/config').then(r => {
      if (r.status === 401) { setNeedsApiKey(true); return null }
      return r.json()
    }).then((d: AppConfig | null) => {
      if (d) {
        setThHigh(d.threshold_high)
        setThCrit(d.threshold_critical)
        setBaselineTcp(d.baseline_tcp)
        setBaselineUdp(d.baseline_udp)
      }
    }).catch(() => {})
    apiFetch('/llm/status').then(r => r.json()).then(d => setLlmReady(!!d.available)).catch(() => {})
  }, [])

  useEffect(() => { loadHistory() }, [loadHistory])

  useEffect(() => {
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission()
    }
    const timer = setTimeout(() => { notifyEnabledRef.current = true }, 4000)
    return () => clearTimeout(timer)
  }, [])

  useEffect(() => {
    const n = allAlerts.filter(a => a.verdict.severity === 'CRITICAL').length
    document.title = n > 0 ? `(${n}) Corvus IDS` : 'Corvus IDS'
  }, [allAlerts])

  // ── WebSocket ─────────────────────────────────────────────────────────────

  const onMessage = (msg: WsMessage) => {
    if (msg.type === 'llm_response') {
      llmResponses[msg.request_id] = msg.text
      forceRender(n => n + 1)
      return
    }
    if (
      msg.type === 'alert' &&
      notifyEnabledRef.current &&
      msg.data.verdict?.severity === 'CRITICAL' &&
      'Notification' in window &&
      Notification.permission === 'granted'
    ) {
      if (!notifyCooldownRef.current) {
        notifyCooldownRef.current = true
        notifyQueuedRef.current   = 0
        new Notification('Corvus IDS — Critical Alert', {
          body: `${msg.data.src_ip} → ${msg.data.dst_ip}:${msg.data.dst_port}  (score ${msg.data.verdict.confidence?.toFixed(2) ?? '?'})`,
          icon: '/favicon.ico',
          tag:  'corvus-critical',
        })
        setTimeout(() => {
          const queued = notifyQueuedRef.current
          notifyCooldownRef.current = false
          notifyQueuedRef.current   = 0
          if (queued > 0) {
            new Notification('Corvus IDS — Critical Alerts', {
              body: `${queued} more critical alert${queued === 1 ? '' : 's'} since last notification.`,
              icon: '/favicon.ico',
              tag:  'corvus-critical',
            })
          }
        }, 10_000)
      } else {
        notifyQueuedRef.current += 1
      }
    }
    handleMessage(msg)
  }

  const { connected, send } = useWebSocket(onMessage)

  // ── grid drag-to-reorder ─────────────────────────────────────────────────

  const onResize = (id: string, size: ModuleSize) =>
    setSizes(s => ({ ...s, [id as ModuleId]: size }))

  const onReorderStart = (id: string) => {
    dragIdRef.current = id as ModuleId
    setDragId(id as ModuleId)
    setOverId(id as ModuleId)
  }

  const onReorderOver = (id: string) => {
    const dId = dragIdRef.current
    if (!dId) return
    setOverId(id as ModuleId)
    if (id === dId) return
    setOrder(cur => {
      const from = cur.indexOf(dId)
      const to   = cur.indexOf(id as ModuleId)
      if (from < 0 || to < 0 || from === to) return cur
      const next = [...cur]
      next.splice(from, 1)
      next.splice(to, 0, dId)
      return next
    })
  }

  const onReorderEnd = () => {
    dragIdRef.current = null
    setDragId(null)
    setOverId(null)
  }

  const removeModule = (id: ModuleId) => {
    setHiddenModules(prev => new Set([...prev, id]))
  }

  // ── API key gate ─────────────────────────────────────────────────────────

  if (needsApiKey) {
    return (
      <div style={{ position: 'fixed', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', background: G3.bg }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, padding: 24, border: `1px solid ${G3.line}`, background: G3.card, borderRadius: 10, width: 320 }}>
          <h2 style={{ fontSize: 13, fontWeight: 600, color: G3.fg, margin: 0 }}>API Key Required</h2>
          <p style={{ fontSize: 11, color: G3.mute2, lineHeight: 1.5, margin: 0 }}>
            This Corvus instance requires authentication.<br />
            Enter the key set in <span style={{ fontFamily: 'JetBrains Mono, ui-monospace, monospace' }}>CORVUS_API_KEY</span>.
          </p>
          <input
            type="password" autoFocus
            value={apiKeyInput}
            onChange={e => setApiKeyInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && apiKeyInput.trim()) {
                sessionStorage.setItem('corvus_api_key', apiKeyInput.trim())
                window.location.reload()
              }
            }}
            placeholder="corvus-api-key"
            style={{ background: G3.card2, border: `1px solid ${G3.line}`, borderRadius: 5, padding: '6px 10px', fontSize: 12, color: G3.fg, outline: 'none' }}
          />
          <button
            onClick={() => {
              if (!apiKeyInput.trim()) return
              sessionStorage.setItem('corvus_api_key', apiKeyInput.trim())
              window.location.reload()
            }}
            style={{ padding: '7px 14px', fontSize: 12, fontWeight: 600, background: G3.accent, color: G3.bg, border: 'none', borderRadius: 5, cursor: 'pointer' }}
          >
            Connect
          </button>
        </div>
      </div>
    )
  }

  // ── render ───────────────────────────────────────────────────────────────

  const critCount = allAlerts.filter(a => a.verdict.severity === 'CRITICAL').length

  return (
    <div style={{ width: '100%', height: '100%', display: 'flex', flexDirection: 'column', background: G3.bg, color: G3.fg, fontFamily: 'Inter, ui-sans-serif, system-ui, sans-serif', fontSize: 12, overflow: 'hidden' }}>

      {/* ── Header ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 18px', background: G3.card, borderBottom: `1px solid ${G3.line}`, flexShrink: 0, gap: 12, flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, minWidth: 0 }}>
          <span style={{ fontSize: 15, fontWeight: 700, letterSpacing: '-0.01em', whiteSpace: 'nowrap', color: G3.fg }}>
            ⬡ Corvus
          </span>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <StatusDot ok={connected}     label="WebSocket" pulse />
            <StatusDot ok={captureUp}     label="Capture"   pulse={captureUp} />
            <StatusDot ok={modelsLoaded && !baselining} warn={baselining} label={baselining ? `Baselining ${Math.round(baselineProgress * 100)}%` : 'Models'} pulse={baselining} />
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 10, flexWrap: 'wrap' }}>
          {critCount > 0 && (
            <span style={{ padding: '3px 9px', background: G3.critBg, borderRadius: 5, color: G3.crit, fontWeight: 600, whiteSpace: 'nowrap' }}>
              {critCount} critical
            </span>
          )}
          <span style={{ padding: '3px 9px', background: G3.card2, borderRadius: 5, color: G3.mute2, display: 'inline-flex', gap: 6, alignItems: 'center', whiteSpace: 'nowrap' }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: connected ? G3.ok : G3.mute, display: 'inline-block' }} />
            {allAlerts.length} flows
          </span>
          <button
            onClick={() => apiFetch('/queue', { method: 'DELETE' }).catch(() => {})}
            title="Drain inference queues"
            style={{ padding: '3px 9px', background: G3.card2, borderRadius: 5, color: G3.mute2, border: 'none', cursor: 'pointer', whiteSpace: 'nowrap', fontSize: 10 }}
          >
            Drain queue
          </button>
          <button
            onClick={() => { apiFetch('/flows', { method: 'DELETE' }).catch(() => {}); clearAlerts(); setSelected(null) }}
            style={{ padding: '3px 9px', background: G3.card2, borderRadius: 5, color: G3.mute2, border: 'none', cursor: 'pointer', whiteSpace: 'nowrap', fontSize: 10 }}
          >
            Clear logs
          </button>
          <button
            onClick={() => setShowModules(true)}
            style={{ padding: '3px 9px', background: G3.card2, borderRadius: 5, color: G3.mute2, border: `1px solid ${G3.line}`, cursor: 'pointer', fontWeight: 500, whiteSpace: 'nowrap', fontSize: 10 }}
          >
            ⊞ Modules
          </button>
          <button
            onClick={() => setShowSettings(true)}
            style={{ padding: '3px 9px', background: G3.accentSoft, borderRadius: 5, color: G3.accent, border: `1px solid ${alpha(G3.accent, 25)}`, cursor: 'pointer', fontWeight: 500, whiteSpace: 'nowrap', fontSize: 10 }}
          >
            ⚙ Settings
          </button>
        </div>
      </div>

      {showSettings && <SettingsPanel onClose={() => setShowSettings(false)} />}
      {showModules && (
        <ModulesPicker
          hiddenModules={hiddenModules}
          setHiddenModules={setHiddenModules}
          onClose={() => setShowModules(false)}
        />
      )}

      {/* ── Grid canvas ── */}
      <div style={{ flex: 1, overflowX: 'hidden', overflowY: 'auto', padding: 12, background: G3.bg, minHeight: 0, cursor: dragId ? 'grabbing' : 'default' }}>
        <GridContainer>
          {visibleOrder.map(id => {
            const size       = sizes[id]
            const constraint = CONSTRAINTS[id]
            const meta       = MODULE_META[id]

            return (
              <Module
                key={id} id={id}
                title={meta.title}
                subtitle={meta.subtitle}
                about={meta.about}
                badge={meta.badge?.(allAlerts)}
                hot={meta.hot?.(allAlerts)}
                size={size}
                constraint={constraint}
                onResize={onResize}
                onReorderStart={onReorderStart}
                onReorderOver={onReorderOver}
                onReorderEnd={onReorderEnd}
                onRemove={() => removeModule(id)}
                isBeingDragged={dragId === id}
                isDragTarget={!!(dragId && overId === id && dragId !== id)}
              >
                {id === 'kpi' && (
                  <ModKPI
                    alerts={allAlerts}
                    tcpHealth={tcpHealth} udpHealth={udpHealth}
                    queueDepth={queueDepth}
                    modelsLoaded={modelsLoaded}
                    baselining={baselining}
                    baselineProgress={baselineProgress}
                    thHigh={thHigh} thCrit={thCrit}
                  />
                )}
                {id === 'pulse'    && <ModPulse alerts={allAlerts} />}
                {id === 'health'   && <ModHealth tcpHealth={tcpHealth} udpHealth={udpHealth} baselineTcp={baselineTcp} baselineUdp={baselineUdp} />}
                {id === 'entities' && (
                  <ModEntities
                    alerts={allAlerts}
                    setSelected={setSelected}
                    entityFilter={entityFilter}
                    setEntityFilter={setEntityFilter}
                    showAll={showAll}
                    setShowAll={setShowAll}
                    protoFilter={protoFilter}
                    setProtoFilter={setProtoFilter}
                  />
                )}
                {id === 'stream' && (
                  <ModStream
                    alerts={allAlerts}
                    selected={selected}
                    setSelected={setSelected}
                    entityFilter={entityFilter}
                    setEntityFilter={setEntityFilter}
                    showAll={showAll}
                    setShowAll={setShowAll}
                    protoFilter={protoFilter}
                    setProtoFilter={setProtoFilter}
                  />
                )}
                {id === 'detail' && (
                  <ModDetail alert={selected} send={send as (msg: FeedbackMsg | LlmRequestMsg) => void} />
                )}
                {id === 'llm' && (
                  <ModLLM
                    alert={selected}
                    allAlerts={allAlerts}
                    send={send as (msg: FeedbackMsg | LlmRequestMsg) => void}
                    llmResponses={llmResponses}
                    llmReady={llmReady}
                  />
                )}
                {id === 'timeline'  && <ModTimeline  alerts={allAlerts} t={t} setT={setT} />}
                {id === 'heatmap'   && <ModHeatmap   alerts={allAlerts} />}
                {id === 'consensus' && <ModConsensus alerts={allAlerts} thHigh={thHigh} thCrit={thCrit} />}
                {id === 'topology'  && <ModTopology  alerts={allAlerts} />}
                {id === 'tree'      && <ModTree />}
              </Module>
            )
          })}
        </GridContainer>
      </div>

      <style>{`
        @keyframes corvus-pulse {
          0%, 100% { opacity: 1; }
          50%       { opacity: 0.4; }
        }
      `}</style>
    </div>
  )
}

// ── Root ─────────────────────────────────────────────────────────────────────

export default function App() {
  return (
    <ThemeProvider>
      <AppInner />
    </ThemeProvider>
  )
}
