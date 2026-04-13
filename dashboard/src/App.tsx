import { useEffect, useMemo, useRef, useState } from 'react'
import type { Alert, AppConfig, WsMessage, FeedbackMsg, LlmRequestMsg } from './types'
import { useWebSocket } from './hooks/useWebSocket'
import { useAlerts } from './hooks/useAlerts'
import { StatusBar } from './components/StatusBar'
import { AlertFeed } from './components/AlertFeed'
import { AlertDetail } from './components/AlertDetail'
import { LLMPanel } from './components/LLMPanel'
import { ModelHealth } from './components/ModelHealth'
import { NetworkTopology } from './components/NetworkTopology'
import { IncidentList } from './components/IncidentList'
import { StatsBar } from './components/StatsBar'
import { SettingsPanel } from './components/SettingsPanel'
import { EntityList } from './components/EntityList'
import { NetworkPulse } from './components/NetworkPulse'
import { ThemeProvider, useTheme } from './context/ThemeContext'

// Accumulated LLM responses keyed by request_id - never reset, grows per session
const llmResponses: Record<string, string> = {}

const DEFAULT_CONFIG: AppConfig = {
  threshold_high: 0.60, threshold_critical: 0.80,
  baseline_tcp: 4096, baseline_udp: 1024,
  min_tcp_pkts: 4, filter_gateway: false,
}

function AppInner() {
  const [tab, setTab]               = useState<'TCP' | 'UDP' | 'Health' | 'Topology' | 'Incidents'>('TCP')
  const [selected, setSelected]     = useState<Alert | null>(null)
  const [showSettings, setShowSettings] = useState(false)
  const [config, setConfig]         = useState<AppConfig>(DEFAULT_CONFIG)
  const [, forceRender]             = useState(0)
  const [entityFilter, setEntityFilter] = useState<string | null>(null)
  const [showAll, setShowAll]       = useState(false)
  const [llmReady, setLlmReady]     = useState(false)
  const [checked, setChecked]       = useState<Set<string>>(new Set())
  const [clockOffsetMs, setClockOffsetMs] = useState(0)  // server_ms − host_ms
  const [needsApiKey, setNeedsApiKey]     = useState(false)
  const [apiKeyInput, setApiKeyInput]     = useState('')

  // Feed pause
  const [paused, setPaused]           = useState(false)
  const frozenFeedRef                 = useRef<Alert[]>([])
  const [newWhilePaused, setNewWhilePaused] = useState(0)
  const allLenRef                     = useRef(0)

  // Search query
  const [searchQuery, setSearchQuery] = useState('')

  // Notification gate - don't fire for history loaded at startup
  const notifyEnabledRef = useRef(false)

  const { theme } = useTheme()

  const {
    tcp, udp, tcpHealth, udpHealth,
    captureUp, modelsLoaded, baselining, baselineProgress,
    queueDepth, handleMessage, loadHistory, clearAlerts,
  } = useAlerts()

  const handleClearLogs = () => {
    fetch('/flows', { method: 'DELETE' }).catch(() => {})
    clearAlerts()
    setSelected(null)
    setEntityFilter(null)
  }

  const handleDrainQueue = () => {
    fetch('/queue', { method: 'DELETE' }).catch(() => {})
  }

  const handleBulkDismiss = (flowIds: string[]) => {
    if (flowIds.length === 0) return
    fetch('/feedback/bulk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ flow_ids: flowIds, dismiss: true }),
    }).catch(() => {})
    setChecked(new Set())
  }

  // Request notification permission once; enable after history load settles
  useEffect(() => {
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission()
    }
    const t = setTimeout(() => { notifyEnabledRef.current = true }, 4000)
    return () => clearTimeout(t)
  }, [])

  // Document title badge - total CRITICAL count
  useEffect(() => {
    const n = [...tcp, ...udp].filter(a => a.verdict.severity === 'CRITICAL').length
    document.title = n > 0 ? `(${n}) Corvus IDS` : 'Corvus IDS'
  }, [tcp, udp])

  // Track new alerts that arrive while feed is paused
  useEffect(() => {
    const total = tcp.length + udp.length
    if (paused) {
      const diff = total - allLenRef.current
      if (diff > 0) setNewWhilePaused(c => c + diff)
    }
    allLenRef.current = total
  }, [tcp, udp, paused])

  useEffect(() => {
    fetch('/config').then(r => {
      if (r.status === 401) { setNeedsApiKey(true); return null }
      return r.json()
    }).then(d => { if (d) setConfig(d) }).catch(() => {})
    fetch('/llm/status').then(r => r.json()).then(d => setLlmReady(!!d.available)).catch(() => {})
    // Measure container ↔ host clock skew via NTP-style midpoint estimate.
    // clockOffsetMs = serverTime − hostTime; subtract from t_ws_ns before
    // computing "WS → browser" to avoid negative latency on WSL2/Hyper-V.
    const t0 = Date.now()
    fetch('/time').then(r => r.json()).then(({ ts }: { ts: number }) => {
      const t1 = Date.now()
      setClockOffsetMs(ts * 1000 - (t0 + t1) / 2)
    }).catch(() => {})
  }, [])

  useEffect(() => { loadHistory() }, [loadHistory])

  const onMessage = (msg: WsMessage) => {
    if (msg.type === 'llm_response') {
      llmResponses[msg.request_id] = msg.text
      forceRender((n) => n + 1)
    }
    // Browser notification for CRITICAL alerts (not during history load)
    if (
      msg.type === 'alert' &&
      notifyEnabledRef.current &&
      msg.data.verdict?.severity === 'CRITICAL' &&
      'Notification' in window &&
      Notification.permission === 'granted'
    ) {
      new Notification('Corvus IDS - Critical Alert', {
        body: `${msg.data.src_ip} → ${msg.data.dst_ip}:${msg.data.dst_port}  (score ${msg.data.verdict.score?.toFixed(2) ?? '?'})`,
        icon: '/favicon.ico',
        tag: msg.data.flow_id,   // collapse duplicates for same flow
      })
    }
    handleMessage(msg)
  }

  const { connected, send } = useWebSocket(onMessage)

  // Protocol split - all flows for the current tab (fed to EntityList + NetworkPulse)
  const alerts = tab === 'TCP' ? tcp : udp
  const allAlerts = [...tcp, ...udp]

  // Apply entity filter + severity bucket + search query
  const liveFeedAlerts = useMemo(() => {
    let result = alerts
    if (entityFilter) result = result.filter((a) => a.src_ip === entityFilter)
    if (!showAll)     result = result.filter((a) => a.verdict.severity !== 'INFO')
    if (searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase()
      result = result.filter((a) =>
        a.src_ip.includes(q) ||
        a.dst_ip.includes(q) ||
        String(a.dst_port).includes(q) ||
        String(a.src_port).includes(q)
      )
    }
    return result
  }, [alerts, entityFilter, showAll, searchQuery])

  // Pause: freeze the feed snapshot; track backlog count
  const handleTogglePause = () => {
    if (!paused) frozenFeedRef.current = liveFeedAlerts
    setPaused(v => !v)
    setNewWhilePaused(0)
    allLenRef.current = tcp.length + udp.length
  }
  const feedAlerts = paused ? frozenFeedRef.current : liveFeedAlerts

  // Clear entity filter when switching tabs
  const handleTabChange = (t: 'TCP' | 'UDP' | 'Health' | 'Topology' | 'Incidents') => {
    setTab(t)
    setSelected(null)
    setEntityFilter(null)
  }

  // API key gate
  if (needsApiKey) {
    return (
      <div className="fixed inset-0 flex items-center justify-center bg-background" data-theme={theme}>
        <div
          className="flex flex-col gap-3 p-6 border bg-card shadow-xl w-80"
          style={{ borderRadius: 'var(--radius)' }}
        >
          <h2 className="text-sm font-semibold">API Key Required</h2>
          <p className="text-xs text-muted-foreground">
            This Corvus instance requires authentication.<br />
            Enter the key configured in <span className="font-mono">CORVUS_API_KEY</span>.
          </p>
          <input
            type="password"
            autoFocus
            value={apiKeyInput}
            onChange={e => setApiKeyInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && apiKeyInput.trim()) {
                sessionStorage.setItem('corvus_api_key', apiKeyInput.trim())
                window.location.reload()
              }
            }}
            placeholder="corvus-api-key"
            className="bg-muted px-3 py-1.5 text-xs rounded focus:outline-none focus:ring-1 focus:ring-border"
            style={{ borderRadius: 'var(--radius)' }}
          />
          <button
            onClick={() => {
              if (!apiKeyInput.trim()) return
              sessionStorage.setItem('corvus_api_key', apiKeyInput.trim())
              window.location.reload()
            }}
            className="px-4 py-1.5 text-xs font-medium text-white transition-colors"
            style={{ backgroundColor: 'var(--color-accent)', borderRadius: 'var(--radius)' }}
          >
            Connect
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-screen" data-theme={theme}>
      <StatusBar
        connected={connected}
        captureUp={captureUp}
        modelsLoaded={modelsLoaded}
        llmReady={llmReady}
        tcpCount={tcp.length}
        udpCount={udp.length}
        baselining={baselining}
        baselineProgress={baselineProgress}
        queueDepth={queueDepth.total}
        onSettings={() => setShowSettings(true)}
        onClearLogs={handleClearLogs}
        onDrainQueue={handleDrainQueue}
      />

      {showSettings && <SettingsPanel onClose={() => setShowSettings(false)} />}

      {/* Tab bar */}
      <div className="flex border-b px-4 bg-card">
        {(['TCP', 'UDP', 'Health', 'Topology', 'Incidents'] as const).map((t) => (
          <button
            key={t}
            onClick={() => handleTabChange(t)}
            {...(tab === t ? { 'data-active-tab': '' } : {})}
            className={`px-4 py-2 text-xs font-medium border-b-2 transition-colors ${
              tab === t
                ? 'border-current text-foreground'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
            style={tab === t ? { borderColor: 'var(--color-accent)' } : {}}
          >
            {t}
          </button>
        ))}
      </div>

      {/* Main content */}
      <div className="flex flex-1 overflow-hidden">
        {tab === 'Health' ? (
          <div className="flex-1 overflow-hidden">
            <ModelHealth tcp={tcpHealth} udp={udpHealth} config={config} tcpAlerts={tcp} udpAlerts={udp} />
          </div>
        ) : tab === 'Topology' ? (
          <div className="flex-1 overflow-hidden">
            <NetworkTopology alerts={allAlerts} />
          </div>
        ) : tab === 'Incidents' ? (
          <div className="flex-1 overflow-hidden">
            <IncidentList alerts={allAlerts} />
          </div>
        ) : (
          <>
            {/* Entity list - narrow left column */}
            <EntityList
              alerts={alerts}
              activeIp={entityFilter}
              onSelect={(ip) => {
                setEntityFilter(ip)
                setSelected(null)
              }}
            />

            {/* Feed column: NetworkPulse strip + AlertFeed */}
            <div className="flex-1 flex flex-col overflow-hidden border-r">
              <NetworkPulse alerts={alerts} />
              <AlertFeed
                alerts={feedAlerts}
                selected={selected}
                onSelect={setSelected}
                showAll={showAll}
                onToggleShowAll={() => setShowAll((v) => !v)}
                entityFilter={entityFilter}
                checked={checked}
                onCheckedChange={setChecked}
                onBulkDismiss={handleBulkDismiss}
                paused={paused}
                onTogglePause={handleTogglePause}
                newWhilePaused={newWhilePaused}
                searchQuery={searchQuery}
                onSearchChange={setSearchQuery}
              />
            </div>

            {/* Detail + LLM - right panel, shown only when an alert is selected */}
            {selected && (
              <div className="w-96 flex flex-col border-r overflow-hidden shrink-0">
                <div className="h-1/2 border-b overflow-hidden">
                  <AlertDetail alert={selected} clockOffsetMs={clockOffsetMs} />
                </div>
                <div className="h-1/2 overflow-hidden">
                  <LLMPanel
                    alert={selected}
                    allAlerts={alerts}
                    send={send as (msg: FeedbackMsg | LlmRequestMsg) => void}
                    llmResponses={llmResponses}
                  />
                </div>
              </div>
            )}
          </>
        )}
      </div>

      <StatsBar alerts={allAlerts} />
    </div>
  )
}

export default function App() {
  return (
    <ThemeProvider>
      <AppInner />
    </ThemeProvider>
  )
}
