import { useEffect, useMemo, useState } from 'react'
import type { Alert, AppConfig, WsMessage, FeedbackMsg, LlmRequestMsg } from './types'
import { useWebSocket } from './hooks/useWebSocket'
import { useAlerts } from './hooks/useAlerts'
import { StatusBar } from './components/StatusBar'
import { AlertFeed } from './components/AlertFeed'
import { AlertDetail } from './components/AlertDetail'
import { LLMPanel } from './components/LLMPanel'
import { ModelHealth } from './components/ModelHealth'
import { NetworkTopology } from './components/NetworkTopology'
import { StatsBar } from './components/StatsBar'
import { SettingsPanel } from './components/SettingsPanel'
import { EntityList } from './components/EntityList'
import { NetworkPulse } from './components/NetworkPulse'
import { ThemeProvider, useTheme } from './context/ThemeContext'

// Accumulated LLM responses keyed by request_id — never reset, grows per session
const llmResponses: Record<string, string> = {}

const DEFAULT_CONFIG: AppConfig = {
  threshold_high: 0.60, threshold_critical: 0.80,
  baseline_tcp: 4096, baseline_udp: 1024,
  min_tcp_pkts: 4, filter_gateway: false,
}

function AppInner() {
  const [tab, setTab]               = useState<'TCP' | 'UDP' | 'Health' | 'Topology'>('TCP')
  const [selected, setSelected]     = useState<Alert | null>(null)
  const [showSettings, setShowSettings] = useState(false)
  const [config, setConfig]         = useState<AppConfig>(DEFAULT_CONFIG)
  const [, forceRender]             = useState(0)
  const [entityFilter, setEntityFilter] = useState<string | null>(null)
  const [showAll, setShowAll]       = useState(false)
  const [llmReady, setLlmReady]     = useState(false)
  const [checked, setChecked]       = useState<Set<string>>(new Set())
  const [clockOffsetMs, setClockOffsetMs] = useState(0)  // server_ms − host_ms

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

  useEffect(() => {
    fetch('/config').then(r => r.json()).then(setConfig).catch(() => {})
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
    handleMessage(msg)
  }

  const { connected, send } = useWebSocket(onMessage)

  // Protocol split — all flows for the current tab (fed to EntityList + NetworkPulse)
  const alerts = tab === 'TCP' ? tcp : udp
  const allAlerts = [...tcp, ...udp]

  // Apply entity filter + bucket filter for the feed
  const feedAlerts = useMemo(() => {
    let result = alerts
    if (entityFilter) result = result.filter((a) => a.src_ip === entityFilter)
    if (!showAll)     result = result.filter((a) => a.verdict.severity !== 'INFO')
    return result
  }, [alerts, entityFilter, showAll])

  // Clear entity filter when switching tabs
  const handleTabChange = (t: 'TCP' | 'UDP' | 'Health' | 'Topology') => {
    setTab(t)
    setSelected(null)
    setEntityFilter(null)
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
        {(['TCP', 'UDP', 'Health', 'Topology'] as const).map((t) => (
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
        ) : (
          <>
            {/* Entity list — narrow left column */}
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
              />
            </div>

            {/* Detail + LLM — right panel, shown only when an alert is selected */}
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
