import { useEffect, useState } from 'react'
import type { Alert, AppConfig, WsMessage, FeedbackMsg, LlmRequestMsg } from './types'
import { useWebSocket } from './hooks/useWebSocket'
import { useAlerts } from './hooks/useAlerts'
import { StatusBar } from './components/StatusBar'
import { AlertFeed } from './components/AlertFeed'
import { AlertDetail } from './components/AlertDetail'
import { LLMPanel } from './components/LLMPanel'
import { ModelHealth } from './components/ModelHealth'
import { StatsBar } from './components/StatsBar'
import { SettingsPanel } from './components/SettingsPanel'

// Accumulated LLM responses keyed by request_id — never reset, grows per session
const llmResponses: Record<string, string> = {}

const DEFAULT_CONFIG: AppConfig = {
  threshold_high: 0.60, threshold_critical: 0.80,
  baseline_tcp: 4096, baseline_udp: 1024,
}

export default function App() {
  const [tab, setTab] = useState<'TCP' | 'UDP' | 'Health'>('TCP')
  const [selected, setSelected] = useState<Alert | null>(null)
  const [showSettings, setShowSettings] = useState(false)
  const [config, setConfig] = useState<AppConfig>(DEFAULT_CONFIG)
  const [, forceRender] = useState(0)

  const { tcp, udp, tcpHealth, udpHealth, captureUp, modelsLoaded, baselining, baselineProgress, handleMessage, loadHistory, clearAlerts } = useAlerts()

  const handleClearLogs = () => {
    fetch('/flows', { method: 'DELETE' }).catch(() => {})
    clearAlerts()
    setSelected(null)
  }

  useEffect(() => {
    fetch('/config').then(r => r.json()).then(setConfig).catch(() => {})
  }, [])

  // Load the last 200 flows from SQLite on mount so the feed survives page refresh
  useEffect(() => { loadHistory() }, [loadHistory])

  const onMessage = (msg: WsMessage) => {
    if (msg.type === 'llm_response') {
      llmResponses[msg.request_id] = msg.text
      forceRender((n) => n + 1)
    }
    handleMessage(msg)
  }

  const { connected, send } = useWebSocket(onMessage)

  const alerts = tab === 'TCP' ? tcp : udp
  const allAlerts = [...tcp, ...udp]

  return (
    <div className="flex flex-col h-screen">
      <StatusBar
        connected={connected}
        captureUp={captureUp}
        modelsLoaded={modelsLoaded}
        tcpCount={tcp.length}
        udpCount={udp.length}
        baselining={baselining}
        baselineProgress={baselineProgress}
        onSettings={() => setShowSettings(true)}
        onClearLogs={handleClearLogs}
      />

      {showSettings && <SettingsPanel onClose={() => setShowSettings(false)} />}

      {/* Tab bar */}
      <div className="flex border-b px-4 bg-card">
        {(['TCP', 'UDP', 'Health'] as const).map((t) => (
          <button
            key={t}
            onClick={() => { setTab(t); setSelected(null) }}
            className={`px-4 py-2 text-xs font-medium border-b-2 transition-colors ${
              tab === t
                ? 'border-blue-400 text-foreground'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {/* Main content */}
      <div className="flex flex-1 overflow-hidden">
        {tab === 'Health' ? (
          <div className="flex-1 overflow-hidden">
            <ModelHealth tcp={tcpHealth} udp={udpHealth} config={config} />
          </div>
        ) : (
          <>
            {/* Alert feed — left panel */}
            <div className="flex-1 overflow-hidden border-r">
              <AlertFeed alerts={alerts} selected={selected} onSelect={setSelected} />
            </div>

            {/* Detail + LLM — right panel, shown only when an alert is selected */}
            {selected && (
              <div className="w-96 flex flex-col border-r overflow-hidden shrink-0">
                <div className="h-1/2 border-b overflow-hidden">
                  <AlertDetail alert={selected} />
                </div>
                <div className="h-1/2 overflow-hidden">
                  <LLMPanel
                    alert={selected}
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
