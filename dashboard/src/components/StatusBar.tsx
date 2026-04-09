import { cn } from '../lib/utils'

interface Props {
  connected: boolean
  captureUp: boolean
  modelsLoaded: boolean
  tcpCount: number
  udpCount: number
  baselining: boolean
  baselineProgress: number
  onSettings: () => void
  onClearLogs: () => void
}

function Dot({ on, label }: { on: boolean; label: string }) {
  return (
    <span className="flex items-center gap-1.5 text-xs">
      <span
        className="h-2 w-2 rounded-full"
        style={{ backgroundColor: on ? 'var(--color-online)' : 'var(--color-offline)' }}
      />
      {label}
    </span>
  )
}

export function StatusBar({ connected, captureUp, modelsLoaded, tcpCount, udpCount, baselining, baselineProgress, onSettings, onClearLogs }: Props) {
  return (
    <header className="flex items-center justify-between border-b px-4 py-2 bg-card">
      <div className="flex items-center gap-2">
        <span className="brand-title font-semibold tracking-tight text-foreground mr-3">
          Corvus IDS
        </span>
        <Dot on={connected} label="WebSocket" />
        <Dot on={captureUp} label="Capture" />
        <Dot on={modelsLoaded} label="Models" />
        {baselining && (
          <span
            className="flex items-center gap-1.5 text-xs ml-2"
            style={{ color: 'var(--color-baselining)' }}
          >
            <span
              className="h-2 w-2 rounded-full animate-pulse"
              style={{ backgroundColor: 'var(--color-baselining)' }}
            />
            Baselining {Math.round(baselineProgress * 100)}%
          </span>
        )}
      </div>
      <div className="flex items-center gap-4 text-xs text-muted-foreground">
        <span>TCP alerts: <span className="text-foreground font-medium">{tcpCount}</span></span>
        <span>UDP alerts: <span className="text-foreground font-medium">{udpCount}</span></span>
        <button
          onClick={onClearLogs}
          title="Clear stored flow logs"
          className={cn(
            'ml-1 transition-colors text-xs leading-none',
            'text-muted-foreground hover:text-foreground',
          )}
          aria-label="Clear logs"
        >
          Clear logs
        </button>
        <button
          onClick={onSettings}
          title="Detection settings"
          className="ml-1 text-muted-foreground hover:text-foreground transition-colors text-base leading-none"
          aria-label="Open settings"
        >
          ⚙
        </button>
      </div>
    </header>
  )
}
