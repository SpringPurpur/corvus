import { cn } from '../lib/utils'

interface Props {
  connected: boolean
  captureUp: boolean
  modelsLoaded: boolean
  tcpCount: number
  udpCount: number
}

function Dot({ on, label }: { on: boolean; label: string }) {
  return (
    <span className="flex items-center gap-1.5 text-xs">
      <span
        className={cn(
          'h-2 w-2 rounded-full',
          on ? 'bg-emerald-400' : 'bg-zinc-600',
        )}
      />
      {label}
    </span>
  )
}

export function StatusBar({ connected, captureUp, modelsLoaded, tcpCount, udpCount }: Props) {
  return (
    <header className="flex items-center justify-between border-b px-4 py-2 bg-card">
      <div className="flex items-center gap-2">
        <span className="font-semibold tracking-tight text-foreground mr-3">Corvus IDS</span>
        <Dot on={connected} label="WebSocket" />
        <Dot on={captureUp} label="Capture" />
        <Dot on={modelsLoaded} label="Models" />
      </div>
      <div className="flex items-center gap-4 text-xs text-muted-foreground">
        <span>TCP alerts: <span className="text-foreground font-medium">{tcpCount}</span></span>
        <span>UDP alerts: <span className="text-foreground font-medium">{udpCount}</span></span>
      </div>
    </header>
  )
}
