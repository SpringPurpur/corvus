import { useEffect, useMemo, useRef, useState } from 'react'
import { apiFetch } from '../../lib/utils'
import { G3, sevCol } from '../grid/g3'
import type { Alert } from '../../types'

interface WindowBucket { ts: number; fast: number; medium: number; slow: number; peak: number }

interface Props {
  alerts: Alert[]
}

export function ModPulse({ alerts }: Props) {
  const [history, setHistory] = useState<WindowBucket[]>([])

  // Anchor to the latest alert timestamp, not the client clock.
  // This makes demo-DB and live scenarios behave identically:
  // - Live: latestTs ≈ now, advances as alerts arrive
  // - Demo: latestTs = last flow in the DB, stable (correct window around the data)
  const latestTs = useMemo(
    () => alerts.length > 0 ? alerts.reduce((m, a) => a.ts > m ? a.ts : m, 0) : Date.now() / 1000,
    [alerts],
  )

  // Ref so the 30 s interval always reads the freshest value without stale closure
  const latestTsRef = useRef(latestTs)
  latestTsRef.current = latestTs

  // Single AbortController across all fetchHistory calls — cancels any in-flight
  // request before starting a new one, preventing concurrent fetches from racing.
  const abortRef = useRef<AbortController | null>(null)

  // Fetch TCP + UDP histories in parallel and merge by timestamp bucket,
  // taking the max peak so the chart reflects the worst-case score across
  // both protocols at every point in time.
  const fetchHistory = (since: number) => {
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    const signal = controller.signal
    return Promise.all([
      apiFetch(`/window_history?proto=TCP&bucket=30&since=${since}`, { signal }).then(r => r.json()),
      apiFetch(`/window_history?proto=UDP&bucket=30&since=${since}`, { signal }).then(r => r.json()),
    ]).then(([tcp, udp]: [WindowBucket[], WindowBucket[]]) => {
      const map = new Map<number, WindowBucket>()
      for (const b of tcp) map.set(b.ts, b)
      for (const b of udp) {
        const x = map.get(b.ts)
        map.set(b.ts, x ? {
          ts: b.ts,
          fast:   Math.max(x.fast,   b.fast),
          medium: Math.max(x.medium, b.medium),
          slow:   Math.max(x.slow,   b.slow),
          peak:   Math.max(x.peak,   b.peak),
        } : b)
      }
      setHistory([...map.values()].sort((a, b) => a.ts - b.ts))
    }).catch(e => { if (e.name !== 'AbortError') throw e })
  }

  // Primary history fetch + 30 s refresh interval
  useEffect(() => {
    const load = () => fetchHistory(latestTsRef.current - 3600).catch(() => {})
    load()
    const id = setInterval(load, 30_000)
    return () => { clearInterval(id); abortRef.current?.abort() }
  }, [])

  // One-shot re-fetch once DB history loads: latestTs may have jumped far into
  // the past (demo DB) making the initial fetch (which used client time) return
  // empty. Re-query with the correct data-anchored since value.
  const anchorFetchedRef = useRef(false)
  useEffect(() => {
    if (alerts.length < 10 || anchorFetchedRef.current) return
    anchorFetchedRef.current = true
    fetchHistory(latestTs - 3600).catch(() => {})
  }, [alerts.length, latestTs])

  // In live mode roll tsMax forward with wall clock every second so dots
  // drift left continuously. In demo mode latestTs is in the past so we
  // anchor to it instead (clock would push tsMin past the data).
  const [clockNow, setClockNow] = useState(() => Date.now() / 1000)
  useEffect(() => {
    const id = setInterval(() => setClockNow(Date.now() / 1000), 5000)
    return () => clearInterval(id)
  }, [])

  const hasHistory = history.length > 1
  const WINDOW = 600
  const isLive = latestTs > Date.now() / 1000 - 60
  const tsMax  = isLive ? clockNow : latestTs
  const tsMin  = tsMax - WINDOW
  const tsSpan = WINDOW

  // Derive fill path and glowing top-edge stroke from the same point set.
  // Memoized on history + window bounds: only recomputes every 30 s (history
  // refresh) or every 5 s (clock tick) — not on every 150 ms alert flush.
  type Pt = [number, number]
  const { fillPath, topPath } = useMemo(() => {
    const pts: Pt[] = hasHistory
      ? history.map(b => [((b.ts - tsMin) / tsSpan) * 400, 100 - b.peak * 90] as Pt)
      : Array.from({ length: 61 }, (_, i) => [
          i * 400 / 60,
          100 - Math.abs(Math.sin(i * 0.3) * 12 + Math.sin(i * 0.7) * 8),
        ] as Pt)
    const seg = pts.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' L ')
    return {
      fillPath: `M 0,120 L ${seg} L 400,120 Z`,
      topPath:  pts.length > 0 ? `M ${seg}` : '',
    }
  }, [history, tsMin, tsSpan, hasHistory])

  // Uniform sample across the window — memoized so alert flushes only
  // recompute dots, not the heavier path geometry above.
  const DOT_CAP = 60
  const dots = useMemo(() => {
    const inWindow = alerts.filter(a => a.ts >= tsMin && a.ts <= tsMax)
    if (inWindow.length <= DOT_CAP) return inWindow
    const sorted = [...inWindow].sort((a, b) => a.ts - b.ts)
    const step   = sorted.length / DOT_CAP
    return Array.from({ length: DOT_CAP }, (_, i) => sorted[Math.floor(i * step)])
  }, [alerts, tsMin, tsMax])

  const scoreToY = (v: number) => 100 - v * 90

  const Y_TICKS = [1.0, 0.75, 0.5, 0.25]
  const fmt = (ts: number) => new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })

  return (
    <div style={{ padding: 10, height: '100%', width: '100%', display: 'flex', gap: 4, boxSizing: 'border-box' }}>

      {/* y-axis labels */}
      <div style={{ position: 'relative', width: 22, flexShrink: 0 }}>
        {Y_TICKS.map(v => (
          <div key={v} style={{
            position: 'absolute',
            top:      `${((100 - v * 90) / 120) * 100}%`,
            right:    0,
            transform: 'translateY(-50%)',
            fontSize: 7,
            color:    G3.mute,
            fontFamily: 'JetBrains Mono, ui-monospace, monospace',
            lineHeight: 1,
          }}>{v.toFixed(2)}</div>
        ))}
      </div>

      <div style={{ position: 'relative', flex: 1, height: '100%' }}>
        <svg viewBox="0 0 400 120" preserveAspectRatio="none" style={{ width: '100%', height: '100%', display: 'block' }}>
          <defs>
            <linearGradient id="pulse-grad" x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%"   stopColor={G3.accent} stopOpacity="0.55" />
              <stop offset="50%"  stopColor={G3.accent} stopOpacity="0.25" />
              <stop offset="100%" stopColor={G3.accent} stopOpacity="0" />
            </linearGradient>
            <filter id="pulse-glow" x="-5%" y="-150%" width="110%" height="400%">
              <feGaussianBlur stdDeviation="1.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {Y_TICKS.map(v => (
            <line key={v} x1="0" x2="400" y1={100 - v * 90} y2={100 - v * 90}
              stroke={G3.line} strokeDasharray="2 4" vectorEffect="non-scaling-stroke" />
          ))}

          <path d={fillPath} fill="url(#pulse-grad)" opacity={hasHistory ? 1 : 0.3} />

          {topPath && (
            <path d={topPath} fill="none"
              stroke={G3.accent} strokeWidth="1.5"
              filter="url(#pulse-glow)"
              opacity={hasHistory ? 0.9 : 0.4}
              vectorEffect="non-scaling-stroke"
            />
          )}

          {dots.map(a => {
            const x   = ((a.ts - tsMin) / tsSpan) * 400
            const cy  = scoreToY(a.verdict.confidence)
            const col = sevCol(a.verdict.severity)
            return (
              <circle key={a.flow_id} cx={x} cy={cy} r="1.5" fill={col} />
            )
          })}
        </svg>

        {dots.length > 0 && (
          <>
            <span style={{ position: 'absolute', bottom: 2, left: 2, fontSize: 7, color: G3.mute, fontFamily: 'JetBrains Mono, ui-monospace, monospace', lineHeight: 1, pointerEvents: 'none' }}>
              {fmt(tsMin)}
            </span>
            <span style={{ position: 'absolute', bottom: 2, right: 2, fontSize: 7, color: G3.mute, fontFamily: 'JetBrains Mono, ui-monospace, monospace', lineHeight: 1, pointerEvents: 'none' }}>
              {fmt(tsMax)}
            </span>
          </>
        )}
      </div>
    </div>
  )
}
