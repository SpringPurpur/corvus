// SettingsPanel.tsx - analyst-facing configuration: alert thresholds,
// baseline management, and visual theme selection.
//
// Thresholds take effect immediately on save (inference engine reads cfg
// per-flow with no restart needed). Baseline reset discards the trained
// OIF model and re-baselines on the next N flows of live traffic.

import { useCallback, useEffect, useRef, useState } from 'react'
import type { AppConfig } from '../types'
import { cn } from '../lib/utils'
import { THEMES } from '../themes'
import { useTheme } from '../context/ThemeContext'

const DEV_STORAGE_KEY = 'corvus-dev-mode'

interface Props {
  onClose: () => void
}

const DEFAULT_CFG: AppConfig = {
  threshold_high:     0.60,
  threshold_critical: 0.80,
  baseline_tcp:       4096,
  baseline_udp:       1024,
  min_tcp_pkts:       4,
  filter_gateway:     false,
}

interface CaptureIface {
  name: string
  up: boolean
  promisc: boolean
}

export function SettingsPanel({ onClose }: Props) {
  const [cfg, setCfg]             = useState<AppConfig>(DEFAULT_CFG)
  const [saving, setSaving]       = useState(false)
  const [saveMsg, setSaveMsg]     = useState<string | null>(null)
  const [resetting, setResetting] = useState<string | null>(null)
  const [devMode, setDevMode]     = useState(() => localStorage.getItem(DEV_STORAGE_KEY) === '1')
  const [fbState, setFbState]     = useState<'idle' | 'running' | 'ok' | 'err'>('idle')
  const [fbMsg, setFbMsg]         = useState<string | null>(null)

  // Feedback history
  interface FeedbackEntry {
    flow_id: string; ts: number; corrected_label: string | null
    dismiss: boolean; reason: string | null; analyst_text: string | null
  }
  const [feedbackLog, setFeedbackLog]   = useState<FeedbackEntry[] | null>(null)
  const [feedbackLoading, setFeedbackLoading] = useState(false)

  const loadFeedback = useCallback(async () => {
    setFeedbackLoading(true)
    try {
      const r = await fetch('/feedback')
      setFeedbackLog(await r.json())
    } catch { setFeedbackLog([]) }
    finally { setFeedbackLoading(false) }
  }, [])

  // Scenario runner
  interface PhaseRecord {
    phase_id: number; run_id: string; scenario: string; phase: string
    t_start: number; t_end: number | null; attacker_ip: string | null
  }
  const [phases, setPhases]             = useState<PhaseRecord[]>([])
  const [activePhase, setActivePhase]   = useState<{ id: number; label: string } | null>(null)
  const [phaseRunId, setPhaseRunId]     = useState('run-001')
  const [phaseScenario, setPhaseScenario] = useState('portscan')
  const [phaseType, setPhaseType]       = useState('baseline')
  const [phaseAttackerIp, setPhaseAttackerIp] = useState('')
  const [phaseMsg, setPhaseMsg]         = useState<string | null>(null)
  const [phaseBusy, setPhaseBusy]       = useState(false)

  const loadPhases = useCallback(async () => {
    try {
      const r = await fetch('/phases')
      setPhases(await r.json())
    } catch { /* leave stale */ }
  }, [])

  useEffect(() => { loadPhases() }, [loadPhases])

  const handleOpenPhase = useCallback(async () => {
    setPhaseBusy(true); setPhaseMsg(null)
    try {
      const r = await fetch('/phases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          run_id: phaseRunId, scenario: phaseScenario, phase: phaseType,
          t_start: Date.now() / 1000,
          attacker_ip: phaseAttackerIp.trim() || null,
        }),
      })
      const d = await r.json()
      setActivePhase({ id: d.phase_id, label: `${phaseType} / ${phaseScenario}` })
      setPhaseMsg(`Phase opened (id ${d.phase_id})`)
      loadPhases()
    } catch { setPhaseMsg('Request failed.') }
    finally { setPhaseBusy(false) }
  }, [phaseRunId, phaseScenario, phaseType, phaseAttackerIp, loadPhases])

  const handleClosePhase = useCallback(async () => {
    if (!activePhase) return
    setPhaseBusy(true); setPhaseMsg(null)
    try {
      await fetch(`/phases/${activePhase.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ t_end: Date.now() / 1000 }),
      })
      setPhaseMsg(`Phase ${activePhase.id} closed.`)
      setActivePhase(null)
      loadPhases()
    } catch { setPhaseMsg('Close failed.') }
    finally { setPhaseBusy(false) }
  }, [activePhase, loadPhases])

  // Capture configuration state
  const [capIfaces, setCapIfaces]       = useState<CaptureIface[] | null>(null)
  const [capIfaceErr, setCapIfaceErr]   = useState<string | null>(null)
  const [capSelected, setCapSelected]   = useState('')
  const [capFilter, setCapFilter]       = useState('')
  const [capPromisc, setCapPromisc]     = useState(false)
  const [capApplying, setCapApplying]   = useState(false)
  const [capMsg, setCapMsg]             = useState<string | null>(null)
  const [capMsgOk, setCapMsgOk]         = useState(true)
  // What the monitor is actually running right now (written by start.sh)
  const [capStatus, setCapStatus]       = useState<{ interface?: string; filter?: string } | null>(null)
  const capFetchedRef = useRef(false)

  // System / container control
  type ContainerInfo = { name: string; status: string }
  type SysStatus = { docker: boolean; containers: Record<string, ContainerInfo>; error?: string }
  const [sysStatus, setSysStatus]       = useState<SysStatus | null>(null)
  const [sysAction, setSysAction]       = useState<string | null>(null)  // "monitor/restart" etc.
  const [sysMsg, setSysMsg]             = useState<string | null>(null)
  const [sysMsgOk, setSysMsgOk]         = useState(true)

  const { theme, setTheme } = useTheme()

  // Load current config from inference engine on open
  useEffect(() => {
    fetch('/config')
      .then((r) => r.json())
      .then((data: AppConfig) => setCfg(data))
      .catch(() => { /* leave defaults */ })
  }, [])

  // Load capture interfaces once (lazy - only when panel is open)
  useEffect(() => {
    if (capFetchedRef.current) return
    capFetchedRef.current = true
    fetch('/capture/interfaces')
      .then((r) => {
        if (!r.ok) return r.json().then((e) => { throw new Error(e.detail ?? `HTTP ${r.status}`) })
        return r.json()
      })
      .then((d: { interfaces: CaptureIface[]; config: { interface?: string; filter?: string }; status: { interface?: string; filter?: string } }) => {
        setCapIfaces(d.interfaces)
        setCapStatus(d.status ?? null)
        // Pre-fill from config (what was requested); fall back to running status
        const iface  = d.config.interface  ?? d.status?.interface  ?? ''
        const filter = d.config.filter     ?? d.status?.filter     ?? ''
        setCapSelected(iface)
        setCapFilter(filter)
      })
      .catch((err: Error) => setCapIfaceErr(err.message))
  }, [])

  // Poll system status every 5 s while the panel is open
  useEffect(() => {
    const fetchSys = () =>
      fetch('/system/status')
        .then((r) => r.json())
        .then((d: SysStatus) => setSysStatus(d))
        .catch(() => {})
    fetchSys()
    const id = setInterval(fetchSys, 5000)
    return () => clearInterval(id)
  }, [])

  const handleSysAction = useCallback(async (container: string, action: 'restart' | 'stop') => {
    const key = `${container}/${action}`
    setSysAction(key)
    setSysMsg(null)
    try {
      const r = await fetch(`/system/${container}/${action}`, { method: 'POST' })
      const body = await r.json().catch(() => ({}))
      if (!r.ok) {
        setSysMsgOk(false)
        setSysMsg(body.detail ?? `${action} failed`)
      } else {
        setSysMsgOk(true)
        setSysMsg(
          action === 'restart'
            ? `${body.container} restarting…`
            : `${body.container} stopped.`,
        )
      }
    } catch {
      setSysMsgOk(false)
      setSysMsg('Network error.')
    } finally {
      setSysAction(null)
    }
  }, [])

  const handleCapApply = useCallback(async () => {
    setCapApplying(true)
    setCapMsg(null)
    try {
      const r = await fetch('/capture/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          interface: capSelected || null,
          filter:    capFilter   || null,
          promisc:   capPromisc,
          restart:   true,
        }),
      })
      const body = await r.json().catch(() => ({}))
      if (!r.ok) {
        setCapMsgOk(false)
        setCapMsg(body.detail ?? 'Apply failed.')
      } else if (body.warning) {
        setCapMsgOk(true)
        setCapMsg(`Config saved. ${body.warning}`)
      } else if (body.engine === 'running') {
        setCapMsgOk(true)
        setCapMsg('Applied - capture engine running.')
      } else if (body.engine === 'failed') {
        setCapMsgOk(false)
        setCapMsg('Config saved but engine failed to restart - check interface name.')
      } else {
        setCapMsgOk(true)
        setCapMsg('Config saved.')
      }
    } catch {
      setCapMsgOk(false)
      setCapMsg('Network error.')
    } finally {
      setCapApplying(false)
    }
  }, [capSelected, capFilter, capPromisc])

  const handleSave = useCallback(async () => {
    if (cfg.threshold_high >= cfg.threshold_critical) {
      setSaveMsg('HIGH threshold must be less than CRITICAL threshold.')
      return
    }
    setSaving(true)
    setSaveMsg(null)
    try {
      const r = await fetch('/config', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(cfg),
      })
      if (!r.ok) {
        const err = await r.json().catch(() => ({}))
        setSaveMsg(err.detail ?? 'Save failed.')
      } else {
        setSaveMsg('Saved.')
      }
    } catch {
      setSaveMsg('Network error.')
    } finally {
      setSaving(false)
    }
  }, [cfg])

  const toggleDevMode = useCallback((next: boolean) => {
    localStorage.setItem(DEV_STORAGE_KEY, next ? '1' : '0')
    setDevMode(next)
    if (!next) { setFbState('idle'); setFbMsg(null) }
  }, [])

  const handleFastBaseline = useCallback(async () => {
    setFbState('running')
    setFbMsg(null)
    try {
      const r = await fetch('/dev/fast-baseline', { method: 'POST' })
      const body = await r.json().catch(() => ({}))
      if (!r.ok) {
        setFbState('err')
        setFbMsg(body.detail ?? 'Request failed.')
      } else {
        const triggered: string[] = body.triggered ?? []
        const skipped:   string[] = body.skipped   ?? []
        setFbState('ok')
        setFbMsg(
          `Started on ${triggered.length} node${triggered.length !== 1 ? 's' : ''}` +
          (skipped.length ? ` (${skipped.length} not found)` : '') + '.'
        )
      }
    } catch {
      setFbState('err')
      setFbMsg('Network error.')
    }
  }, [])

  const handleReset = useCallback(async (protocol: 'TCP' | 'UDP' | 'all') => {
    setResetting(protocol)
    try {
      await fetch(`/baseline/reset?protocol=${protocol}`, { method: 'POST' })
      // Reload so the alert feed clears and baselining indicator shows from scratch
      window.location.reload()
    } catch {
      setResetting(null)
    }
  }, [])

  const set = (key: keyof AppConfig, val: number | boolean) =>
    setCfg((c) => ({ ...c, [key]: val }))

  return (
    // Backdrop
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      onClick={onClose}
    >
      {/* Panel - stop propagation so clicking inside doesn't close */}
      <div
        className="w-[440px] max-w-[calc(100vw-2rem)] max-h-[90vh] border bg-card shadow-xl flex flex-col overflow-hidden"
        style={{ borderRadius: 'var(--radius)' }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b">
          <h2 className="text-sm font-semibold">Detection Settings</h2>
          <button
            onClick={onClose}
            className="text-muted-foreground hover:text-foreground transition-colors text-lg leading-none"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <div className="flex flex-col gap-5 p-5 overflow-y-auto">

          {/* Appearance */}
          <section className="flex flex-col gap-3">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              Appearance
            </h3>
            <div className="grid grid-cols-2 gap-2">
              {THEMES.map((t) => {
                const active = theme === t.name
                return (
                  <button
                    key={t.name}
                    onClick={() => setTheme(t.name)}
                    className={cn(
                      'flex items-center gap-2 px-3 py-2 border text-left transition-colors',
                      active
                        ? 'text-foreground'
                        : 'border-border bg-muted/20 text-muted-foreground hover:bg-muted/50',
                    )}
                    style={active ? {
                      borderColor: 'var(--color-accent)',
                      backgroundColor: 'color-mix(in srgb, var(--color-accent) 12%, transparent)',
                      borderRadius: 'var(--radius)',
                    } : { borderRadius: 'var(--radius)' }}
                  >
                    {/* Swatch */}
                    <span
                      className="h-5 w-5 shrink-0 border border-border/40"
                      style={{ backgroundColor: t.swatch, borderRadius: 'calc(var(--radius) / 2)' }}
                    />
                    <div>
                      <div className="text-xs font-medium leading-tight">{t.label}</div>
                      <div className="text-[10px] opacity-60 leading-tight">{t.description}</div>
                    </div>
                  </button>
                )
              })}
            </div>
          </section>

          {/* Thresholds */}
          <section className="flex flex-col gap-3 pt-1 border-t">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mt-2">
              Alert Thresholds  <span className="font-normal normal-case">(OIF composite score 0–1)</span>
            </h3>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              Raise to reduce false positives. Lower to catch more marginal anomalies.
              HIGH must be strictly less than CRITICAL.
            </p>

            <ThresholdSlider
              label="HIGH"
              value={cfg.threshold_high}
              min={0.30} max={cfg.threshold_critical - 0.01}
              varName="--color-badge-warn-text"
              onChange={(v) => set('threshold_high', v)}
            />
            <ThresholdSlider
              label="CRITICAL"
              value={cfg.threshold_critical}
              min={cfg.threshold_high + 0.01} max={0.99}
              varName="--color-badge-danger-text"
              onChange={(v) => set('threshold_critical', v)}
            />
          </section>

          {/* Baseline window */}
          <section className="flex flex-col gap-3">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              Baseline Window  <span className="font-normal normal-case">(flows before detection activates)</span>
            </h3>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              Larger = more stable baseline. TCP can tolerate 4096 (continuous traffic).
              UDP default 1024 suits sparse protocols like DNS/NTP.
            </p>
            <div className="grid grid-cols-2 gap-3">
              <BaselineInput label="TCP" value={cfg.baseline_tcp}
                onChange={(v) => set('baseline_tcp', v)} />
              <BaselineInput label="UDP" value={cfg.baseline_udp}
                onChange={(v) => set('baseline_udp', v)} />
            </div>
          </section>

          {/* Save */}
          <div className="flex items-center gap-3">
            <button
              onClick={handleSave}
              disabled={saving}
              className={cn(
                'px-4 py-1.5 text-xs font-medium transition-colors text-white',
                saving && 'opacity-50 cursor-not-allowed',
              )}
              style={{
                backgroundColor: 'var(--color-accent)',
                borderRadius: 'var(--radius)',
              }}
              onMouseEnter={(e) => {
                (e.currentTarget as HTMLButtonElement).style.backgroundColor = 'var(--color-accent-hover)'
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLButtonElement).style.backgroundColor = 'var(--color-accent)'
              }}
            >
              {saving ? 'Saving…' : 'Save'}
            </button>
            {saveMsg && (
              <span
                className="text-xs"
                style={{ color: saveMsg === 'Saved.' ? 'var(--color-count-trained)' : 'var(--color-badge-danger-text)' }}
              >
                {saveMsg}
              </span>
            )}
          </div>

          {/* Baseline reset */}
          <section className="flex flex-col gap-3 pt-1 border-t">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mt-2">
              Baseline Management
            </h3>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              Discards the trained OIF model and re-baselines on the next N flows of
              live traffic. Use after clearing an attack to prevent attack flows from
              polluting the baseline.
            </p>
            <div className="flex gap-2 flex-wrap">
              {(['TCP', 'UDP', 'all'] as const).map((p) => (
                <button
                  key={p}
                  onClick={() => handleReset(p)}
                  disabled={resetting !== null}
                  className={cn(
                    'px-3 py-1.5 text-xs transition-colors bg-muted hover:bg-muted/60',
                    resetting === p && 'opacity-50 cursor-not-allowed',
                  )}
                  style={{ borderRadius: 'var(--radius)' }}
                >
                  {resetting === p ? 'Resetting…' : `Reset ${p === 'all' ? 'All' : p}`}
                </button>
              ))}
            </div>
          </section>

          {/* Export */}
          <section className="flex flex-col gap-3 pt-1 border-t">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mt-2">
              Export
            </h3>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              Data is stored in <span className="font-mono">./data/flows.db</span> on the host
              and persists across container restarts.
            </p>
            <div className="flex flex-col gap-2">
              <a
                href="/export/flows.ndjson"
                download="corvus_flows.ndjson"
                className="flex items-center gap-2 px-3 py-1.5 text-xs bg-muted hover:bg-muted/60 transition-colors"
                style={{ borderRadius: 'var(--radius)' }}
              >
                <span className="font-medium">NDJSON - full flow records</span>
                <span className="text-muted-foreground ml-auto text-[10px]">
                  scores · attribution · timing
                </span>
              </a>
              <a
                href="/export/summary.csv"
                download="corvus_summary.csv"
                className="flex items-center gap-2 px-3 py-1.5 text-xs bg-muted hover:bg-muted/60 transition-colors"
                style={{ borderRadius: 'var(--radius)' }}
              >
                <span className="font-medium">CSV - hourly summary</span>
                <span className="text-muted-foreground ml-auto text-[10px]">
                  counts · mean score · OIF latency
                </span>
              </a>
            </div>
          </section>

          {/* Scenario runner */}
          <section className="flex flex-col gap-3 pt-1 border-t">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mt-2">
              Scenario Runner
            </h3>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              Mark evaluation phases in the database. Phase records align
              alert timestamps with attack windows for offline analysis.
            </p>

            {/* Active phase indicator */}
            {activePhase && (
              <div className="flex items-center gap-2 px-3 py-2 text-[11px]"
                style={{ borderRadius: 'var(--radius)', borderLeft: '2px solid var(--color-badge-danger-text)', backgroundColor: 'var(--color-sev-crit-bg)' }}>
                <span className="h-1.5 w-1.5 rounded-full animate-pulse shrink-0" style={{ backgroundColor: 'var(--color-badge-danger-text)' }} />
                <span className="flex-1 font-medium" style={{ color: 'var(--color-badge-danger-text)' }}>
                  Recording: {activePhase.label}
                </span>
                <button
                  onClick={handleClosePhase}
                  disabled={phaseBusy}
                  className="px-2 py-0.5 text-[10px] font-medium transition-colors"
                  style={{ backgroundColor: 'var(--color-badge-danger-text)', color: '#fff', borderRadius: 'var(--radius)', opacity: phaseBusy ? 0.5 : 1 }}
                >
                  Stop
                </button>
              </div>
            )}

            <div className="grid grid-cols-2 gap-2">
              <label className="flex flex-col gap-0.5">
                <span className="text-[10px] text-muted-foreground">Run ID</span>
                <input value={phaseRunId} onChange={e => setPhaseRunId(e.target.value)}
                  className="bg-muted px-2 py-1 text-xs font-mono focus:outline-none focus:ring-1 focus:ring-border"
                  style={{ borderRadius: 'var(--radius)' }} />
              </label>
              <label className="flex flex-col gap-0.5">
                <span className="text-[10px] text-muted-foreground">Scenario</span>
                <input value={phaseScenario} onChange={e => setPhaseScenario(e.target.value)}
                  className="bg-muted px-2 py-1 text-xs font-mono focus:outline-none focus:ring-1 focus:ring-border"
                  style={{ borderRadius: 'var(--radius)' }} />
              </label>
              <label className="flex flex-col gap-0.5">
                <span className="text-[10px] text-muted-foreground">Phase type</span>
                <select value={phaseType} onChange={e => setPhaseType(e.target.value)}
                  className="bg-muted px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-border"
                  style={{ borderRadius: 'var(--radius)' }}>
                  {['baseline', 'attack', 'benign', 'recovery'].map(p => (
                    <option key={p} value={p}>{p}</option>
                  ))}
                </select>
              </label>
              <label className="flex flex-col gap-0.5">
                <span className="text-[10px] text-muted-foreground">Attacker IP (optional)</span>
                <input value={phaseAttackerIp} onChange={e => setPhaseAttackerIp(e.target.value)}
                  placeholder="172.20.0.20"
                  className="bg-muted px-2 py-1 text-xs font-mono focus:outline-none focus:ring-1 focus:ring-border"
                  style={{ borderRadius: 'var(--radius)' }} />
              </label>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={handleOpenPhase}
                disabled={phaseBusy || !!activePhase}
                className="px-3 py-1.5 text-xs font-medium text-white transition-colors"
                style={{ backgroundColor: 'var(--color-accent)', borderRadius: 'var(--radius)', opacity: (phaseBusy || !!activePhase) ? 0.4 : 1 }}
              >
                Start Phase
              </button>
              {phaseMsg && <span className="text-[11px] text-muted-foreground">{phaseMsg}</span>}
            </div>

            {/* Recent phases log */}
            {phases.length > 0 && (
              <div className="flex flex-col gap-1 max-h-28 overflow-y-auto">
                {[...phases].reverse().slice(0, 10).map(p => (
                  <div key={p.phase_id} className="flex items-center gap-2 text-[10px] px-2 py-1 bg-muted/40"
                    style={{ borderRadius: 'var(--radius)' }}>
                    <span className="font-mono text-muted-foreground w-5 text-right">{p.phase_id}</span>
                    <span className="font-medium">{p.phase}</span>
                    <span className="text-muted-foreground">{p.scenario}</span>
                    <span className="ml-auto font-mono text-muted-foreground">
                      {p.t_end ? `${(p.t_end - p.t_start).toFixed(0)}s` : <span style={{ color: 'var(--color-badge-danger-text)' }}>open</span>}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* Feedback history */}
          <section className="flex flex-col gap-3 pt-1 border-t">
            <div className="flex items-center justify-between mt-2">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                Feedback History
              </h3>
              <button
                onClick={loadFeedback}
                disabled={feedbackLoading}
                className="text-[10px] text-muted-foreground hover:text-foreground transition-colors"
              >
                {feedbackLoading ? 'Loading…' : feedbackLog === null ? 'Load' : 'Refresh'}
              </button>
            </div>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              Analyst corrections stored for offline evaluation. Not currently
              fed back into the live model (ground-truth log only).
            </p>

            {feedbackLog !== null && (
              feedbackLog.length === 0 ? (
                <p className="text-[11px] text-muted-foreground">No feedback submitted yet.</p>
              ) : (
                <div className="flex flex-col gap-1 max-h-40 overflow-y-auto">
                  {feedbackLog.map(f => (
                    <div key={f.flow_id} className="flex flex-col gap-0.5 text-[10px] px-2 py-1.5 bg-muted/40"
                      style={{ borderRadius: 'var(--radius)' }}>
                      <div className="flex items-center gap-2">
                        <span
                          className="px-1 py-0.5 font-medium"
                          style={{
                            backgroundColor: f.dismiss ? 'var(--color-badge-warn-bg)' : 'var(--color-sev-info-bg)',
                            color: f.dismiss ? 'var(--color-badge-warn-text)' : 'var(--color-sev-info-text)',
                            borderRadius: 'calc(var(--radius)/2)',
                          }}
                        >
                          {f.dismiss ? 'FP dismiss' : f.corrected_label ?? 'correction'}
                        </span>
                        <span className="font-mono text-muted-foreground truncate flex-1">{f.flow_id.slice(0, 16)}…</span>
                        <span className="text-muted-foreground shrink-0">
                          {new Date(f.ts * 1000).toLocaleTimeString()}
                        </span>
                      </div>
                      {f.reason && <span className="text-muted-foreground pl-1">{f.reason}</span>}
                    </div>
                  ))}
                </div>
              )
            )}
          </section>

          {/* System */}
          <section className="flex flex-col gap-3 pt-1 border-t">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mt-2">
              System
            </h3>

            {sysStatus === null ? (
              <p className="text-[11px] text-muted-foreground">Loading…</p>
            ) : !sysStatus.docker ? (
              <p className="text-[11px] text-muted-foreground">
                Docker socket unavailable - container control disabled.
                {sysStatus.error && <span className="block font-mono mt-0.5 opacity-70">{sysStatus.error}</span>}
              </p>
            ) : (
              <div className="flex flex-col gap-2">
                {(['monitor', 'inference'] as const).map((key) => {
                  const info = sysStatus.containers[key]
                  const status = info?.status ?? 'unknown'
                  const running    = status === 'running'
                  const restarting = status === 'restarting'
                  const dotColor   = running    ? 'var(--color-online)'
                                   : restarting ? 'var(--color-baselining)'
                                   : status === 'unknown' ? 'hsl(var(--muted-foreground))'
                                   : 'var(--color-offline)'
                  const label = key === 'monitor' ? 'Capture monitor' : 'Inference engine'
                  const busyR = sysAction === `${key}/restart`
                  const busyS = sysAction === `${key}/stop`

                  return (
                    <div
                      key={key}
                      className="flex items-center gap-3 px-3 py-2 bg-muted/30"
                      style={{ borderRadius: 'var(--radius)' }}
                    >
                      {/* Status dot */}
                      <span
                        className={cn('h-2 w-2 rounded-full shrink-0', restarting && 'animate-pulse')}
                        style={{ backgroundColor: dotColor }}
                      />
                      {/* Label + status */}
                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-medium">{label}</div>
                        <div className="text-[10px] text-muted-foreground font-mono">{info?.name ?? key} · {status}</div>
                      </div>
                      {/* Actions */}
                      <div className="flex gap-1.5 shrink-0">
                        <button
                          onClick={() => handleSysAction(key, 'restart')}
                          disabled={!!sysAction}
                          title="Restart container"
                          className={cn(
                            'px-2 py-1 text-[10px] font-medium transition-colors bg-muted hover:bg-muted/60',
                            !!sysAction && 'opacity-40 cursor-not-allowed',
                          )}
                          style={{ borderRadius: 'var(--radius)' }}
                        >
                          {busyR ? '…' : 'Restart'}
                        </button>
                        {key === 'monitor' && (
                          <button
                            onClick={() => handleSysAction(key, 'stop')}
                            disabled={!!sysAction || !running}
                            title="Stop container"
                            className={cn(
                              'px-2 py-1 text-[10px] font-medium transition-colors',
                              (!!sysAction || !running) ? 'opacity-40 cursor-not-allowed bg-muted'
                                : 'bg-muted hover:bg-muted/60',
                            )}
                            style={{ borderRadius: 'var(--radius)' }}
                          >
                            {busyS ? '…' : 'Stop'}
                          </button>
                        )}
                        {key === 'inference' && (
                          <span className="text-[9px] text-muted-foreground self-center opacity-60">
                            restart reconnects
                          </span>
                        )}
                      </div>
                    </div>
                  )
                })}

                {sysMsg && (
                  <p
                    className="text-[11px]"
                    style={{ color: sysMsgOk ? 'var(--color-count-trained)' : 'var(--color-badge-danger-text)' }}
                  >
                    {sysMsg}
                  </p>
                )}
              </div>
            )}
          </section>

          {/* Capture interface */}
          <section className="flex flex-col gap-3 pt-1 border-t">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mt-2">
              Capture Interface
            </h3>
            <p className="text-[11px] text-muted-foreground leading-relaxed">
              Select the interface the capture engine should listen on.
              Changes are written to <span className="font-mono">capture.json</span> and
              applied immediately - no container restart needed.
            </p>

            {/* Currently running status - sourced from _status in capture.json */}
            {capStatus?.interface && (
              <div className="flex flex-col gap-1 px-3 py-2 bg-muted/40 text-[11px]"
                style={{ borderRadius: 'var(--radius)', borderLeft: '2px solid var(--color-count-trained)' }}>
                <div className="flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full shrink-0" style={{ backgroundColor: 'var(--color-count-trained)' }} />
                  <span className="font-medium text-foreground">Running:</span>
                  <span className="font-mono">{capStatus.interface}</span>
                </div>
                {capStatus.filter && (
                  <div className="text-muted-foreground pl-3">
                    filter: <span className="font-mono">{capStatus.filter}</span>
                  </div>
                )}
              </div>
            )}

            {capIfaceErr ? (
              <div className="text-[11px] text-muted-foreground bg-muted/40 px-3 py-2"
                style={{ borderRadius: 'var(--radius)' }}>
                <span className="font-medium">Interface list unavailable:</span> {capIfaceErr}
                <br />Enter an interface name manually below.
              </div>
            ) : capIfaces === null ? (
              <p className="text-[11px] text-muted-foreground">Loading interfaces…</p>
            ) : (
              <div className="flex flex-col gap-1">
                {capIfaces.map((iface) => (
                  <label
                    key={iface.name}
                    className={cn(
                      'flex items-center gap-2 px-3 py-1.5 border cursor-pointer transition-colors',
                      capSelected === iface.name
                        ? 'text-foreground'
                        : 'border-border bg-muted/20 text-muted-foreground hover:bg-muted/40',
                    )}
                    style={capSelected === iface.name ? {
                      borderColor: 'var(--color-accent)',
                      backgroundColor: 'color-mix(in srgb, var(--color-accent) 10%, transparent)',
                      borderRadius: 'var(--radius)',
                    } : { borderRadius: 'var(--radius)' }}
                  >
                    <input
                      type="radio"
                      name="cap-iface"
                      value={iface.name}
                      checked={capSelected === iface.name}
                      onChange={() => setCapSelected(iface.name)}
                      className="accent-current"
                    />
                    <span className="font-mono text-xs font-medium flex-1">{iface.name}</span>
                    <span className="flex gap-1">
                      {iface.up && (
                        <span className="text-[9px] px-1 py-0.5 rounded font-medium"
                          style={{ backgroundColor: 'var(--color-count-trained)', color: '#fff', borderRadius: 'calc(var(--radius)/2)' }}>
                          UP
                        </span>
                      )}
                      {iface.promisc && (
                        <span className="text-[9px] px-1 py-0.5 rounded font-medium"
                          style={{ backgroundColor: 'var(--color-badge-warn-bg)', color: 'var(--color-badge-warn-text)', borderRadius: 'calc(var(--radius)/2)', border: '1px solid var(--color-badge-warn-bdr)' }}>
                          PROMISC
                        </span>
                      )}
                    </span>
                  </label>
                ))}
              </div>
            )}

            {/* Testbed hint */}
            {capIfaces !== null && capIfaces.some((i) => i.name.startsWith('br-')) && (
              <p className="text-[10px] text-muted-foreground bg-muted/40 px-2 py-1.5"
                style={{ borderRadius: 'var(--radius)' }}>
                Testbed detected - use the <span className="font-mono">br-</span> bridge, not <span className="font-mono">docker0</span>.
                Docker creates a named bridge per compose network; <span className="font-mono">docker0</span> carries only standalone containers.
              </p>
            )}

            {/* Manual entry if not in list / no Docker */}
            <div className="flex flex-col gap-1">
              <label className="text-[11px] text-muted-foreground">
                Interface name {capIfaces !== null && capIfaces.length > 0 ? '(or enter manually)' : ''}
              </label>
              <input
                type="text"
                value={capSelected}
                onChange={(e) => setCapSelected(e.target.value)}
                placeholder="e.g. eth0, ens3, bond0"
                className="bg-muted px-2 py-1 text-xs font-mono focus:outline-none focus:ring-1 focus:ring-border"
                style={{ borderRadius: 'var(--radius)' }}
              />
            </div>

            {/* BPF filter */}
            <div className="flex flex-col gap-1">
              <label className="text-[11px] text-muted-foreground">BPF pre-filter (optional)</label>
              <input
                type="text"
                value={capFilter}
                onChange={(e) => setCapFilter(e.target.value)}
                placeholder="e.g. ip and not host 10.0.0.1"
                className="bg-muted px-2 py-1 text-xs font-mono focus:outline-none focus:ring-1 focus:ring-border"
                style={{ borderRadius: 'var(--radius)' }}
              />
            </div>

            {/* Set promiscuous toggle */}
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-muted-foreground">
                Persist promiscuous flag on host
                <span className="block text-[10px] opacity-60">
                  libpcap sets promisc automatically - only needed for Mode 2 auto-detection
                </span>
              </span>
              <button
                onClick={() => setCapPromisc((v) => !v)}
                className="flex items-center gap-1.5 text-xs transition-colors"
              >
                <span
                  className="inline-flex items-center h-4 w-7 border transition-colors"
                  style={{
                    backgroundColor: capPromisc ? 'color-mix(in srgb, var(--color-accent) 20%, transparent)' : 'hsl(var(--muted))',
                    borderColor: capPromisc ? 'var(--color-accent)' : 'hsl(var(--border))',
                    borderRadius: 'var(--radius)',
                  }}
                >
                  <span
                    className="h-3 w-3 border transition-all"
                    style={{
                      transform: capPromisc ? 'translateX(14px)' : 'translateX(1px)',
                      backgroundColor: capPromisc ? 'var(--color-accent)' : 'hsl(var(--muted-foreground))',
                      borderColor: 'transparent',
                      borderRadius: 'calc(var(--radius) / 2)',
                    }}
                  />
                </span>
                {capPromisc ? 'Yes' : 'No'}
              </button>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={handleCapApply}
                disabled={capApplying || !capSelected.trim()}
                className={cn(
                  'px-4 py-1.5 text-xs font-medium transition-colors text-white',
                  (capApplying || !capSelected.trim()) && 'opacity-40 cursor-not-allowed',
                )}
                style={{ backgroundColor: 'var(--color-accent)', borderRadius: 'var(--radius)' }}
              >
                {capApplying ? 'Validating & restarting…' : 'Apply'}
              </button>
              {capMsg && (
                <span
                  className="text-xs"
                  style={{ color: capMsgOk ? 'var(--color-count-trained)' : 'var(--color-badge-danger-text)' }}
                >
                  {capMsg}
                </span>
              )}
            </div>
          </section>

          {/* Developer Mode */}
          <section className="flex flex-col gap-3 pt-1 border-t">
            <div className="flex items-center justify-between mt-2">
              <h3
                className="text-xs font-semibold uppercase tracking-wider"
                style={{ color: 'var(--color-badge-warn-text)' }}
              >
                Developer Mode
              </h3>
              {/* Toggle */}
              <button
                onClick={() => toggleDevMode(!devMode)}
                className="flex items-center gap-1.5 text-xs transition-colors"
                style={{ color: devMode ? 'var(--color-badge-warn-text)' : undefined }}
              >
                <span
                  className="inline-flex items-center h-4 w-7 border transition-colors"
                  style={{
                    backgroundColor: devMode ? 'var(--color-badge-warn-bg)' : 'hsl(var(--muted))',
                    borderColor: devMode ? 'var(--color-badge-warn-bdr)' : 'hsl(var(--border))',
                    borderRadius: 'var(--radius)',
                  }}
                >
                  <span
                    className="h-3 w-3 border transition-all"
                    style={{
                      transform: devMode ? 'translateX(14px)' : 'translateX(1px)',
                      backgroundColor: devMode ? 'var(--color-badge-warn-text)' : 'hsl(var(--muted-foreground))',
                      borderColor: 'transparent',
                      borderRadius: 'calc(var(--radius) / 2)',
                    }}
                  />
                </span>
                {devMode ? 'On' : 'Off'}
              </button>
            </div>

            {devMode && (
              <div className="flex flex-col gap-4">

                {/* Fast Baseline */}
                <div className="flex flex-col gap-2">
                  <p className="text-[11px] text-muted-foreground leading-relaxed">
                    Runs <span className="font-mono">fast_baseline.sh</span> on all 5 node
                    containers simultaneously; generates HTTP, DNS, and SSH traffic to
                    fill the OIF baselines in ~20 seconds instead of organic traffic time.
                    Requires all node containers to be running.
                  </p>
                  <div className="flex items-center gap-3">
                    <button
                      onClick={handleFastBaseline}
                      disabled={fbState === 'running'}
                      className={cn(
                        'px-3 py-1.5 text-xs font-medium transition-colors border',
                        fbState === 'running' && 'opacity-50 cursor-not-allowed',
                      )}
                      style={{
                        backgroundColor: 'var(--color-badge-warn-bg)',
                        borderColor:     'var(--color-badge-warn-bdr)',
                        color:           'var(--color-badge-warn-text)',
                        borderRadius:    'var(--radius)',
                      }}
                    >
                      {fbState === 'running' ? 'Triggering…' : 'Trigger Fast Baseline'}
                    </button>
                    {fbMsg && (
                      <span
                        className="text-xs"
                        style={{ color: fbState === 'err' ? 'var(--color-badge-danger-text)' : 'var(--color-count-trained)' }}
                      >
                        {fbMsg}
                      </span>
                    )}
                  </div>
                </div>

                {/* Min TCP packets */}
                <div className="flex flex-col gap-1.5 pt-2 border-t border-dashed" style={{ borderColor: 'var(--color-badge-warn-bdr)' }}>
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-medium" style={{ color: 'var(--color-badge-warn-text)' }}>
                      Min TCP packet guard
                    </span>
                    <span className="text-xs tabular-nums font-mono" style={{ color: 'var(--color-badge-warn-text)' }}>
                      {cfg.min_tcp_pkts} pkts
                    </span>
                  </div>
                  <input
                    type="range"
                    min={2} max={10} step={1}
                    value={cfg.min_tcp_pkts}
                    onChange={(e) => set('min_tcp_pkts', parseInt(e.target.value))}
                    style={{ accentColor: 'var(--color-badge-warn-text)' }}
                    className="w-full"
                  />
                  <p className="text-[10px] text-muted-foreground leading-relaxed">
                    Default 4 blocks micro-flows (port scans, SYN floods) from reaching
                    the OIF. Set to 2–3 to observe how the detector scores these flows.
                    <span className="font-medium" style={{ color: 'var(--color-badge-warn-text)' }}> Value of 1 floods the inference queue; port scans generate ~1000 flows at once. Poisoning risk at low values.</span>
                  </p>
                </div>

                {/* Filter gateway */}
                <div className="flex flex-col gap-1.5 pt-2 border-t border-dashed" style={{ borderColor: 'var(--color-badge-warn-bdr)' }}>
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-medium" style={{ color: 'var(--color-badge-warn-text)' }}>
                      Filter gateway traffic
                    </span>
                    <button
                      onClick={() => set('filter_gateway', !cfg.filter_gateway)}
                      className="flex items-center gap-1.5 text-xs transition-colors"
                      style={{ color: cfg.filter_gateway ? 'var(--color-badge-warn-text)' : undefined }}
                    >
                      <span
                        className="inline-flex items-center h-4 w-7 border transition-colors"
                        style={{
                          backgroundColor: cfg.filter_gateway ? 'var(--color-badge-warn-bg)' : 'hsl(var(--muted))',
                          borderColor:     cfg.filter_gateway ? 'var(--color-badge-warn-bdr)' : 'hsl(var(--border))',
                          borderRadius:    'var(--radius)',
                        }}
                      >
                        <span
                          className="h-3 w-3 border transition-all"
                          style={{
                            transform:       cfg.filter_gateway ? 'translateX(14px)' : 'translateX(1px)',
                            backgroundColor: cfg.filter_gateway ? 'var(--color-badge-warn-text)' : 'hsl(var(--muted-foreground))',
                            borderColor:     'transparent',
                            borderRadius:    'calc(var(--radius) / 2)',
                          }}
                        />
                      </span>
                      {cfg.filter_gateway ? 'On' : 'Off'}
                    </button>
                  </div>
                  <p className="text-[10px] text-muted-foreground leading-relaxed">
                    Suppress flows from <span className="font-mono">172.20.0.1</span> (Docker
                    bridge gateway; API polls, dashboard WebSocket). Enables cleaner FPR
                    measurement during eval runs. Does not affect detection quality.
                  </p>
                </div>

              </div>
            )}
          </section>

        </div>
      </div>
    </div>
  )
}


// sub-components

function ThresholdSlider({
  label, value, min, max, varName, onChange,
}: {
  label: string
  value: number
  min: number
  max: number
  varName: string
  onChange: (v: number) => void
}) {
  return (
    <div className="flex items-center gap-3">
      <span
        className="text-[10px] font-semibold w-14 text-right"
        style={{ color: `var(${varName})` }}
      >
        {label}
      </span>
      <input
        type="range"
        min={min} max={max} step={0.01}
        value={value}
        onChange={(e) => onChange(parseFloat(e.target.value))}
        className="flex-1 accent-current"
        style={{ accentColor: `var(${varName})` }}
      />
      <span className="w-10 text-xs tabular-nums text-right">{value.toFixed(2)}</span>
    </div>
  )
}

function BaselineInput({
  label, value, onChange,
}: {
  label: string
  value: number
  onChange: (v: number) => void
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[11px] text-muted-foreground">{label} flows</span>
      <input
        type="number"
        min={64}
        value={value}
        onChange={(e) => onChange(Math.max(64, parseInt(e.target.value) || 64))}
        className={cn(
          'bg-muted px-2 py-1 text-xs tabular-nums',
          'focus:outline-none focus:ring-1 focus:ring-border w-full',
        )}
        style={{ borderRadius: 'var(--radius)' }}
      />
    </label>
  )
}
