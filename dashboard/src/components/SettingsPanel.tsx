// SettingsPanel.tsx — analyst-facing configuration: alert thresholds,
// baseline management, and visual theme selection.
//
// Thresholds take effect immediately on save (inference engine reads cfg
// per-flow with no restart needed). Baseline reset discards the trained
// OIF model and re-baselines on the next N flows of live traffic.

import { useCallback, useEffect, useState } from 'react'
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

export function SettingsPanel({ onClose }: Props) {
  const [cfg, setCfg]             = useState<AppConfig>(DEFAULT_CFG)
  const [saving, setSaving]       = useState(false)
  const [saveMsg, setSaveMsg]     = useState<string | null>(null)
  const [resetting, setResetting] = useState<string | null>(null)
  const [devMode, setDevMode]     = useState(() => localStorage.getItem(DEV_STORAGE_KEY) === '1')
  const [fbState, setFbState]     = useState<'idle' | 'running' | 'ok' | 'err'>('idle')
  const [fbMsg, setFbMsg]         = useState<string | null>(null)

  const { theme, setTheme } = useTheme()

  // Load current config from inference engine on open
  useEffect(() => {
    fetch('/config')
      .then((r) => r.json())
      .then((data: AppConfig) => setCfg(data))
      .catch(() => { /* leave defaults */ })
  }, [])

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
      {/* Panel — stop propagation so clicking inside doesn't close */}
      <div
        className="w-[440px] border bg-card shadow-xl flex flex-col gap-0 overflow-hidden"
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

          {/* ── Appearance ─────────────────────────────────────────────── */}
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

          {/* ── Thresholds ─────────────────────────────────────────────── */}
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

          {/* ── Baseline window ────────────────────────────────────────── */}
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

          {/* ── Baseline reset ─────────────────────────────────────────── */}
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

          {/* ── Developer Mode ────────────────────────────────────────── */}
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
                    containers simultaneously — generates HTTP, DNS, and SSH traffic to
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
                    <span className="font-medium" style={{ color: 'var(--color-badge-warn-text)' }}> Value of 1 floods the inference queue — port scans generate ~1000 flows at once. Poisoning risk at low values.</span>
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
                    bridge gateway — API polls, dashboard WebSocket). Enables cleaner FPR
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


// ── sub-components ────────────────────────────────────────────────────────────

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
