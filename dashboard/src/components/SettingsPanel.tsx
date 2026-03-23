// SettingsPanel.tsx — analyst-facing configuration: alert thresholds and
// baseline management. Opened via the gear icon in StatusBar.
//
// Thresholds take effect immediately on save (inference engine reads cfg
// per-flow with no restart needed). Baseline reset discards the trained
// OIF model and re-baselines on the next N flows of live traffic.

import { useCallback, useEffect, useState } from 'react'
import type { AppConfig } from '../types'
import { cn } from '../lib/utils'

interface Props {
  onClose: () => void
}

const DEFAULT_CFG: AppConfig = {
  threshold_high:     0.60,
  threshold_critical: 0.80,
  baseline_tcp:       4096,
  baseline_udp:       1024,
}

export function SettingsPanel({ onClose }: Props) {
  const [cfg, setCfg]           = useState<AppConfig>(DEFAULT_CFG)
  const [saving, setSaving]     = useState(false)
  const [saveMsg, setSaveMsg]   = useState<string | null>(null)
  const [resetting, setResetting] = useState<string | null>(null)

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

  const set = (key: keyof AppConfig, val: number) =>
    setCfg((c) => ({ ...c, [key]: val }))

  return (
    // Backdrop
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      onClick={onClose}
    >
      {/* Panel — stop propagation so clicking inside doesn't close */}
      <div
        className="w-[420px] rounded-lg border bg-card shadow-xl flex flex-col gap-0 overflow-hidden"
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

          {/* Thresholds */}
          <section className="flex flex-col gap-3">
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
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
              color="bg-amber-400"
              onChange={(v) => set('threshold_high', v)}
            />
            <ThresholdSlider
              label="CRITICAL"
              value={cfg.threshold_critical}
              min={cfg.threshold_high + 0.01} max={0.99}
              color="bg-red-500"
              onChange={(v) => set('threshold_critical', v)}
            />
          </section>

          {/* Baseline sizes */}
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
                'px-4 py-1.5 rounded text-xs font-medium transition-colors',
                'bg-blue-600 hover:bg-blue-500 text-white',
                saving && 'opacity-50 cursor-not-allowed',
              )}
            >
              {saving ? 'Saving…' : 'Save'}
            </button>
            {saveMsg && (
              <span className={cn(
                'text-xs',
                saveMsg === 'Saved.' ? 'text-emerald-400' : 'text-red-400',
              )}>
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
                    'px-3 py-1.5 rounded text-xs transition-colors',
                    'bg-muted hover:bg-muted/60',
                    resetting === p && 'opacity-50 cursor-not-allowed',
                  )}
                >
                  {resetting === p ? 'Resetting…' : `Reset ${p === 'all' ? 'All' : p}`}
                </button>
              ))}
            </div>
          </section>

        </div>
      </div>
    </div>
  )
}


// ── sub-components ────────────────────────────────────────────────────────────

function ThresholdSlider({
  label, value, min, max, color, onChange,
}: {
  label: string
  value: number
  min: number
  max: number
  color: string
  onChange: (v: number) => void
}) {
  return (
    <div className="flex items-center gap-3">
      <span className={cn('text-[10px] font-semibold w-14 text-right', color.replace('bg-', 'text-'))}>
        {label}
      </span>
      <input
        type="range"
        min={min} max={max} step={0.01}
        value={value}
        onChange={(e) => onChange(parseFloat(e.target.value))}
        className="flex-1 accent-blue-500"
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
          'rounded bg-muted px-2 py-1 text-xs tabular-nums',
          'focus:outline-none focus:ring-1 focus:ring-border w-full',
        )}
      />
    </label>
  )
}