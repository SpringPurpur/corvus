export const G3 = {
  bg:         'hsl(var(--background))',
  card:       'hsl(var(--card))',
  card2:      'hsl(var(--muted))',
  fg:         'hsl(var(--foreground))',
  mute:       'hsl(var(--muted-foreground))',
  mute2:      'hsl(var(--foreground) / 0.65)',
  line:       'hsl(var(--border))',
  lineSoft:   'hsl(var(--border) / 0.5)',
  accent:     'var(--color-accent)',
  accentSoft: 'color-mix(in srgb, var(--color-accent) 12%, transparent)',
  accentMid:  'color-mix(in srgb, var(--color-accent) 30%, transparent)',
  purple:     'var(--color-bar-secondary)',
  ok:         'var(--color-online)',
  info:       'var(--color-sev-info-text)',
  infoBg:     'var(--color-sev-info-bg)',
  crit:       'var(--color-badge-danger-text)',
  critBg:     'var(--color-badge-danger-bg)',
  high:       'var(--color-badge-warn-text)',
  highBg:     'var(--color-badge-warn-bg)',
} as const

export const alpha = (color: string, pct: number): string =>
  `color-mix(in srgb, ${color} ${pct}%, transparent)`

export const sevCol = (s: string): string =>
  s === 'CRITICAL' ? G3.crit : s === 'HIGH' ? G3.high : G3.info

export const sevBg = (s: string): string =>
  s === 'CRITICAL' ? G3.critBg : s === 'HIGH' ? G3.highBg : G3.infoBg
