// FeatureRadar.tsx - spider/radar chart of per-feature IQR deviation.
//
// Each axis = one attribution feature.  The radius encodes how many IQRs the
// anomalous flow's value sits away from the baseline median:
//   radius = min( |value − median| / IQR , MAX_DEV ) / MAX_DEV
//
// Reading the chart:
//   Grey band  → 1 IQR from baseline ("normal operating range")
//   Coloured polygon → actual deviation; spikes pointing outward mark the
//                      features that pushed this flow beyond the grey zone
//   Axis labels → abbreviated feature names (hover title shows the full name)

import type { AttributionEntry } from '../types'

const MAX_FEATURES = 6    // cap axes so labels don't overlap
const MAX_DEV      = 4    // IQRs at which we clip to the outer ring
const CX = 100, CY = 100, R = 72

// Shorten long snake_case names so they fit inside the SVG label area.
// Strategy: remove common prefixes, title-case the rest, clip at 12 chars.
const PREFIX_RE = /^(fwd_|bwd_|flow_)/
function abbrev(name: string): string {
  return name
    .replace(PREFIX_RE, '')
    .replace(/_/g, ' ')
    .slice(0, 12)
}

interface Props {
  attribution: AttributionEntry[]
  severity:    'INFO' | 'HIGH' | 'CRITICAL'
}

export function FeatureRadar({ attribution, severity }: Props) {
  const entries = attribution.slice(0, MAX_FEATURES)
  const N = entries.length
  if (N < 3) return null   // a polygon needs ≥ 3 vertices

  const angle = (i: number) => (2 * Math.PI * i) / N - Math.PI / 2

  // Compute IQR-normalised deviation fraction for each feature.
  // Fall back to entry.score (0-1 contribution) when IQR is unavailable or zero.
  const devFrac = entries.map((e) => {
    const iqr = e.baseline?.iqr ?? 0
    if (iqr < 1e-9) return Math.min(e.score, 1)
    const dev = Math.abs(e.value - (e.baseline?.median ?? 0)) / iqr
    return Math.min(dev / MAX_DEV, 1)
  })

  // Convert an array of fractions → polygon point string
  const toPoints = (fracs: number[]) =>
    fracs
      .map((f, i) => {
        const a = angle(i)
        return `${(CX + R * f * Math.cos(a)).toFixed(2)},${(CY + R * f * Math.sin(a)).toFixed(2)}`
      })
      .join(' ')

  const normalFrac  = Array<number>(N).fill(1 / MAX_DEV)  // 1 IQR band
  const allAxes     = entries.map((_, i) => angle(i))

  const fillColor =
    severity === 'CRITICAL' ? 'var(--color-score-crit)' :
    severity === 'HIGH'     ? 'var(--color-score-high)' :
                              'var(--color-accent)'

  return (
    <svg
      viewBox="0 0 200 200"
      className="w-full"
      style={{ maxHeight: 188 }}
      aria-label="Feature deviation radar"
    >
      {/* Axis lines */}
      {allAxes.map((a, i) => (
        <line
          key={i}
          x1={CX} y1={CY}
          x2={(CX + R * Math.cos(a)).toFixed(2)}
          y2={(CY + R * Math.sin(a)).toFixed(2)}
          stroke="currentColor"
          strokeWidth="0.5"
          className="text-border opacity-50"
        />
      ))}

      {/* Concentric reference rings at 25 / 50 / 75 / 100 % */}
      {[0.25, 0.5, 0.75, 1].map((level) => (
        <polygon
          key={level}
          points={toPoints(Array<number>(N).fill(level))}
          fill="none"
          stroke="currentColor"
          strokeWidth={level === 1 ? 0.75 : 0.4}
          className="text-border"
          opacity={0.45}
        />
      ))}

      {/* Normal band - 1 IQR from baseline */}
      <polygon
        points={toPoints(normalFrac)}
        fill="var(--color-score-normal)"
        fillOpacity={0.18}
        stroke="var(--color-score-normal)"
        strokeWidth="1"
        strokeOpacity={0.6}
      />

      {/* Anomaly polygon */}
      <polygon
        points={toPoints(devFrac)}
        fill={fillColor}
        fillOpacity={0.20}
        stroke={fillColor}
        strokeWidth="1.5"
        strokeLinejoin="round"
      />

      {/* Axis labels */}
      {entries.map((e, i) => {
        const a      = angle(i)
        const lx     = CX + (R + 15) * Math.cos(a)
        const ly     = CY + (R + 15) * Math.sin(a)
        const anchor =
          Math.cos(a) >  0.15 ? 'start'  :
          Math.cos(a) < -0.15 ? 'end'    :
                                 'middle'
        return (
          <text
            key={i}
            x={lx.toFixed(2)}
            y={ly.toFixed(2)}
            textAnchor={anchor}
            dominantBaseline="middle"
            fontSize="7.5"
            fill="currentColor"
            className="text-muted-foreground"
          >
            <title>{e.feature}</title>
            {abbrev(e.feature)}
          </text>
        )
      })}

      {/* IQR legend note */}
      <text
        x="100" y="197"
        textAnchor="middle"
        fontSize="6"
        fill="currentColor"
        className="text-muted-foreground"
        opacity="0.55"
      >
        grey band = 1 IQR · outer ring = {MAX_DEV} IQRs
      </text>
    </svg>
  )
}