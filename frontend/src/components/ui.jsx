import { useState } from 'react'

// Shared presentation primitives for the operator-facing screens.
//
// These live in one place so the Overview, the processing results and the review
// queue can never disagree about what a status means or how confidence is worded.
// Nothing here invents data: every component renders only what it is given and
// falls back to an explicit "unavailable" state rather than a placeholder number.

// ── Status vocabulary ─────────────────────────────────────────────────────────
// Mirrors backend `_user_facing_status`. Five mutually exclusive outcomes, each
// with a plain-language explanation. Internal tokens (parse_status /
// ocsf_mapping_status / parse_path) are deliberately never shown here.
export const STATUS_STYLE = {
  SUCCESS: {
    dot: 'bg-emerald-400',
    text: 'text-emerald-300',
    ring: 'border-emerald-500/30 bg-emerald-500/10',
    icon: '✓',
  },
  PARTIAL: {
    dot: 'bg-amber-400',
    text: 'text-amber-300',
    ring: 'border-amber-500/30 bg-amber-500/10',
    icon: '◐',
  },
  REVIEW: {
    dot: 'bg-sky-400',
    text: 'text-sky-300',
    ring: 'border-sky-500/30 bg-sky-500/10',
    icon: '⁇',
  },
  UNRESOLVED: {
    dot: 'bg-slate-400',
    text: 'text-slate-300',
    ring: 'border-slate-500/30 bg-slate-500/10',
    icon: '–',
  },
  ERROR: {
    dot: 'bg-red-400',
    text: 'text-red-300',
    ring: 'border-red-500/30 bg-red-500/10',
    icon: '✕',
  },
}

/** A status badge that always carries its own explanation. */
export function StatusBadge({ status, size = 'sm' }) {
  if (!status) return <span className="text-gray-600">—</span>
  const code = typeof status === 'string' ? status : status.code
  const label = typeof status === 'string' ? '' : status.label
  const s = STATUS_STYLE[code] || STATUS_STYLE.REVIEW
  const pad = size === 'lg' ? 'px-3 py-1.5 text-sm' : 'px-2 py-0.5 text-[11px]'
  return (
    <span
      title={label}
      className={`inline-flex items-center gap-1.5 rounded-md border font-medium ${s.ring} ${s.text} ${pad}`}
    >
      <span aria-hidden="true">{s.icon}</span>
      <span className="whitespace-nowrap">{label || code}</span>
    </span>
  )
}

// ── Confidence ────────────────────────────────────────────────────────────────
const CONFIDENCE_TOOLTIP =
  'Confidence represents how strongly the processing pipeline matched the event ' +
  'format, source, extracted fields and schema mapping. It is an indicator of ' +
  'match strength, not a guarantee of correctness.'

export function confidenceBand(value) {
  if (value == null) return null
  const pct = value <= 1 ? value * 100 : value
  if (pct >= 85) return { label: 'High confidence', tone: 'text-emerald-300', bar: 'bg-emerald-400' }
  if (pct >= 60) return { label: 'Medium confidence', tone: 'text-amber-300', bar: 'bg-amber-400' }
  return { label: 'Low confidence', tone: 'text-red-300', bar: 'bg-red-400' }
}

/** Confidence as a number AND a qualitative band, never a bare mystery figure. */
export function Confidence({ value, showBar = false }) {
  if (value == null) {
    return <span className="text-gray-600" title="Not recorded for this event">—</span>
  }
  const pct = Math.round((value <= 1 ? value * 100 : value))
  const band = confidenceBand(value)
  return (
    <span className="inline-flex items-center gap-2" title={CONFIDENCE_TOOLTIP}>
      <span className="tabular-nums text-gray-100">{pct}%</span>
      <span className={`text-[11px] ${band.tone}`}>{band.label}</span>
      {showBar && (
        <span className="inline-block h-1 w-16 rounded bg-gray-700 overflow-hidden align-middle">
          <span className={`block h-full ${band.bar}`} style={{ width: `${pct}%` }} />
        </span>
      )}
    </span>
  )
}

// ── Layout primitives ─────────────────────────────────────────────────────────

export function Panel({ title, subtitle, action, children, className = '' }) {
  return (
    <section
      className={`rounded-lg border border-gray-800 bg-gray-900/60 ${className}`}
    >
      {(title || action) && (
        <header className="flex items-start justify-between gap-3 border-b border-gray-800 px-4 py-3">
          <div>
            {title && (
              <h2 className="text-[13px] font-semibold tracking-wide text-gray-200">
                {title}
              </h2>
            )}
            {subtitle && (
              <p className="mt-0.5 text-[11px] leading-snug text-gray-500">{subtitle}</p>
            )}
          </div>
          {action}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  )
}

/** A KPI tile. `pct` is optional; nothing is fabricated when a value is absent. */
export function Kpi({ label, value, pct, hint, tone = 'text-gray-50' }) {
  const missing = value == null || value === ''
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900/60 px-4 py-3">
      <div className="text-[10px] font-medium uppercase tracking-[0.12em] text-gray-500">
        {label}
      </div>
      <div className="mt-1.5 flex items-baseline gap-2">
        <span className={`text-2xl font-semibold tabular-nums ${missing ? 'text-gray-600' : tone}`}>
          {missing ? '—' : value}
        </span>
        {pct != null && !missing && (
          <span className="text-xs tabular-nums text-gray-400">{pct}%</span>
        )}
      </div>
      {hint && <div className="mt-1 text-[11px] leading-snug text-gray-500">{hint}</div>}
    </div>
  )
}

/**
 * Horizontal distribution bars.
 *
 * Deliberately CSS rather than a charting library: the label sits in its own
 * column beside the track instead of on top of it, so labels can never overlap
 * the bar or each other at any viewport width. Long tails collapse into a single
 * "Other" row with an opt-in "View all".
 */
export function BarList({ rows, topN = 5, emptyMessage = 'No data available', unit = 'events' }) {
  const [expanded, setExpanded] = useState(false)
  if (!rows || rows.length === 0) {
    return <p className="text-xs text-gray-500">{emptyMessage}</p>
  }
  const sorted = [...rows].sort((a, b) => b.count - a.count)
  const max = Math.max(...sorted.map(r => r.count), 1)

  let shown = sorted
  let otherRow = null
  if (!expanded && sorted.length > topN) {
    shown = sorted.slice(0, topN)
    const rest = sorted.slice(topN)
    const restCount = rest.reduce((s, r) => s + r.count, 0)
    const restPct = rest.reduce((s, r) => s + (r.pct || 0), 0)
    otherRow = {
      label: `Other (${rest.length})`,
      count: restCount,
      pct: Math.round(restPct * 10) / 10,
      muted: true,
    }
  }
  const display = otherRow ? [...shown, otherRow] : shown

  return (
    <div>
      <ul className="space-y-2">
        {display.map(r => (
          <li key={r.label} className="grid grid-cols-[minmax(6rem,9rem)_1fr_auto] items-center gap-3">
            <span
              className={`truncate text-xs ${r.muted ? 'text-gray-500' : 'text-gray-300'}`}
              title={r.label}
            >
              {r.label}
            </span>
            <span
              className="h-2 rounded-sm bg-gray-800"
              title={`${r.label}: ${r.count.toLocaleString()} ${unit} (${r.pct ?? 0}%)`}
            >
              <span
                className={`block h-full rounded-sm ${r.muted ? 'bg-gray-600' : 'bg-cyan-500/70'}`}
                style={{ width: `${Math.max((r.count / max) * 100, 1)}%` }}
              />
            </span>
            <span className="w-24 text-right text-xs tabular-nums text-gray-400">
              {r.count.toLocaleString()}
              <span className="ml-1.5 text-gray-600">{r.pct ?? 0}%</span>
            </span>
          </li>
        ))}
      </ul>
      {sorted.length > topN && (
        <button
          type="button"
          onClick={() => setExpanded(!expanded)}
          className="mt-3 text-[11px] text-cyan-400 hover:text-cyan-300"
        >
          {expanded ? 'Show top ' + topN : `View all ${sorted.length}`}
        </button>
      )}
    </div>
  )
}


