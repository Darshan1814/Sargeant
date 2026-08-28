import { useEffect, useState } from 'react'
import axios from 'axios'
import { Panel, Kpi, BarList, StatusBadge, Confidence } from '../components/ui'

/**
 * Operational overview.
 *
 * Answers, at a glance: how many events arrived, how many were processed
 * successfully, how many need review, which source families were seen, which
 * event categories were identified, how many reached the common schema, and
 * whether the platform is healthy.
 *
 * Everything rendered here comes from GET /api/overview. No percentage, count or
 * rate is computed or assumed in the browser — if the backend cannot determine a
 * figure, the tile shows an explicit dash instead of a fabricated value.
 *
 * Internal vocabulary (parser identifiers, fallback engine names, pipeline path
 * tokens, database names) is intentionally absent from this screen. Those remain
 * available per event under "Processing Details".
 */

const REFRESH_MS = 10000

function num(n) {
  return n == null ? '—' : Number(n).toLocaleString()
}

/** Pipeline funnel. Each stage explains how its number was derived on hover. */
function Pipeline({ stages }) {
  if (!stages?.length) return <p className="text-xs text-gray-500">No events processed yet.</p>
  const first = stages[0]?.count || 0
  return (
    <ol className="space-y-1.5">
      {stages.map((s, i) => {
        const width = first ? Math.max((s.count / first) * 100, 1) : 0
        const dropped = i > 0 ? (stages[i - 1].count - s.count) : 0
        return (
          <li
            key={s.stage}
            className="grid grid-cols-[minmax(7rem,9.5rem)_1fr_auto] items-center gap-3"
            title={s.definition}
          >
            <span className="flex items-center gap-2 truncate text-xs text-gray-300">
              <span className="w-4 text-right text-[10px] tabular-nums text-gray-600">
                {i + 1}
              </span>
              {s.stage}
            </span>
            <span className="h-5 rounded-sm bg-gray-800/80">
              <span
                className="flex h-full items-center rounded-sm bg-gradient-to-r from-cyan-600/50 to-cyan-500/30"
                style={{ width: `${width}%` }}
              />
            </span>
            <span className="w-32 text-right text-xs tabular-nums">
              <span className="text-gray-200">{num(s.count)}</span>
              <span className="ml-1.5 text-gray-600">{s.pct}%</span>
              {dropped > 0 && (
                <span
                  className="ml-1.5 text-amber-500/70"
                  title={`${num(dropped)} fewer than the previous stage`}
                >
                  −{num(dropped)}
                </span>
              )}
            </span>
          </li>
        )
      })}
    </ol>
  )
}

/** Quality breakdown: parsing and mapping are separate concerns, never merged. */
function QualityRows({ rows }) {
  if (!rows?.length) return <p className="text-xs text-gray-500">Not yet measured.</p>
  return (
    <ul className="space-y-2.5">
      {rows.map(r => (
        <li key={r.label}>
          <div className="flex items-baseline justify-between gap-2">
            <span className="text-xs text-gray-300">{r.label}</span>
            <span className="text-xs tabular-nums">
              <span className="text-gray-100">{r.pct}%</span>
              <span className="ml-2 text-gray-600">{num(r.count)}</span>
            </span>
          </div>
          <div className="mt-1 h-1.5 rounded-sm bg-gray-800">
            <div
              className="h-full rounded-sm bg-gray-500"
              style={{ width: `${Math.max(r.pct, 0.5)}%` }}
            />
          </div>
        </li>
      ))}
    </ul>
  )
}

export default function Overview() {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let alive = true
    const load = () =>
      axios
        .get('/api/overview')
        .then(r => { if (alive) { setData(r.data); setError(null) } })
        .catch(e => { if (alive) setError(e.message || 'Request failed') })
    load()
    const id = setInterval(load, REFRESH_MS)
    return () => { alive = false; clearInterval(id) }
  }, [])

  const k = data?.kpis
  const rate = k?.processing_rate

  // Source rows. An "Unidentified" bucket is surfaced honestly rather than being
  // silently folded into another family.
  const sourceRows = (data?.sources || []).map(s => ({
    label: s.label, count: s.count, pct: s.pct, muted: !s.identified,
  }))
  const unidentified = (data?.sources || []).find(s => !s.identified)

  const typeRows = (data?.event_types || []).map(t => ({
    label: t.name, count: t.count, pct: t.pct,
  }))

  // The health payload carries a top-level `status` verdict ("ok" / "degraded")
  // alongside one entry per dependency. `status` must be excluded from the
  // per-service scan — treating it as a service would make "ok" look like an
  // unrecognised (therefore degraded) state and permanently show a false warning.
  // A "yellow" OpenSearch cluster is expected on a single node and is not a fault.
  const HEALTHY = ['up', 'green', 'yellow', 'disabled']
  const services = Object.entries(data?.health || {}).filter(([kk]) => kk !== 'status')
  const unhealthy = services.filter(
    ([, v]) => typeof v === 'string' && !HEALTHY.includes(v)
  )

  return (
    <div className="mx-auto max-w-[1600px] space-y-4">
      {/* ── Masthead ── */}
      <header className="flex flex-wrap items-end justify-between gap-x-6 gap-y-2 border-b border-gray-800 pb-4">
        <div>
          <div className="flex items-baseline gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-white">ULPF</h1>
            <span className="text-sm text-gray-400">
              Universal Log Pre-processing Framework
            </span>
          </div>
          <p className="mt-1 max-w-3xl text-xs leading-relaxed text-gray-500">
            Convert heterogeneous logs into a common, lossless, analytics-ready
            representation.
          </p>
        </div>
        <div className="flex items-center gap-3 text-[11px]">
          <span className="text-gray-600">Air-gapped deployment</span>
          <span className="text-gray-700">·</span>
          {error ? (
            <span className="text-red-400">Backend unreachable</span>
          ) : unhealthy.length === 0 ? (
            <span className="flex items-center gap-1.5 text-emerald-300">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
              All services operational
            </span>
          ) : (
            <span
              className="flex items-center gap-1.5 text-amber-300"
              title={unhealthy.map(([kk, vv]) => `${kk}: ${vv}`).join('\n')}
            >
              <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
              {unhealthy.length} service{unhealthy.length > 1 ? 's' : ''} degraded
            </span>
          )}
        </div>
      </header>

      {error && !data && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-4 text-xs text-red-300">
          Could not load the overview: {error}
        </div>
      )}

      {/* ── KPI row ── */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Kpi label="Total Events" value={num(k?.total_events)} tone="text-white" />
        <Kpi
          label="Successfully Parsed"
          value={k?.successfully_parsed ? num(k.successfully_parsed.count) : null}
          pct={k?.successfully_parsed?.pct}
          tone="text-emerald-300"
          hint="Parsed and confidently mapped"
        />
        <Kpi
          label="OCSF Mapped"
          value={k?.ocsf_mapped ? num(k.ocsf_mapped.count) : null}
          pct={k?.ocsf_mapped?.pct}
          tone="text-cyan-300"
          hint="Reached the common schema"
        />
        <Kpi
          label="Needs Review"
          value={k?.needs_review ? num(k.needs_review.count) : null}
          pct={k?.needs_review?.pct}
          tone="text-amber-300"
          hint="Low mapping confidence"
        />
        <Kpi
          label="Unresolved"
          value={k?.unresolved ? num(k.unresolved.count) : null}
          pct={k?.unresolved?.pct}
          tone="text-slate-300"
          hint="Retained, not discarded"
        />
        <Kpi
          label="Processing Rate"
          value={rate ? `${num(Math.round(rate.throughput_eps))}` : null}
          tone="text-white"
          hint={
            rate
              ? `events/sec · measured over ${num(rate.events)} events`
              : 'Not yet measured — run an upload'
          }
        />
      </div>

      {/* ── Pipeline + quality ── */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel
          className="xl:col-span-2"
          title="Processing Pipeline"
          subtitle="Every record reaches a canonical representation. Hover a stage for how its figure is derived."
        >
          <Pipeline stages={data?.pipeline} />
        </Panel>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-1">
          <Panel title="Parsing Quality" subtitle="Was the record's structure understood?">
            <QualityRows rows={data?.quality?.parsing} />
          </Panel>
          <Panel title="Mapping Quality" subtitle="Did it reach the common schema?">
            <QualityRows rows={data?.quality?.mapping} />
          </Panel>
        </div>
      </div>

      {/* ── Distributions ── */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel
          title="Log Sources"
          subtitle="Originating system family, determined during processing"
        >
          <BarList rows={sourceRows} topN={6} emptyMessage="No events processed yet" />
          {unidentified?.count > 0 && (
            <p className="mt-3 border-t border-gray-800 pt-2.5 text-[11px] leading-snug text-gray-500">
              Source identification unavailable for {num(unidentified.count)} events
              ({unidentified.pct}%). These are retained in full and listed under
              Unresolved Events.
            </p>
          )}
        </Panel>

        <Panel
          title="Event Types"
          subtitle="Identified event category, with its schema class as secondary detail"
        >
          <BarList rows={typeRows} topN={6} emptyMessage="No events classified yet" />
          <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 border-t border-gray-800 pt-2.5">
            {(data?.event_types || []).slice(0, 6).map(t => (
              <span key={t.name} className="text-[10px] text-gray-600">
                {t.name}
                {t.class_uid != null && (
                  <span className="ml-1 text-gray-700">· OCSF Class {t.class_uid}</span>
                )}
              </span>
            ))}
          </div>
        </Panel>
      </div>

      {/* ── Recent activity ── */}
      <Panel
        title="Recent Activity"
        subtitle="Most recently processed events"
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-gray-800 text-[10px] uppercase tracking-wider text-gray-500">
                <th className="pb-2 pr-3 font-medium">Time</th>
                <th className="pb-2 pr-3 font-medium">Source</th>
                <th className="pb-2 pr-3 font-medium">Event Type</th>
                <th className="pb-2 pr-3 font-medium">Activity</th>
                <th className="pb-2 pr-3 font-medium">Host</th>
                <th className="pb-2 pr-3 font-medium">Status</th>
                <th className="pb-2 pr-3 font-medium">Confidence</th>
              </tr>
            </thead>
            <tbody>
              {(data?.recent || []).map(r => (
                <tr
                  key={r.event_id}
                  className="border-b border-gray-800/60 last:border-0 hover:bg-gray-800/30"
                >
                  <td className="py-2 pr-3 tabular-nums text-gray-400">
                    {(r.time || '').toString().slice(11, 19) || '—'}
                  </td>
                  <td className="py-2 pr-3 text-gray-200">{r.source}</td>
                  <td className="py-2 pr-3 text-gray-200">
                    {r.event_type}
                    {r.class_uid != null && (
                      <span className="ml-1.5 text-[10px] text-gray-600">
                        {r.class_uid}
                      </span>
                    )}
                  </td>
                  <td className="py-2 pr-3 text-gray-400">{r.activity}</td>
                  <td className="py-2 pr-3 truncate max-w-[10rem] text-gray-300" title={r.host || ''}>
                    {r.host || '—'}
                  </td>
                  <td className="py-2 pr-3"><StatusBadge status={r.status} /></td>
                  <td className="py-2 pr-3"><Confidence value={r.confidence} /></td>
                </tr>
              ))}
              {!data?.recent?.length && (
                <tr>
                  <td colSpan={7} className="py-6 text-center text-gray-600">
                    No events yet. Upload a log file to begin.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  )
}
