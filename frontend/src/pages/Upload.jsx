import { useState, useRef, useMemo } from 'react'
import axios from 'axios'
import { Panel, Kpi, StatusBadge, Confidence } from '../components/ui'
import {
  detected, extractedFields, normalizedSummary, ocsfMapping, userStatus,
  technicalDetails, parseStages, highlightRaw, matchesFilters, distinct,
  humanFormat, reviewReason,
} from '../lib/event'

/**
 * Log processing and results.
 *
 * Structured so an evaluator reads one event in the intended order: the raw line,
 * what system produced it, which fields were lifted out, what it was normalized
 * into, which schema event it became, how confident the mapping is, and how to
 * trace it back to the original.
 *
 * A file summary is shown first and individual records are paginated, so a
 * 10,000-line upload never renders 10,000 nodes.
 */

const PAGE_SIZES = [50, 100, 250, 500]

function Section({ label, children, right }) {
  return (
    <div className="border-t border-gray-800 px-4 py-3 first:border-t-0">
      <div className="mb-2 flex items-center justify-between gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-500">
          {label}
        </span>
        {right}
      </div>
      {children}
    </div>
  )
}

function FieldGrid({ items, mono = false }) {
  if (!items?.length) {
    return <p className="text-xs text-gray-600">None could be determined from this record.</p>
  }
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-1.5 sm:grid-cols-2 xl:grid-cols-3">
      {items.map(f => (
        <div key={f.label + f.value} className="flex items-baseline gap-2 min-w-0">
          <dt className="w-28 shrink-0 truncate text-[11px] text-gray-500" title={f.label}>
            {f.label}
          </dt>
          <dd
            className={`min-w-0 flex-1 truncate text-xs text-gray-100 ${mono ? 'font-mono' : ''}`}
            title={f.value}
          >
            {f.value}
          </dd>
        </div>
      ))}
    </dl>
  )
}

/** Raw text with extracted values highlighted, proving provenance. */
function RawText({ raw, fields, highlight = true }) {
  const parts = highlight ? highlightRaw(raw, fields) : [{ text: raw, field: null }]
  return (
    <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-words rounded border border-gray-800 bg-gray-950/70 p-2.5 text-[11px] leading-relaxed text-gray-300">
      {parts.map((p, i) =>
        p.field ? (
          <mark
            key={i}
            title={`Extracted as ${p.field.label} → ${p.field.path}`}
            className="rounded bg-cyan-500/20 px-0.5 text-cyan-200"
          >
            {p.text}
          </mark>
        ) : (
          <span key={i}>{p.text}</span>
        )
      )}
    </pre>
  )
}

/** Three-column traceability: original → canonical → schema. */
function CompareTriptych({ row }) {
  const n = row.normalized || {}
  const fields = extractedFields(n)
  const ocsf = ocsfMapping(n)
  return (
    <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
      <div>
        <h4 className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
          Raw Event
        </h4>
        <RawText raw={row.raw} fields={fields} />
        <p className="mt-1.5 text-[10px] text-gray-600">
          Highlighted spans were located literally in the source text.
        </p>
      </div>
      <div>
        <h4 className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
          Extracted → Canonical
        </h4>
        <ul className="space-y-1 rounded border border-gray-800 bg-gray-950/40 p-2.5">
          {fields.length === 0 && (
            <li className="text-[11px] text-gray-600">No fields extracted.</li>
          )}
          {fields.map(f => (
            <li key={f.path} className="text-[11px] leading-snug">
              <span className="text-gray-500">{f.label}</span>
              <span className="mx-1 text-gray-700">=</span>
              <span className="text-cyan-200">{f.value}</span>
            </li>
          ))}
        </ul>
      </div>
      <div>
        <h4 className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
          Schema Event (OCSF)
        </h4>
        <ul className="space-y-1 rounded border border-gray-800 bg-gray-950/40 p-2.5">
          {fields.map(f => (
            <li key={f.path} className="text-[11px] leading-snug">
              <span className="font-mono text-emerald-300/90">{f.path}</span>
              <span className="mx-1 text-gray-700">=</span>
              <span className="text-gray-200">{f.value}</span>
            </li>
          ))}
          {ocsf?.classUid != null && (
            <li className="mt-1.5 border-t border-gray-800 pt-1.5 text-[11px]">
              <span className="font-mono text-emerald-300/90">class_uid</span>
              <span className="mx-1 text-gray-700">=</span>
              <span className="text-gray-200">{ocsf.classUid}</span>
              <span className="ml-1.5 text-gray-500">({ocsf.className})</span>
            </li>
          )}
        </ul>
      </div>
    </div>
  )
}

function Drawer({ title, onClose, children }) {
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/70 p-4 sm:p-8">
      <div className="w-full max-w-5xl rounded-lg border border-gray-700 bg-gray-900 shadow-2xl">
        <header className="flex items-center justify-between border-b border-gray-800 px-4 py-3">
          <h3 className="text-sm font-semibold text-gray-100">{title}</h3>
          <button
            onClick={onClose}
            className="rounded px-2 py-0.5 text-xs text-gray-400 hover:bg-gray-800 hover:text-white"
          >
            Close
          </button>
        </header>
        <div className="max-h-[75vh] overflow-y-auto p-4">{children}</div>
      </div>
    </div>
  )
}

function JsonBlock({ value }) {
  return (
    <pre className="overflow-auto whitespace-pre-wrap break-words rounded border border-gray-800 bg-gray-950/70 p-3 text-[11px] leading-relaxed text-gray-300">
      {JSON.stringify(value, null, 2)}
    </pre>
  )
}

/** One processing card. */
function ProcessingCard({ row }) {
  const [view, setView] = useState(null)
  const [showTech, setShowTech] = useState(false)
  const n = row.normalized || {}
  const det = detected(n)
  const fields = extractedFields(n)
  const ocsf = ocsfMapping(n)
  const status = userStatus(n)
  const cb = n.confidence_breakdown || {}
  const reasons = reviewReason(n)

  const detItems = [
    { label: 'Format', value: det.format || 'Not positively identified' },
    { label: 'Source', value: det.source || 'Not identified' },
    { label: 'Service', value: det.service || '—' },
    { label: 'Event Type', value: det.eventType || 'Unclassified' },
  ]

  return (
    <article className="rounded-lg border border-gray-800 bg-gray-900/50">
      {/* header */}
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-800 px-4 py-2.5">
        <div className="flex items-center gap-3">
          <span className="text-[10px] tabular-nums text-gray-600">
            line {row.line_no}
          </span>
          <StatusBadge status={status} />
        </div>
        <div className="flex items-center gap-3">
          <Confidence value={row.confidence} showBar />
        </div>
      </header>

      <Section label="Raw Event">
        <RawText raw={row.raw} fields={fields} />
      </Section>

      <Section label="Detected">
        <FieldGrid items={detItems} />
      </Section>

      <Section
        label="Extracted Fields"
        right={
          <span className="text-[10px] text-gray-600">
            {fields.length} field{fields.length !== 1 ? 's' : ''}
            {cb.field_coverage != null &&
              ` · ${Math.round(cb.field_coverage * 100)}% mapped to schema`}
          </span>
        }
      >
        <FieldGrid items={fields} mono />
      </Section>

      <Section label="Normalized Event">
        <FieldGrid items={normalizedSummary(n)} />
      </Section>

      <Section label="OCSF Mapping">
        {ocsf ? (
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
            {[
              ['Class', ocsf.className],
              ['Activity', ocsf.activity],
              ['Outcome', ocsf.status],
              ['Severity', ocsf.severity],
            ].map(([l, v]) => (
              <div key={l} className="flex items-baseline gap-2">
                <span className="text-[11px] text-gray-500">{l}</span>
                <span className="text-xs text-gray-100">{v || '—'}</span>
              </div>
            ))}
            {ocsf.classUid != null && (
              <span className="text-[10px] text-gray-600">OCSF Class {ocsf.classUid}</span>
            )}
            {!ocsf.mapped && (
              <span className="text-[11px] text-sky-300">
                Schema mapping requires review
              </span>
            )}
          </div>
        ) : (
          <p className="text-xs text-gray-600">Not available.</p>
        )}
      </Section>

      {reasons.length > 0 && status.code !== 'SUCCESS' && (
        <Section label="Why this needs attention">
          <ul className="space-y-1">
            {reasons.map(r => (
              <li key={r} className="flex gap-2 text-[11px] text-gray-400">
                <span className="text-amber-500/70">•</span>
                {r}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {/* actions */}
      <footer className="flex flex-wrap items-center gap-2 border-t border-gray-800 px-4 py-2.5">
        {[
          ['Raw', 'raw'],
          ['Normalized', 'normalized'],
          ['OCSF', 'ocsf'],
          ['Compare', 'compare'],
        ].map(([label, key]) => (
          <button
            key={key}
            onClick={() => setView(key)}
            className="rounded border border-gray-700 px-2.5 py-1 text-[11px] text-gray-300 hover:border-gray-600 hover:bg-gray-800 hover:text-white"
          >
            View {label}
          </button>
        ))}
        <button
          onClick={() => setShowTech(!showTech)}
          className="rounded border border-gray-700 px-2.5 py-1 text-[11px] text-gray-400 hover:bg-gray-800 hover:text-white"
        >
          {showTech ? 'Hide' : 'Processing'} Details
        </button>
      </footer>

      {/* technical details — the only place internal identifiers appear */}
      {showTech && (
        <div className="border-t border-gray-800 bg-gray-950/40 px-4 py-3">
          <p className="mb-2 text-[10px] text-gray-600">
            Developer traceability. Not required to interpret the event.
          </p>
          <div className="mb-3">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">
              Processing stages
            </span>
            <ol className="mt-1 flex flex-wrap items-center gap-x-1.5 gap-y-1">
              {parseStages(n).map((s, i, arr) => (
                <li key={s} className="flex items-center gap-1.5 text-[11px] text-gray-400">
                  <span className="rounded bg-gray-800 px-1.5 py-0.5">{s}</span>
                  {i < arr.length - 1 && <span className="text-gray-700">→</span>}
                </li>
              ))}
            </ol>
          </div>
          <FieldGrid items={technicalDetails(n, row)} mono />
        </div>
      )}

      {view === 'raw' && (
        <Drawer title={`Raw event · line ${row.line_no}`} onClose={() => setView(null)}>
          <RawText raw={row.raw} fields={fields} />
          <p className="mt-2 text-[11px] text-gray-500">
            Retained byte-for-byte. Integrity hash:{' '}
            <span className="font-mono text-gray-400">
              {n.metadata?.raw_sha256 || 'not recorded'}
            </span>
          </p>
        </Drawer>
      )}
      {view === 'normalized' && (
        <Drawer title="Normalized event" onClose={() => setView(null)}>
          <FieldGrid items={normalizedSummary(n)} />
          <details className="mt-4">
            <summary className="cursor-pointer text-[11px] text-cyan-400">
              Show complete canonical record
            </summary>
            <div className="mt-2"><JsonBlock value={n} /></div>
          </details>
        </Drawer>
      )}
      {view === 'ocsf' && (
        <Drawer title="OCSF event" onClose={() => setView(null)}>
          <JsonBlock value={n} />
        </Drawer>
      )}
      {view === 'compare' && (
        <Drawer title="Raw → Normalized → OCSF" onClose={() => setView(null)}>
          <CompareTriptych row={row} />
        </Drawer>
      )}
    </article>
  )
}

export default function Upload() {
  const [text, setText] = useState('')
  const [file, setFile] = useState(null)
  const [dragOver, setDragOver] = useState(false)
  const [job, setJob] = useState(null)
  const [running, setRunning] = useState(false)
  const [err, setErr] = useState(null)
  const [showResults, setShowResults] = useState(false)
  const [page, setPage] = useState(0)
  const [pageSize, setPageSize] = useState(PAGE_SIZES[0])
  const [tab, setTab] = useState('all')
  const [filters, setFilters] = useState({
    q: '', source: '', format: '', eventType: '', status: '',
    severity: '', outcome: '', host: '', minConfidence: '',
  })
  const fileRef = useRef(null)

  const results = job?.results || []
  const done = job?.status === 'completed'

  function reset() {
    setJob(null); setErr(null); setShowResults(false); setPage(0); setTab('all')
  }

  async function run() {
    setErr(null); setJob(null); setShowResults(false); setRunning(true); setPage(0)
    try {
      const form = new FormData()
      if (file) form.append('file', file)
      else if (text.trim()) form.append('text', text)
      else { setErr('Provide a file or paste some log text'); setRunning(false); return }

      const { data } = await axios.post('/api/upload', form)
      const jobId = data.job_id
      await new Promise(resolve => {
        const id = setInterval(async () => {
          try {
            const s = await axios.get(`/api/ingest/status/${jobId}`)
            setJob(s.data)
            if (s.data.status === 'completed' || s.data.status === 'error') {
              clearInterval(id); resolve()
            }
          } catch { clearInterval(id); resolve() }
        }, 500)
      })
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message)
    } finally {
      setRunning(false)
    }
  }

  // Outcome tallies computed from the returned records themselves.
  const tally = useMemo(() => {
    const t = { SUCCESS: 0, PARTIAL: 0, REVIEW: 0, UNRESOLVED: 0, ERROR: 0, mapped: 0 }
    for (const r of results) {
      const s = userStatus(r.normalized || {})
      t[s.code] = (t[s.code] || 0) + 1
      if (r.normalized?.ocsf_mapping_status === 'mapped') t.mapped++
    }
    return t
  }, [results])

  const tabbed = useMemo(() => {
    if (tab === 'review') {
      return results.filter(r => ['REVIEW', 'PARTIAL'].includes(userStatus(r.normalized || {}).code))
    }
    if (tab === 'unresolved') {
      return results.filter(r => ['UNRESOLVED', 'ERROR'].includes(userStatus(r.normalized || {}).code))
    }
    return results
  }, [results, tab])

  const filtered = useMemo(
    () => tabbed.filter(r => matchesFilters(r, filters)),
    [tabbed, filters]
  )

  const pageCount = Math.max(Math.ceil(filtered.length / pageSize), 1)
  const safePage = Math.min(page, pageCount - 1)
  const visible = filtered.slice(safePage * pageSize, safePage * pageSize + pageSize)

  const opts = useMemo(() => ({
    source: distinct(results, n => n.device?.os?.family),
    format: distinct(results, n => humanFormat(n)),
    eventType: distinct(results, n => n.class_name),
    severity: distinct(results, n => n.severity),
    outcome: distinct(results, n => n.status),
    host: distinct(results, n => n.device?.hostname),
  }), [results])

  function setF(k, v) { setFilters(p => ({ ...p, [k]: v })); setPage(0) }

  const activeFilters = Object.entries(filters).filter(([, v]) => v).length

  return (
    <div className="mx-auto max-w-[1600px] space-y-4">
      <header className="border-b border-gray-800 pb-4">
        <h1 className="text-lg font-bold text-white">Log Processing</h1>
        <p className="mt-1 max-w-3xl text-xs leading-relaxed text-gray-500">
          Submit logs in any supported format. Each record is identified, parsed,
          normalized and mapped to the common schema, and remains traceable to its
          original bytes.
        </p>
      </header>

      {/* ── Input ── */}
      {!done && (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <div
            onDragOver={e => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onDrop={e => {
              e.preventDefault(); setDragOver(false)
              const f = e.dataTransfer.files?.[0]
              if (f) { setFile(f); setText('') }
            }}
            onClick={() => fileRef.current?.click()}
            className={`cursor-pointer rounded-lg border border-dashed p-6 text-center transition-colors ${
              dragOver ? 'border-cyan-500 bg-cyan-500/5' : 'border-gray-700 bg-gray-900/40'
            }`}
          >
            <input
              ref={fileRef}
              type="file"
              className="hidden"
              onChange={e => {
                const f = e.target.files?.[0]
                if (f) { setFile(f); setText('') }
              }}
            />
            <p className="text-xs text-gray-300">
              {file
                ? `${file.name} · ${file.size.toLocaleString()} bytes`
                : 'Drop a log file here, or click to browse'}
            </p>
            <p className="mt-1 text-[11px] text-gray-600">
              Windows, Linux, macOS, network devices, applications, syslog, JSON
            </p>
          </div>
          <textarea
            value={text}
            onChange={e => { setText(e.target.value); setFile(null) }}
            placeholder="…or paste raw log text, one record per line"
            className="min-h-[132px] resize-y rounded-lg border border-gray-800 bg-gray-900/40 p-3 font-mono text-[11px] text-gray-200 placeholder:text-gray-600"
          />
        </div>
      )}

      {!done && (
        <div className="flex items-center gap-3">
          <button
            onClick={run}
            disabled={running}
            className="rounded bg-cyan-700 px-4 py-1.5 text-xs font-medium text-white hover:bg-cyan-600 disabled:opacity-50"
          >
            {running ? 'Processing…' : 'Process Logs'}
          </button>
          {(file || text) && !running && (
            <button
              onClick={() => { setFile(null); setText(''); reset() }}
              className="text-[11px] text-gray-500 hover:text-gray-300"
            >
              Clear
            </button>
          )}
        </div>
      )}

      {err && (
        <div className="rounded border border-red-500/30 bg-red-500/5 p-3 text-xs text-red-300">
          {err}
        </div>
      )}

      {/* ── Live progress ── */}
      {job && !done && (
        <Panel title="Processing">
          <div className="mb-2 flex justify-between text-[11px] text-gray-400">
            <span>{job.processed?.toLocaleString()} of {job.total?.toLocaleString()} records</span>
            <span className="tabular-nums">{job.percent}%</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded bg-gray-800">
            <div
              className="h-full bg-cyan-500 transition-all"
              style={{ width: `${job.percent || 0}%` }}
            />
          </div>
        </Panel>
      )}

      {/* ── File summary, shown before any individual record ── */}
      {done && (
        <>
          <Panel
            title="Processing Complete"
            subtitle={file?.name || 'Pasted input'}
            action={
              <div className="flex flex-wrap items-center gap-2">
                {!showResults && (
                  <button
                    onClick={() => setShowResults(true)}
                    className="rounded bg-cyan-700 px-3 py-1 text-[11px] font-medium text-white hover:bg-cyan-600"
                  >
                    View Results
                  </button>
                )}
                {['json', 'csv', 'parquet'].map(f => (
                  <button
                    key={f}
                    onClick={() => window.open(`/api/export/${f}`, '_blank')}
                    className="rounded border border-gray-700 px-2.5 py-1 text-[11px] uppercase text-gray-300 hover:bg-gray-800"
                  >
                    {f}
                  </button>
                ))}
                <button
                  onClick={() => { setFile(null); setText(''); reset() }}
                  className="text-[11px] text-gray-500 hover:text-gray-300"
                >
                  New upload
                </button>
              </div>
            }
          >
            <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
              <Kpi label="Events Received" value={job.total?.toLocaleString()} tone="text-white" />
              <Kpi
                label="Successfully Processed"
                value={tally.SUCCESS.toLocaleString()}
                tone="text-emerald-300"
              />
              <Kpi
                label="Partially Mapped"
                value={tally.PARTIAL.toLocaleString()}
                tone="text-amber-300"
              />
              <Kpi
                label="Needs Review"
                value={tally.REVIEW.toLocaleString()}
                tone="text-sky-300"
              />
              <Kpi
                label="Unresolved"
                value={(tally.UNRESOLVED + tally.ERROR).toLocaleString()}
                tone="text-slate-300"
                hint="Retained in full"
              />
              <Kpi
                label="Processing Time"
                value={job.elapsed_seconds != null ? `${job.elapsed_seconds}s` : null}
                hint={
                  job.throughput_eps != null
                    ? `${Math.round(job.throughput_eps).toLocaleString()} events/sec measured`
                    : undefined
                }
              />
            </div>
            {results.length < (job.total || 0) && (
              <p className="mt-3 border-t border-gray-800 pt-2.5 text-[11px] text-gray-500">
                Showing detail for the first {results.length.toLocaleString()} of{' '}
                {job.total.toLocaleString()} records. All records were processed and
                stored; use the export buttons for the complete set.
              </p>
            )}
          </Panel>

          {/* ── Results ── */}
          {showResults && (
            <>
              <Panel
                title="Records"
                subtitle="Search and filter using plain terms — no schema identifiers required."
                action={
                  <div className="flex items-center gap-1.5">
                    {[
                      ['all', `All (${results.length})`],
                      ['review', `Needs Review (${tally.REVIEW + tally.PARTIAL})`],
                      ['unresolved', `Unresolved (${tally.UNRESOLVED + tally.ERROR})`],
                    ].map(([k, label]) => (
                      <button
                        key={k}
                        onClick={() => { setTab(k); setPage(0) }}
                        className={`rounded px-2.5 py-1 text-[11px] ${
                          tab === k
                            ? 'bg-gray-700 text-white'
                            : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
                        }`}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                }
              >
                <div className="grid grid-cols-2 gap-2 md:grid-cols-4 xl:grid-cols-7">
                  <input
                    value={filters.q}
                    onChange={e => setF('q', e.target.value)}
                    placeholder="Search text, host, user…"
                    className="col-span-2 rounded border border-gray-800 bg-gray-950/60 px-2 py-1 text-[11px] text-gray-200 placeholder:text-gray-600"
                  />
                  {[
                    ['source', 'Any source', opts.source],
                    ['format', 'Any format', opts.format],
                    ['eventType', 'Any event type', opts.eventType],
                    ['severity', 'Any severity', opts.severity],
                    ['outcome', 'Any outcome', opts.outcome],
                  ].map(([key, placeholder, values]) => (
                    <select
                      key={key}
                      value={filters[key]}
                      onChange={e => setF(key, e.target.value)}
                      className="rounded border border-gray-800 bg-gray-950/60 px-2 py-1 text-[11px] text-gray-300"
                    >
                      <option value="">{placeholder}</option>
                      {values.map(v => (
                        <option key={v} value={v}>{v}</option>
                      ))}
                    </select>
                  ))}
                  <select
                    value={filters.status}
                    onChange={e => setF('status', e.target.value)}
                    className="rounded border border-gray-800 bg-gray-950/60 px-2 py-1 text-[11px] text-gray-300"
                  >
                    <option value="">Any status</option>
                    {['SUCCESS', 'PARTIAL', 'REVIEW', 'UNRESOLVED', 'ERROR'].map(s => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                  <select
                    value={filters.minConfidence}
                    onChange={e => setF('minConfidence', e.target.value)}
                    className="rounded border border-gray-800 bg-gray-950/60 px-2 py-1 text-[11px] text-gray-300"
                  >
                    <option value="">Any confidence</option>
                    <option value="90">Above 90%</option>
                    <option value="75">Above 75%</option>
                    <option value="50">Above 50%</option>
                  </select>
                </div>

                <div className="mt-3 flex flex-wrap items-center justify-between gap-3 border-t border-gray-800 pt-2.5">
                  <span className="text-[11px] text-gray-500">
                    {filtered.length.toLocaleString()} matching record
                    {filtered.length !== 1 ? 's' : ''}
                    {activeFilters > 0 && (
                      <button
                        onClick={() => setFilters({
                          q: '', source: '', format: '', eventType: '', status: '',
                          severity: '', outcome: '', host: '', minConfidence: '',
                        })}
                        className="ml-2 text-cyan-400 hover:text-cyan-300"
                      >
                        clear {activeFilters} filter{activeFilters > 1 ? 's' : ''}
                      </button>
                    )}
                  </span>
                  <div className="flex items-center gap-3 text-[11px] text-gray-500">
                    <label className="flex items-center gap-1.5">
                      Per page
                      <select
                        value={pageSize}
                        onChange={e => { setPageSize(Number(e.target.value)); setPage(0) }}
                        className="rounded border border-gray-800 bg-gray-950/60 px-1.5 py-0.5 text-gray-300"
                      >
                        {PAGE_SIZES.map(s => <option key={s} value={s}>{s}</option>)}
                      </select>
                    </label>
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => setPage(Math.max(safePage - 1, 0))}
                        disabled={safePage === 0}
                        className="rounded border border-gray-800 px-2 py-0.5 disabled:opacity-40 hover:bg-gray-800"
                      >
                        Prev
                      </button>
                      <span className="tabular-nums px-1">
                        {safePage + 1} / {pageCount}
                      </span>
                      <button
                        onClick={() => setPage(Math.min(safePage + 1, pageCount - 1))}
                        disabled={safePage >= pageCount - 1}
                        className="rounded border border-gray-800 px-2 py-0.5 disabled:opacity-40 hover:bg-gray-800"
                      >
                        Next
                      </button>
                    </div>
                  </div>
                </div>
              </Panel>

              {tab === 'unresolved' && visible.length > 0 && (
                <div className="rounded border border-gray-800 bg-gray-900/40 px-4 py-2.5 text-[11px] leading-relaxed text-gray-400">
                  These records could not be confidently identified. They are
                  retained in full with their original bytes and integrity hash —
                  nothing was discarded.
                </div>
              )}

              <div className="space-y-3">
                {visible.map(r => (
                  <ProcessingCard key={`${r.line_no}-${r.event_id}`} row={r} />
                ))}
                {visible.length === 0 && (
                  <p className="rounded border border-gray-800 bg-gray-900/40 p-6 text-center text-xs text-gray-600">
                    No records match the current filters.
                  </p>
                )}
              </div>
            </>
          )}
        </>
      )}
    </div>
  )
}
