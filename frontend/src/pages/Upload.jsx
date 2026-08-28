import { useState, useRef } from 'react'
import axios from 'axios'

const PATH_COLOR = { ngre: '#10b981', drain3: '#f59e0b', dlq: '#ef4444', error: '#ef4444' }

export default function Upload() {
  const [text, setText] = useState('')
  const [file, setFile] = useState(null)
  const [dragOver, setDragOver] = useState(false)
  const [job, setJob] = useState(null)
  const [running, setRunning] = useState(false)
  const [err, setErr] = useState(null)
  const [copied, setCopied] = useState(false)
  const fileRef = useRef(null)

  function onDrop(e) {
    e.preventDefault(); setDragOver(false)
    const f = e.dataTransfer.files?.[0]
    if (f) { setFile(f); setText('') }
  }

  async function process() {
    setErr(null); setJob(null); setCopied(false); setRunning(true)
    try {
      const form = new FormData()
      if (file) form.append('file', file)
      else if (text.trim()) form.append('text', text)
      else { setErr('Provide a file or paste some log text'); setRunning(false); return }

      const { data } = await axios.post('/api/upload', form)
      const jobId = data.job_id
      await new Promise((resolve) => {
        const id = setInterval(async () => {
          try {
            const s = await axios.get(`/api/ingest/status/${jobId}`)
            setJob(s.data)
            if (s.data.status === 'completed') { clearInterval(id); resolve() }
          } catch { clearInterval(id); resolve() }
        }, 500)
      })
    } catch (e) {
      setErr(e?.response?.data?.detail || e.message)
    } finally {
      setRunning(false)
    }
  }

  function copyJson() {
    const payload = JSON.stringify((job?.results || []).map(r => r.normalized), null, 2)
    navigator.clipboard?.writeText(payload).then(() => {
      setCopied(true); setTimeout(() => setCopied(false), 1500)
    })
  }

  function download(fmt) {
    // Existing export endpoint (DuckDB source-of-truth). Opens a real file download.
    window.open(`/api/export/${fmt}`, '_blank')
  }

  const counts = job?.counts || {}
  const done = job?.status === 'completed'
  const results = job?.results || []

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Log Upload</h1>
        <p className="text-gray-500 text-sm mt-1">
          Drop a file or paste raw logs in any format. The framework automatically detects the
          source and format, then normalizes every record into the unified OCSF schema.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Drag & drop */}
        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
          onClick={() => fileRef.current?.click()}
          className={`cursor-pointer rounded-xl border-2 border-dashed p-8 text-center transition-colors ${
            dragOver ? 'border-cyan-500 bg-cyan-950/20' : 'border-gray-600 bg-gray-800'
          }`}
        >
          <input ref={fileRef} type="file" className="hidden"
                 onChange={(e) => { const f = e.target.files?.[0]; if (f) { setFile(f); setText('') } }} />
          <p className="text-gray-300 text-sm">
            {file ? `📄 ${file.name} (${file.size} bytes)` : 'Drag & drop a log file here, or click to browse'}
          </p>
          <p className="text-gray-600 text-xs mt-1">.log .txt .json .csv — any text log</p>
        </div>

        {/* Paste */}
        <div className="flex flex-col gap-2">
          <textarea
            value={text}
            onChange={(e) => { setText(e.target.value); setFile(null) }}
            placeholder="…or paste raw log text (one record per line)"
            className="flex-1 min-h-[140px] bg-gray-800 border border-gray-700 rounded-xl p-3 text-xs text-gray-200 font-mono resize-y"
          />
        </div>
      </div>

      <div className="flex items-center gap-3">
        <button onClick={process} disabled={running}
                className="bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 text-white text-sm rounded px-5 py-2">
          {running ? 'Processing…' : 'Process'}
        </button>
        {(file || text) && !running && (
          <button onClick={() => { setFile(null); setText(''); setJob(null); setErr(null) }}
                  className="text-gray-400 text-xs hover:text-white">clear</button>
        )}
      </div>

      {err && <p className="text-red-400 text-sm">Error: {err}</p>}

      {/* Live progress */}
      {job && (
        <div className="bg-gray-800 rounded-xl p-4 border border-gray-700 space-y-2">
          <div className="flex justify-between text-xs text-gray-400">
            <span>{job.processed}/{job.total} · {job.current_stage}</span>
            <span>{job.percent}%</span>
          </div>
          <div className="w-full h-2 bg-gray-700 rounded overflow-hidden">
            <div className="h-full bg-cyan-500 transition-all" style={{ width: `${job.percent}%` }} />
          </div>
          {done && (
            <div className="flex flex-wrap gap-2 text-xs pt-1">
              {['ngre', 'drain3', 'dlq', 'error'].map(k => (
                <span key={k} className="px-2 py-0.5 rounded"
                      style={{ backgroundColor: (PATH_COLOR[k] || '#374151') + '33', color: PATH_COLOR[k] || '#9ca3af' }}>
                  {k}: <b>{counts[k] ?? 0}</b>
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Export toolbar */}
      {done && results.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap">
          <button onClick={copyJson}
                  className="bg-gray-700 hover:bg-gray-600 text-white text-xs rounded px-3 py-1.5">
            {copied ? '✓ Copied' : 'Copy JSON'}
          </button>
          <span className="text-gray-500 text-xs">Download all events as:</span>
          {['json', 'csv', 'parquet'].map(f => (
            <button key={f} onClick={() => download(f)}
                    className="bg-gray-700 hover:bg-gray-600 text-cyan-300 text-xs rounded px-3 py-1.5 uppercase">
              {f}
            </button>
          ))}
        </div>
      )}

      {/* Side-by-side per-line output: raw → normalized OCSF.
          Detection details (parser/confidence) are shown only as a subtle badge,
          not as a headline — the framework identifies the source automatically. */}
      {done && results.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-sm font-semibold text-gray-300">
            Normalized output — {results.length} record{results.length !== 1 ? 's' : ''}
          </h2>
          {results.map(r => (
            <div key={r.line_no} className="grid grid-cols-1 lg:grid-cols-2 gap-3 bg-gray-800 border border-gray-700 rounded-xl p-3">
              <div>
                <p className="text-[10px] uppercase tracking-widest text-gray-500 mb-1">Raw input (line {r.line_no})</p>
                <pre className="text-[11px] text-gray-300 whitespace-pre-wrap break-words max-h-48 overflow-y-auto">{r.raw}</pre>
              </div>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <p className="text-[10px] uppercase tracking-widest text-gray-500">Normalized (OCSF)</p>
                  {/* auto-detection + parse-status badge (PART 39) */}
                  <span className="text-[10px] text-gray-500" title={`detected via ${r.path}`}>
                    <span className="inline-block w-1.5 h-1.5 rounded-full mr-1 align-middle"
                          style={{ backgroundColor: PATH_COLOR[r.path] || '#06b6d4' }} />
                    {(r.normalized?.parse_status || 'parsed')}
                    {r.normalized?.ocsf_mapping_status === 'mapped'
                      ? ` · OCSF ${r.ocsf_class}`
                      : ' · OCSF not confidently mapped'}
                    {r.needs_review ? ' · review' : ''}
                  </span>
                </div>
                <pre className="text-[10px] text-emerald-300 whitespace-pre-wrap break-words max-h-48 overflow-y-auto">
{JSON.stringify(r.normalized, null, 2)}
                </pre>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
