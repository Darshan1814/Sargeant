import { useState } from 'react'
import axios from 'axios'

const FAMILIES = [
  { key: 'windows',  label: 'Windows',  icon: '🪟', blurb: 'Security 4625, Sysmon, DHCP, IIS…' },
  { key: 'macos',    label: 'macOS',    icon: '', blurb: 'socketfilterfw, unified log, crash IPS…' },
  { key: 'firewall', label: 'Firewall', icon: '🧱', blurb: 'Generic + W3C firewall logs' },
  { key: 'linux',    label: 'Linux',    icon: '🐧', blurb: 'syslog + auth (sshd/sudo)' },
]

const PATH_COLOR = { ngre: '#10b981', drain3: '#f59e0b', dlq: '#ef4444', error: '#ef4444' }

function FamilyCard({ fam }) {
  const [job, setJob] = useState(null)
  const [running, setRunning] = useState(false)
  const [showOut, setShowOut] = useState(false)
  const [err, setErr] = useState(null)

  async function run() {
    setErr(null); setJob(null); setShowOut(false); setRunning(true)
    try {
      // 1) pull pre-generated test logs for this family
      const td = await axios.get(`/api/testdata/${fam.key}?n=40`)
      // 2) POST to the EXISTING batch-ingest endpoint
      const { data } = await axios.post('/api/ingest/batch', {
        logs: td.data.logs, source_hint: fam.key,
      })
      const jobId = data.job_id
      // 3) poll real job status every 500ms
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

  const counts = job?.counts || {}
  const done = job?.status === 'completed'

  return (
    <div className="bg-gray-800 rounded-xl p-5 border border-gray-700 flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <span className="text-2xl">{fam.icon}</span>
        <div>
          <h3 className="text-white font-semibold">{fam.label}</h3>
          <p className="text-gray-500 text-[11px]">{fam.blurb}</p>
        </div>
      </div>

      <button
        onClick={run}
        disabled={running}
        className="bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 text-white text-sm rounded px-3 py-2 transition-colors"
      >
        {running ? 'Ingesting…' : 'Generate & Ingest Test Logs'}
      </button>

      {job && (
        <div className="space-y-2">
          <div className="flex justify-between text-[11px] text-gray-400">
            <span>{job.processed}/{job.total}</span>
            <span>{job.percent}%</span>
          </div>
          <div className="w-full h-2 bg-gray-700 rounded overflow-hidden">
            <div className="h-full bg-cyan-500 transition-all"
                 style={{ width: `${job.percent}%` }} />
          </div>
          <p className="text-[11px] text-gray-500 truncate" title={job.current_stage}>
            stage: <span className="text-gray-300">{job.current_stage}</span>
          </p>
        </div>
      )}

      {done && (
        <div className="border-t border-gray-700 pt-3 space-y-2">
          <p className="text-[11px] text-gray-400 uppercase tracking-widest">This run</p>
          <div className="flex flex-wrap gap-2 text-xs">
            {['ngre', 'drain3', 'dlq', 'error'].map(k => (
              <span key={k} className="px-2 py-0.5 rounded"
                    style={{ backgroundColor: (PATH_COLOR[k] || '#374151') + '33',
                             color: PATH_COLOR[k] || '#9ca3af' }}>
                {k}: <b>{counts[k] ?? 0}</b>
              </span>
            ))}
          </div>
          {job.results?.length > 0 && (
            <button onClick={() => setShowOut(v => !v)}
                    className="text-cyan-400 text-xs hover:underline">
              {showOut ? 'Hide' : 'View'} converted output ({job.results.length})
            </button>
          )}
          {showOut && (
            <div className="overflow-x-auto max-h-64 overflow-y-auto border border-gray-700 rounded">
              <table className="w-full text-[11px]">
                <thead className="sticky top-0 bg-gray-900">
                  <tr className="text-gray-500 text-left">
                    <th className="p-1.5">#</th>
                    <th className="p-1.5">Parser</th>
                    <th className="p-1.5">Path</th>
                    <th className="p-1.5">OCSF</th>
                    <th className="p-1.5">Message</th>
                  </tr>
                </thead>
                <tbody>
                  {job.results.map(r => (
                    <tr key={r.line_no} className="border-t border-gray-800">
                      <td className="p-1.5 text-gray-500">{r.line_no}</td>
                      <td className="p-1.5 text-cyan-400">{r.parser_id}</td>
                      <td className="p-1.5" style={{ color: PATH_COLOR[r.path] || '#9ca3af' }}>{r.path}</td>
                      <td className="p-1.5 text-gray-400">{r.ocsf_class}</td>
                      <td className="p-1.5 text-gray-300 truncate max-w-[220px]" title={r.message}>{r.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {err && <p className="text-red-400 text-xs">Error: {err}</p>}
    </div>
  )
}

export default function Fetch() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-white">Fetch &amp; Ingest Test Logs</h1>
        <p className="text-gray-500 text-sm mt-1">
          Each button pulls pre-generated well-formed logs for that family and pushes them through
          the real batch-ingest pipeline. Progress and per-run results are live from the job status.
        </p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {FAMILIES.map(f => <FamilyCard key={f.key} fam={f} />)}
      </div>
    </div>
  )
}
