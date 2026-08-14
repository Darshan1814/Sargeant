import { useState } from 'react'
import axios from 'axios'

function diffFields(a, b) {
  const allKeys = new Set([...Object.keys(a || {}), ...Object.keys(b || {})])
  const result = []
  for (const k of allKeys) {
    const va = a?.[k], vb = b?.[k]
    const status = va === undefined ? 'added' : vb === undefined ? 'removed' : va !== vb ? 'changed' : 'same'
    result.push({ key: k, va: JSON.stringify(va), vb: JSON.stringify(vb), status })
  }
  return result
}

function StatusBadge({ status }) {
  const cls = {
    added:   'bg-green-900/50 text-green-400',
    removed: 'bg-red-900/50 text-red-400',
    changed: 'bg-yellow-900/50 text-yellow-400',
    same:    'bg-gray-800 text-gray-500',
  }[status]
  return <span className={`px-1.5 py-0.5 rounded text-xs ${cls}`}>{status}</span>
}

export default function CompareView() {
  const [idA, setIdA] = useState('')
  const [idB, setIdB] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function compare() {
    if (!idA || !idB) return
    setLoading(true)
    setError('')
    try {
      const res = await axios.get(`/api/compare?event_a=${idA}&event_b=${idB}`)
      setResult(res.data)
    } catch (e) {
      setError('Compare failed: ' + (e.response?.data?.detail || e.message))
    }
    setLoading(false)
  }

  const diffs = result ? diffFields(result.event_a?.normalized, result.event_b?.normalized) : []

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-white">Compare Events</h1>

      <div className="flex gap-4 items-end">
        <div>
          <label className="text-xs text-gray-400 block mb-1">Event A — ID</label>
          <input className="bg-gray-800 text-gray-100 text-sm p-2 rounded border border-gray-600 focus:outline-none focus:border-cyan-500 w-72" value={idA} onChange={e => setIdA(e.target.value)} placeholder="event_id" />
        </div>
        <div>
          <label className="text-xs text-gray-400 block mb-1">Event B — ID</label>
          <input className="bg-gray-800 text-gray-100 text-sm p-2 rounded border border-gray-600 focus:outline-none focus:border-cyan-500 w-72" value={idB} onChange={e => setIdB(e.target.value)} placeholder="event_id" />
        </div>
        <button onClick={compare} disabled={loading || !idA || !idB} className="bg-cyan-700 hover:bg-cyan-600 px-4 py-2 rounded text-sm font-medium disabled:opacity-50">
          {loading ? 'Comparing…' : 'Compare'}
        </button>
      </div>

      {error && <div className="bg-red-900/50 text-red-300 px-4 py-2 rounded text-sm">{error}</div>}

      {result && (
        <>
          {/* Raw side-by-side */}
          <div className="grid grid-cols-2 gap-4">
            {[['A', result.event_a], ['B', result.event_b]].map(([label, ev]) => (
              <div key={label} className="bg-gray-800 rounded-xl p-4 border border-gray-700">
                <h2 className="text-xs font-semibold text-gray-400 mb-2">Event {label} — Raw Log</h2>
                <pre className="text-xs text-gray-300 bg-gray-900 p-3 rounded overflow-auto max-h-48 whitespace-pre-wrap">{ev?.raw_log}</pre>
              </div>
            ))}
          </div>

          {/* OCSF field-level diff */}
          <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
            <h2 className="text-sm font-semibold text-gray-300 mb-3">OCSF Field Diff</h2>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-gray-500 border-b border-gray-700">
                    <th className="text-left pb-2 w-40">Field</th>
                    <th className="text-left pb-2">Event A</th>
                    <th className="text-left pb-2">Event B</th>
                    <th className="text-left pb-2 w-20">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {diffs.map(d => (
                    <tr key={d.key} className={`border-b border-gray-700/40 ${d.status !== 'same' ? 'bg-gray-700/20' : ''}`}>
                      <td className="py-1.5 text-cyan-400 font-medium">{d.key}</td>
                      <td className="py-1.5 font-mono truncate max-w-xs">{d.va ?? '—'}</td>
                      <td className="py-1.5 font-mono truncate max-w-xs">{d.vb ?? '—'}</td>
                      <td className="py-1.5"><StatusBadge status={d.status} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
