import { useEffect, useState } from 'react'
import axios from 'axios'

export default function LogBrowser() {
  const [events, setEvents] = useState([])
  const [search, setSearch] = useState('')
  const [source, setSource] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [expanded, setExpanded] = useState(null)
  const [expandedData, setExpandedData] = useState(null)
  const [loading, setLoading] = useState(false)

  async function load() {
    setLoading(true)
    try {
      const params = new URLSearchParams({ limit: 50 })
      if (search) params.set('q', search)
      if (source) params.set('source', source)
      if (dateFrom) params.set('date_from', dateFrom)
      if (dateTo) params.set('date_to', dateTo)
      const res = await axios.get(`/api/events?${params}`)
      setEvents(res.data)
    } catch {}
    setLoading(false)
  }

  useEffect(() => { load() }, [])

  async function expand(event_id) {
    if (expanded === event_id) { setExpanded(null); return }
    setExpanded(event_id)
    try {
      const res = await axios.get(`/api/events/${event_id}`)
      setExpandedData(res.data)
    } catch { setExpandedData(null) }
  }

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-white">Log Browser</h1>

      {/* Filters */}
      <div className="bg-gray-800 rounded-xl p-4 border border-gray-700 flex flex-wrap gap-3 items-end">
        <div>
          <label className="text-xs text-gray-400 block mb-1">Free-text search</label>
          <input className="bg-gray-900 text-gray-100 text-sm p-2 rounded border border-gray-600 focus:outline-none focus:border-cyan-500 w-64" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search messages…" />
        </div>
        <div>
          <label className="text-xs text-gray-400 block mb-1">Source</label>
          <input className="bg-gray-900 text-gray-100 text-sm p-2 rounded border border-gray-600 focus:outline-none focus:border-cyan-500 w-48" value={source} onChange={e => setSource(e.target.value)} placeholder="Filter by source" />
        </div>
        <div>
          <label className="text-xs text-gray-400 block mb-1">From</label>
          <input type="date" className="bg-gray-900 text-gray-100 text-sm p-2 rounded border border-gray-600 focus:outline-none focus:border-cyan-500" value={dateFrom} onChange={e => setDateFrom(e.target.value)} />
        </div>
        <div>
          <label className="text-xs text-gray-400 block mb-1">To</label>
          <input type="date" className="bg-gray-900 text-gray-100 text-sm p-2 rounded border border-gray-600 focus:outline-none focus:border-cyan-500" value={dateTo} onChange={e => setDateTo(e.target.value)} />
        </div>
        <button onClick={load} disabled={loading} className="bg-cyan-700 hover:bg-cyan-600 px-4 py-2 rounded text-sm font-medium disabled:opacity-50">
          {loading ? 'Loading…' : 'Search'}
        </button>
      </div>

      {/* Table */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-gray-500 border-b border-gray-700 bg-gray-900">
              <th className="text-left px-4 py-2">Timestamp</th>
              <th className="text-left px-4 py-2">Source</th>
              <th className="text-left px-4 py-2">Parser</th>
              <th className="text-left px-4 py-2">Confidence</th>
              <th className="text-left px-4 py-2">OCSF Class</th>
              <th className="text-left px-4 py-2">Review?</th>
            </tr>
          </thead>
          <tbody>
            {events.map(e => (
              <>
                <tr
                  key={e.event_id}
                  onClick={() => expand(e.event_id)}
                  className="border-b border-gray-700/50 hover:bg-gray-700/30 cursor-pointer"
                >
                  <td className="px-4 py-2 text-gray-400">{e.ingested_at?.slice(0, 19)}</td>
                  <td className="px-4 py-2">{e.source}</td>
                  <td className="px-4 py-2 text-cyan-400">{e.parser_id}</td>
                  <td className="px-4 py-2">{e.confidence != null ? (e.confidence * 100).toFixed(0) + '%' : '—'}</td>
                  <td className="px-4 py-2">{e.ocsf_class}</td>
                  <td className="px-4 py-2">{e.needs_review ? <span className="text-yellow-400">⚠ Yes</span> : '—'}</td>
                </tr>
                {expanded === e.event_id && expandedData && (
                  <tr key={`${e.event_id}-expanded`} className="bg-gray-900">
                    <td colSpan={6} className="px-4 py-4">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <p className="text-gray-400 text-xs mb-1 font-semibold">Raw Log</p>
                          <pre className="bg-gray-800 p-3 rounded text-xs text-gray-300 overflow-auto max-h-64 whitespace-pre-wrap">{expandedData.raw_log}</pre>
                        </div>
                        <div>
                          <p className="text-gray-400 text-xs mb-1 font-semibold">Normalized OCSF</p>
                          <pre className="bg-gray-800 p-3 rounded text-xs text-green-300 overflow-auto max-h-64">{JSON.stringify(expandedData.normalized, null, 2)}</pre>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
            {events.length === 0 && !loading && (
              <tr><td colSpan={6} className="px-4 py-6 text-center text-gray-500">No events found.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
