import { useEffect, useState } from 'react'
import axios from 'axios'
import {
  PieChart, Pie, Cell, Tooltip, Legend,
  BarChart, Bar, XAxis, YAxis, ResponsiveContainer,
  LineChart, Line, CartesianGrid,
} from 'recharts'

const COLORS = ['#06b6d4', '#8b5cf6', '#10b981', '#f59e0b', '#ef4444', '#3b82f6']

function StatCard({ label, value, sub }) {
  return (
    <div className="bg-gray-800 rounded-xl p-5 flex flex-col gap-1 border border-gray-700">
      <span className="text-gray-400 text-xs uppercase tracking-widest">{label}</span>
      <span className="text-3xl font-bold text-cyan-400">{value ?? '—'}</span>
      {sub && <span className="text-gray-500 text-xs">{sub}</span>}
    </div>
  )
}

// Honest parse-path coverage: what fraction was structurally parsed by a real
// NGRE parser vs. fell back to Drain3 vs. last-resort DLQ. No "100%" claims —
// these are measured from what actually flowed through the pipeline.
function CoveragePanel({ cov }) {
  if (!cov || !cov.total) {
    return (
      <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
        <h2 className="text-sm font-semibold text-gray-300 mb-2">Parse Coverage</h2>
        <p className="text-gray-500 text-xs">No events yet — ingest logs to measure coverage.</p>
      </div>
    )
  }
  const segments = [
    { key: 'ngre_windows', label: 'Windows NGRE', color: '#3b82f6', n: cov.ngre_windows, pct: cov.pct_ngre_windows },
    { key: 'ngre_macos',   label: 'macOS NGRE',   color: '#8b5cf6', n: cov.ngre_macos,   pct: cov.pct_ngre_macos },
    { key: 'ngre_other',   label: 'Other NGRE',   color: '#10b981', n: cov.ngre_other,   pct: cov.total ? +(100*cov.ngre_other/cov.total).toFixed(1) : 0 },
    { key: 'drain3',       label: 'Drain3 fallback', color: '#f59e0b', n: cov.drain3, pct: cov.pct_drain3 },
    { key: 'dlq',          label: 'DLQ (unparsed)',  color: '#ef4444', n: cov.dlq,    pct: cov.pct_dlq },
  ].filter(s => s.n > 0)

  return (
    <div className="bg-gray-800 rounded-xl p-5 border border-gray-700 md:col-span-2">
      <div className="flex items-baseline justify-between mb-3">
        <h2 className="text-sm font-semibold text-gray-300">Parse Coverage (measured)</h2>
        <span className="text-xs text-gray-500">
          {cov.pct_ngre}% via NGRE · {cov.pct_drain3}% Drain3 · {cov.pct_dlq}% DLQ · n={cov.total}
        </span>
      </div>
      {/* stacked proportion bar */}
      <div className="flex w-full h-5 rounded-lg overflow-hidden border border-gray-700">
        {segments.map(s => (
          <div key={s.key} style={{ width: `${s.pct}%`, backgroundColor: s.color }}
               title={`${s.label}: ${s.n} (${s.pct}%)`} />
        ))}
      </div>
      {/* legend + per-bucket counts */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3 mt-4">
        {segments.map(s => (
          <div key={s.key} className="flex flex-col gap-0.5">
            <div className="flex items-center gap-1.5">
              <span className="inline-block w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: s.color }} />
              <span className="text-gray-400 text-[11px]">{s.label}</span>
            </div>
            <span className="text-white text-sm font-semibold">{s.pct}%</span>
            <span className="text-gray-500 text-[11px]">{s.n} events</span>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function Overview() {
  const [stats, setStats] = useState(null)
  const [recent, setRecent] = useState([])

  useEffect(() => {
    axios.get('/api/stats').then(r => setStats(r.data)).catch(() => {})
    axios.get('/api/events?limit=10').then(r => setRecent(r.data)).catch(() => {})
    const id = setInterval(() => {
      axios.get('/api/stats').then(r => setStats(r.data)).catch(() => {})
      axios.get('/api/events?limit=10').then(r => setRecent(r.data)).catch(() => {})
    }, 10000)
    return () => clearInterval(id)
  }, [])

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-white">Overview</h1>

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Events" value={stats?.total_events} />
        <StatCard label="Needs Review" value={stats?.needs_review} sub="Drain3 fallbacks" />
        <StatCard label="Parsers" value={stats?.by_parser?.length} />
        <StatCard label="OCSF Classes" value={stats?.by_ocsf_class?.length} />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Honest parse-path coverage */}
        <CoveragePanel cov={stats?.coverage} />

        {/* By parser donut */}
        <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Events by Parser</h2>
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie data={stats?.by_parser ?? []} dataKey="count" nameKey="parser_id" cx="50%" cy="50%" outerRadius={90} label>
                {(stats?.by_parser ?? []).map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* NGRE vs Drain3 */}
        <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">OCSF Class Breakdown</h2>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={stats?.by_ocsf_class ?? []}>
              <XAxis dataKey="class_uid" stroke="#6b7280" />
              <YAxis stroke="#6b7280" />
              <Tooltip />
              <Bar dataKey="count" fill="#06b6d4" radius={[4,4,0,0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Events over time */}
        <div className="bg-gray-800 rounded-xl p-5 border border-gray-700 md:col-span-2">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Events Over Time (14 days)</h2>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={[...(stats?.by_day ?? [])].reverse()}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="day" stroke="#6b7280" tick={{ fontSize: 11 }} />
              <YAxis stroke="#6b7280" />
              <Tooltip />
              <Line type="monotone" dataKey="count" stroke="#06b6d4" dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Last 10 events ticker */}
      <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
        <h2 className="text-sm font-semibold text-gray-300 mb-3">Last 10 Events</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-gray-500 border-b border-gray-700">
                <th className="text-left pb-2">Event ID</th>
                <th className="text-left pb-2">Source</th>
                <th className="text-left pb-2">Parser</th>
                <th className="text-left pb-2">Confidence</th>
                <th className="text-left pb-2">OCSF Class</th>
                <th className="text-left pb-2">Ingested</th>
              </tr>
            </thead>
            <tbody>
              {recent.map(e => (
                <tr key={e.event_id} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                  <td className="py-1.5 text-cyan-400 truncate max-w-[120px]">{e.event_id?.slice(0, 8)}…</td>
                  <td className="py-1.5">{e.source}</td>
                  <td className="py-1.5">{e.parser_id}</td>
                  <td className="py-1.5">{e.confidence != null ? (e.confidence * 100).toFixed(0) + '%' : '—'}</td>
                  <td className="py-1.5">{e.ocsf_class}</td>
                  <td className="py-1.5 text-gray-400">{e.ingested_at?.slice(0, 19)}</td>
                </tr>
              ))}
              {recent.length === 0 && (
                <tr><td colSpan={6} className="py-4 text-center text-gray-500">No events yet — ingest some logs.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
