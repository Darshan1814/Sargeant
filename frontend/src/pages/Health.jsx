import { useEffect, useState, useCallback } from 'react'
import axios from 'axios'

// Map a health check value to a dot color + display text.
function statusColor(val) {
  if (val == null) return '#6b7280'
  const s = String(val).toLowerCase()
  if (s === 'up' || s === 'green') return '#10b981'
  if (s === 'yellow') return '#f59e0b'
  if (s === 'red') return '#ef4444'
  if (s.startsWith('down') || s.startsWith('http') || s === 'unreachable') return '#ef4444'
  return '#f59e0b'
}

function Dot({ color }) {
  return <span className="inline-block w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
}

const SERVICES = [
  { key: 'duckdb',     label: 'DuckDB',      sub: 'source-of-truth store' },
  { key: 'opensearch', label: 'OpenSearch',  sub: 'cluster status (green/yellow/red)' },
  { key: 'prometheus', label: 'Prometheus',  sub: 'metrics scrape target' },
  { key: 'grafana',    label: 'Grafana',     sub: 'dashboards' },
]

function StatCard({ label, value, sub }) {
  return (
    <div className="bg-gray-800 rounded-xl p-4 flex flex-col gap-1 border border-gray-700">
      <span className="text-gray-400 text-[11px] uppercase tracking-widest">{label}</span>
      <span className="text-2xl font-bold text-cyan-400">{value ?? '—'}</span>
      {sub && <span className="text-gray-500 text-[11px]">{sub}</span>}
    </div>
  )
}

export default function Health() {
  const [health, setHealth] = useState(null)
  const [cov, setCov] = useState(null)
  const [loading, setLoading] = useState(false)
  const [ts, setTs] = useState(null)

  const recheck = useCallback(async () => {
    setLoading(true)
    try {
      const [h, c] = await Promise.allSettled([
        axios.get('/api/health'),
        axios.get('/api/coverage'),
      ])
      if (h.status === 'fulfilled') setHealth(h.value.data)
      if (c.status === 'fulfilled') setCov(c.value.data)
      setTs(new Date().toLocaleTimeString())
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { recheck() }, [recheck])

  const fam = cov?.by_family || {}

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">System Health</h1>
          {ts && <p className="text-gray-500 text-xs mt-1">Last checked {ts}</p>}
        </div>
        <button onClick={recheck} disabled={loading}
                className="bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 text-white text-sm rounded px-4 py-2">
          {loading ? 'Checking…' : 'Re-check all'}
        </button>
      </div>

      {/* Service dot grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {SERVICES.map(svc => {
          const val = health?.[svc.key]
          return (
            <div key={svc.key} className="bg-gray-800 rounded-xl p-4 border border-gray-700 flex items-center gap-3">
              <Dot color={statusColor(val)} />
              <div className="min-w-0">
                <div className="text-white text-sm font-semibold">{svc.label}</div>
                <div className="text-gray-400 text-xs truncate" title={val}>{val ?? '—'}</div>
                <div className="text-gray-600 text-[10px]">{svc.sub}</div>
              </div>
            </div>
          )
        })}
      </div>
      {health && (
        <p className="text-xs text-gray-500">
          Overall: <span style={{ color: statusColor(health.status === 'ok' ? 'up' : 'yellow') }}>
            {health.status}
          </span>
        </p>
      )}

      {/* Inline coverage totals */}
      <div>
        <h2 className="text-sm font-semibold text-gray-300 mb-3">Coverage &amp; Throughput</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="Total Events" value={cov?.total} />
          <StatCard label="NGRE" value={cov ? `${cov.pct_ngre}%` : '—'} sub={`${cov?.ngre ?? 0} events`} />
          <StatCard label="Drain3" value={cov ? `${cov.pct_drain3}%` : '—'} sub={`${cov?.drain3 ?? 0} fallbacks`} />
          <StatCard label="Failure (DLQ)" value={cov ? `${cov.pct_failure}%` : '—'} sub={`${cov?.failure ?? 0} events`} />
        </div>
      </div>

      {/* Per-family breakdown */}
      <div>
        <h2 className="text-sm font-semibold text-gray-300 mb-3">Per-Family NGRE</h2>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {['windows', 'macos', 'firewall', 'linux', 'other'].map(k => (
            <StatCard key={k} label={k}
                      value={fam[k]?.ngre ?? 0}
                      sub={fam[k]?.pct_ngre != null ? `${fam[k].pct_ngre}% NGRE` : ''} />
          ))}
        </div>
      </div>
    </div>
  )
}
