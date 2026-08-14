import { useState } from 'react'
import axios from 'axios'

const OCSF_CLASSES = [
  { uid: 1001, name: 'System Activity' },
  { uid: 3002, name: 'Authentication' },
  { uid: 4001, name: 'Network Activity' },
  { uid: 6003, name: 'API Activity' },
]

const OCSF_FIELDS = [
  'actor.process.name', 'actor.process.pid', 'actor.user.name', 'actor.user.uid',
  'device.hostname', 'device.ip', 'message', 'severity', 'category_name',
  'activity_id', 'src_endpoint.ip', 'dst_endpoint.ip', 'connection_info.protocol_name',
]

export default function CreateParser() {
  const [sampleLog, setSampleLog] = useState('')
  const [template, setTemplate] = useState(null)
  const [ngrePattern, setNgrePattern] = useState('')
  const [parserId, setParserId] = useState('')
  const [sourceName, setSourceName] = useState('')
  const [osFamily, setOsFamily] = useState('')
  const [ocsfClass, setOcsfClass] = useState(1001)
  const [testResult, setTestResult] = useState(null)
  const [savedParser, setSavedParser] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function detectTemplate() {
    if (!sampleLog.trim()) return
    setLoading(true)
    setError('')
    try {
      const res = await axios.post('/api/ingest', new URLSearchParams({ raw_log: sampleLog }))
      const norm = res.data?.normalized
      setTemplate(norm?.drain3_template || norm?.message || 'Template extracted')
      if (res.data?.path === 'ngre') {
        setTemplate(`[Auto-detected parser: ${res.data.parser_id}] — edit pattern below if needed`)
      }
    } catch (e) {
      setError('Detection failed: ' + (e.response?.data?.detail || e.message))
    }
    setLoading(false)
  }

  async function testParser() {
    if (!parserId || !ngrePattern || !sampleLog) return
    setLoading(true)
    setError('')
    try {
      // Create a temp parser, test it, then delete
      await axios.post('/api/parsers', {
        parser_id: parserId, source_name: sourceName, os_family: osFamily,
        ocsf_class_uid: Number(ocsfClass), ngre_pattern: ngrePattern, field_mapping: {},
        identifiers: { required_substrings: [], regex_signature: '' },
      })
      const res = await axios.post(`/api/parsers/${parserId}/test`, { sample_log: sampleLog })
      setTestResult(res.data)
    } catch (e) {
      setError('Test failed: ' + (e.response?.data?.detail || e.message))
    }
    setLoading(false)
  }

  async function saveParser() {
    setLoading(true)
    setError('')
    try {
      const res = await axios.post('/api/parsers', {
        parser_id: parserId, source_name: sourceName, os_family: osFamily,
        ocsf_class_uid: Number(ocsfClass), ngre_pattern: ngrePattern, field_mapping: {},
        identifiers: { required_substrings: [], regex_signature: ngrePattern.slice(0, 60) },
        version: '1.0',
      })
      setSavedParser(res.data)
    } catch (e) {
      setError('Save failed: ' + (e.response?.data?.detail || e.message))
    }
    setLoading(false)
  }

  return (
    <div className="max-w-3xl space-y-6">
      <h1 className="text-xl font-bold text-white">Create Parser</h1>

      {error && <div className="bg-red-900/50 text-red-300 px-4 py-2 rounded text-sm">{error}</div>}
      {savedParser && <div className="bg-green-900/50 text-green-300 px-4 py-2 rounded text-sm">Parser "{savedParser.parser_id}" saved successfully.</div>}

      <div className="bg-gray-800 rounded-xl p-5 border border-gray-700 space-y-4">
        <h2 className="text-sm font-semibold text-gray-300">1. Paste Sample Log</h2>
        <textarea
          className="w-full h-40 bg-gray-900 text-gray-100 text-xs p-3 rounded border border-gray-600 focus:outline-none focus:border-cyan-500 font-mono"
          placeholder="Paste a raw log sample here…"
          value={sampleLog}
          onChange={e => setSampleLog(e.target.value)}
        />
        <button
          onClick={detectTemplate}
          disabled={loading}
          className="bg-cyan-700 hover:bg-cyan-600 px-4 py-2 rounded text-sm font-medium disabled:opacity-50"
        >
          {loading ? 'Detecting…' : 'Auto-detect Template'}
        </button>
        {template && (
          <div className="bg-gray-900 border border-gray-600 rounded p-3 text-xs text-yellow-300 whitespace-pre-wrap">{template}</div>
        )}
      </div>

      <div className="bg-gray-800 rounded-xl p-5 border border-gray-700 space-y-4">
        <h2 className="text-sm font-semibold text-gray-300">2. Parser Configuration</h2>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-gray-400 block mb-1">Parser ID</label>
            <input className="w-full bg-gray-900 text-gray-100 text-sm p-2 rounded border border-gray-600 focus:outline-none focus:border-cyan-500" value={parserId} onChange={e => setParserId(e.target.value)} placeholder="e.g. CISCO-ASA-001" />
          </div>
          <div>
            <label className="text-xs text-gray-400 block mb-1">Source Name</label>
            <input className="w-full bg-gray-900 text-gray-100 text-sm p-2 rounded border border-gray-600 focus:outline-none focus:border-cyan-500" value={sourceName} onChange={e => setSourceName(e.target.value)} placeholder="e.g. Cisco ASA Firewall" />
          </div>
          <div>
            <label className="text-xs text-gray-400 block mb-1">OS / Vendor Family</label>
            <input className="w-full bg-gray-900 text-gray-100 text-sm p-2 rounded border border-gray-600 focus:outline-none focus:border-cyan-500" value={osFamily} onChange={e => setOsFamily(e.target.value)} placeholder="e.g. Cisco" />
          </div>
          <div>
            <label className="text-xs text-gray-400 block mb-1">OCSF Class</label>
            <select className="w-full bg-gray-900 text-gray-100 text-sm p-2 rounded border border-gray-600 focus:outline-none focus:border-cyan-500" value={ocsfClass} onChange={e => setOcsfClass(e.target.value)}>
              {OCSF_CLASSES.map(c => <option key={c.uid} value={c.uid}>{c.uid} — {c.name}</option>)}
            </select>
          </div>
        </div>
        <div>
          <label className="text-xs text-gray-400 block mb-1">NGRE Pattern (named-group regex)</label>
          <textarea
            className="w-full h-24 bg-gray-900 text-gray-100 text-xs p-3 rounded border border-gray-600 focus:outline-none focus:border-cyan-500 font-mono"
            placeholder="^(?P<month>\w{3})\s+(?P<day>\d+)…"
            value={ngrePattern}
            onChange={e => setNgrePattern(e.target.value)}
          />
        </div>
      </div>

      <div className="flex gap-3">
        <button onClick={testParser} disabled={loading} className="bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded text-sm font-medium disabled:opacity-50">
          Test Parser
        </button>
        <button onClick={saveParser} disabled={loading || !parserId} className="bg-cyan-700 hover:bg-cyan-600 px-4 py-2 rounded text-sm font-medium disabled:opacity-50">
          Save Parser
        </button>
      </div>

      {testResult && (
        <div className={`bg-gray-800 border rounded-xl p-5 ${testResult.matched ? 'border-green-600' : 'border-red-600'}`}>
          <p className={`text-sm font-semibold mb-2 ${testResult.matched ? 'text-green-400' : 'text-red-400'}`}>
            {testResult.matched ? '✓ Match' : '✗ No Match'}
          </p>
          <pre className="text-xs text-gray-300 bg-gray-900 p-3 rounded overflow-auto">{JSON.stringify(testResult.fields, null, 2)}</pre>
        </div>
      )}
    </div>
  )
}
