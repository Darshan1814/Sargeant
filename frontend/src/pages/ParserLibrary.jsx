import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'

export default function ParserLibrary() {
  const [parsers, setParsers] = useState([])
  const [loading, setLoading] = useState(false)
  const [testTarget, setTestTarget] = useState(null)
  const [testLog, setTestLog] = useState('')
  const [testResult, setTestResult] = useState(null)
  const navigate = useNavigate()

  async function load() {
    setLoading(true)
    try {
      const res = await axios.get('/api/parsers')
      setParsers(res.data)
    } catch {}
    setLoading(false)
  }

  useEffect(() => { load() }, [])

  async function deleteParser(id) {
    // No delete endpoint in spec — just reload (graceful no-op)
    alert('Delete not yet implemented in v1. Remove the JSON file from parsers/registry manually.')
  }

  async function runTest(id) {
    if (!testLog.trim()) return
    try {
      const res = await axios.post(`/api/parsers/${id}/test`, { sample_log: testLog })
      setTestResult({ id, ...res.data })
    } catch (e) {
      setTestResult({ id, matched: false, fields: {}, error: e.message })
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Parser Library</h1>
        <button onClick={() => navigate('/parsers/new')} className="bg-cyan-700 hover:bg-cyan-600 px-4 py-2 rounded text-sm font-medium">
          + New Parser
        </button>
      </div>

      <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-gray-500 border-b border-gray-700 bg-gray-900">
              <th className="text-left px-4 py-2">ID</th>
              <th className="text-left px-4 py-2">Source</th>
              <th className="text-left px-4 py-2">OS / Family</th>
              <th className="text-left px-4 py-2">Category</th>
              <th className="text-left px-4 py-2">OCSF Class</th>
              <th className="text-left px-4 py-2">Version</th>
              <th className="text-left px-4 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {parsers.map(p => (
              <>
                <tr key={p.parser_id} className="border-b border-gray-700/50 hover:bg-gray-700/20">
                  <td className="px-4 py-2 text-cyan-400 font-medium">{p.parser_id}</td>
                  <td className="px-4 py-2">{p.source_name}</td>
                  <td className="px-4 py-2">{p.os_family}</td>
                  <td className="px-4 py-2">{p.category}</td>
                  <td className="px-4 py-2">{p.ocsf_class_uid}</td>
                  <td className="px-4 py-2">{p.version}</td>
                  <td className="px-4 py-2 flex gap-2">
                    <button
                      onClick={() => setTestTarget(testTarget === p.parser_id ? null : p.parser_id)}
                      className="bg-gray-700 hover:bg-gray-600 px-2 py-1 rounded"
                    >Test</button>
                    <button onClick={() => deleteParser(p.parser_id)} className="bg-red-900/60 hover:bg-red-800 px-2 py-1 rounded">Del</button>
                  </td>
                </tr>
                {testTarget === p.parser_id && (
                  <tr key={`${p.parser_id}-test`} className="bg-gray-900">
                    <td colSpan={7} className="px-4 py-3 space-y-2">
                      <textarea
                        className="w-full h-24 bg-gray-800 text-gray-100 text-xs p-2 rounded border border-gray-600 focus:outline-none focus:border-cyan-500 font-mono"
                        placeholder="Paste a sample log to test this parser…"
                        value={testLog}
                        onChange={e => setTestLog(e.target.value)}
                      />
                      <button onClick={() => runTest(p.parser_id)} className="bg-cyan-700 hover:bg-cyan-600 px-3 py-1 rounded text-xs">Run Test</button>
                      {testResult?.id === p.parser_id && (
                        <div className={`mt-2 p-2 rounded border ${testResult.matched ? 'border-green-700 text-green-300' : 'border-red-700 text-red-300'}`}>
                          <p className="text-xs font-semibold mb-1">{testResult.matched ? '✓ Matched' : '✗ No match'}</p>
                          <pre className="text-xs text-gray-300 overflow-auto">{JSON.stringify(testResult.fields, null, 2)}</pre>
                        </div>
                      )}
                    </td>
                  </tr>
                )}
              </>
            ))}
            {parsers.length === 0 && !loading && (
              <tr><td colSpan={7} className="px-4 py-6 text-center text-gray-500">No parsers registered.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
