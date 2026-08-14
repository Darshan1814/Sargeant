export default function OpsView() {
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-white">Ops Dashboard</h1>
      <p className="text-gray-400 text-sm">Live Prometheus metrics via Grafana (auto-provisioned, no setup required).</p>
      <div className="rounded-xl overflow-hidden border border-gray-700" style={{ height: '80vh' }}>
        <iframe
          src="http://localhost:3001/d/ulpf/ulpf-parse-operations?orgId=1&refresh=10s&kiosk"
          className="w-full h-full"
          title="Grafana ULPF Dashboard"
          frameBorder="0"
        />
      </div>
    </div>
  )
}
