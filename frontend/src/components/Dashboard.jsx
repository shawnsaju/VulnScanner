export default function Dashboard({ scanResult }) {
  if (!scanResult || !scanResult.summary) return null;

  const { summary, open_ports, target, scan_type, started_at, completed_at } = scanResult;

  const stats = [
    { key: 'critical', label: 'Critical', icon: '🔴', value: summary.critical || 0 },
    { key: 'high', label: 'High', icon: '🟠', value: summary.high || 0 },
    { key: 'medium', label: 'Medium', icon: '🟡', value: summary.medium || 0 },
    { key: 'low', label: 'Low', icon: '🔵', value: summary.low || 0 },
    { key: 'total', label: 'Total Vulns', icon: '🛡️', value: summary.total || 0 },
    { key: 'ports', label: 'Open Ports', icon: '🔌', value: open_ports?.length || 0 },
  ];

  const riskScore = calculateRiskScore(scanResult.vulnerabilities || []);
  const riskLabel = riskScore >= 8 ? 'CRITICAL' :
                    riskScore >= 6 ? 'HIGH' :
                    riskScore >= 4 ? 'MEDIUM' :
                    riskScore >= 2 ? 'LOW' : 'CLEAN';

  const riskColor = riskScore >= 8 ? 'var(--critical)' :
                    riskScore >= 6 ? 'var(--high)' :
                    riskScore >= 4 ? 'var(--medium)' :
                    riskScore >= 2 ? 'var(--low)' : 'var(--accent-green)';

  const duration = completed_at && started_at
    ? Math.round((new Date(completed_at) - new Date(started_at)) / 1000)
    : null;

  return (
    <div style={{ marginBottom: '2rem' }}>
      {/* Target info banner */}
      <div className="glass-card" style={{ padding: '1.25rem 1.5rem', marginBottom: '1.25rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.25rem' }}>
            Scan Target
          </div>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '1.1rem', color: 'var(--accent-cyan)', fontWeight: 600 }}>
            {target}
          </div>
        </div>
        <div style={{ display: 'flex', gap: '2rem', flexWrap: 'wrap' }}>
          {[
            { label: 'Scan Type', value: scan_type?.toUpperCase() },
            { label: 'Duration', value: duration ? `${duration}s` : 'N/A' },
            { label: 'Started', value: started_at ? new Date(started_at).toLocaleTimeString() : 'N/A' },
          ].map(item => (
            <div key={item.label}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{item.label}</div>
              <div style={{ fontSize: '0.9rem', color: 'var(--text-primary)', fontWeight: 600 }}>{item.value}</div>
            </div>
          ))}
          {/* Risk score */}
          <div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Risk Score</div>
            <div style={{ fontSize: '0.9rem', color: riskColor, fontWeight: 700 }}>
              {riskScore}/10 — {riskLabel}
            </div>
          </div>
        </div>
      </div>

      {/* Stats grid */}
      <div className="stats-grid">
        {stats.map((stat) => (
          <div key={stat.key} className={`glass-card stat-card ${stat.key}`}>
            <div className="stat-value">{stat.value}</div>
            <div className="stat-label">{stat.icon} {stat.label}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function calculateRiskScore(vulnerabilities) {
  if (!vulnerabilities?.length) return 0;
  const weights = { critical: 10, high: 7.5, medium: 4, low: 1.5, info: 0 };
  const total = vulnerabilities.reduce((sum, v) => sum + (weights[v.severity] || 0), 0);
  const max = vulnerabilities.length * 10;
  return Math.min(10, Math.round((total / max) * 100) / 10);
}
