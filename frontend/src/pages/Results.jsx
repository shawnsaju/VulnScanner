import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import Dashboard from '../components/Dashboard';
import VulnerabilityCard from '../components/VulnerabilityCard';
import SeverityChart from '../components/SeverityChart';
import ReportDownload from '../components/ReportDownload';
import ScanProgress from '../components/ScanProgress';
import { getScanStatus } from '../api/scanner';

const FILTERS = ['all', 'critical', 'high', 'medium', 'low', 'info'];

export default function Results() {
  const { scanId } = useParams();
  const navigate = useNavigate();

  const [scanResult, setScanResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [activeFilter, setActiveFilter] = useState('all');
  const [activeTab, setActiveTab] = useState('vulnerabilities');

  useEffect(() => {
    if (!scanId) return;
    fetchScan();
  }, [scanId]);

  // Poll if still running
  useEffect(() => {
    if (!scanResult) return;
    if (scanResult.status === 'completed' || scanResult.status === 'failed') return;

    const interval = setInterval(fetchScan, 1500);
    return () => clearInterval(interval);
  }, [scanResult?.status]);

  const fetchScan = async () => {
    try {
      const data = await getScanStatus(scanId);
      setScanResult(data);
      setLoading(false);
    } catch (e) {
      setError(e.response?.data?.detail || 'Failed to load scan results');
      setLoading(false);
    }
  };

  const filteredVulns = scanResult?.vulnerabilities?.filter(
    (v) => activeFilter === 'all' || v.severity === activeFilter
  ) || [];

  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '60vh', gap: '1rem' }}>
        <div className="spinner" style={{ width: 40, height: 40, borderWidth: 3 }} />
        <div style={{ color: 'var(--text-secondary)' }}>Loading scan results...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container" style={{ padding: '4rem 1.5rem', textAlign: 'center' }}>
        <div className="empty-state">
          <div className="empty-state-icon">❌</div>
          <div className="empty-state-title">{error}</div>
          <button
            onClick={() => navigate('/')}
            className="scan-btn"
            style={{ margin: '1rem auto', display: 'inline-flex' }}
          >
            ← Back to Home
          </button>
        </div>
      </div>
    );
  }

  if (!scanResult) return null;

  const isRunning = scanResult.status === 'running' || scanResult.status === 'pending';

  return (
    <div className="container" style={{ padding: '2rem 1.5rem 4rem' }}>
      {/* Back button */}
      <button
        onClick={() => navigate('/')}
        style={{
          background: 'none',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-sm)',
          color: 'var(--text-secondary)',
          padding: '0.5rem 1rem',
          cursor: 'pointer',
          fontSize: '0.85rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.4rem',
          marginBottom: '1.5rem',
          transition: 'all 0.2s',
        }}
        onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'var(--accent-blue)'; e.currentTarget.style.color = 'var(--text-primary)'; }}
        onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-secondary)'; }}
      >
        ← New Scan
      </button>

      {/* Show progress if still running */}
      {isRunning && <ScanProgress scanResult={scanResult} />}

      {/* Results */}
      {scanResult.status === 'completed' && (
        <>
          {/* Dashboard stats */}
          <Dashboard scanResult={scanResult} />

          {/* PDF Download */}
          <ReportDownload
            scanId={scanId}
            target={scanResult.target}
            summary={scanResult.summary}
          />

          {/* Charts */}
          <SeverityChart
            summary={scanResult.summary}
            vulnerabilities={scanResult.vulnerabilities}
          />

          {/* Tab Navigation */}
          <div className="tab-nav">
            {[
              { id: 'vulnerabilities', label: `🛡️ Vulnerabilities (${scanResult.vulnerabilities?.length || 0})` },
              { id: 'ports', label: `🔌 Open Ports (${scanResult.open_ports?.length || 0})` },
              { id: 'ssl', label: '🔒 SSL/TLS' },
              { id: 'dns', label: '🌐 DNS & WHOIS' },
            ].map((tab) => (
              <button
                key={tab.id}
                className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
                onClick={() => setActiveTab(tab.id)}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Vulnerabilities Tab */}
          {activeTab === 'vulnerabilities' && (
            <div>
              <div className="section-header">
                <div className="section-title">
                  🛡️ Vulnerability Findings
                </div>
                <div className="filter-pills">
                  {FILTERS.map((f) => {
                    const count = f === 'all'
                      ? scanResult.vulnerabilities?.length || 0
                      : scanResult.vulnerabilities?.filter(v => v.severity === f).length || 0;
                    return (
                      <button
                        key={f}
                        className={`filter-pill ${activeFilter === f ? 'active' : ''}`}
                        onClick={() => setActiveFilter(f)}
                      >
                        {f === 'all' ? 'All' : f.charAt(0).toUpperCase() + f.slice(1)} ({count})
                      </button>
                    );
                  })}
                </div>
              </div>

              {filteredVulns.length > 0 ? (
                filteredVulns.map((v) => (
                  <VulnerabilityCard key={v.id} vuln={v} />
                ))
              ) : (
                <div className="empty-state glass-card" style={{ padding: '3rem' }}>
                  <div className="empty-state-icon">🎉</div>
                  <div className="empty-state-title">No vulnerabilities in this category</div>
                </div>
              )}
            </div>
          )}

          {/* Ports Tab */}
          {activeTab === 'ports' && (
            <div className="glass-card" style={{ padding: '1.5rem' }}>
              <div className="section-title" style={{ marginBottom: '1rem' }}>🔌 Open Ports</div>
              {scanResult.open_ports?.length > 0 ? (
                <table className="port-table">
                  <thead>
                    <tr>
                      <th>Port</th>
                      <th>Service</th>
                      <th>State</th>
                      <th>Risk</th>
                      <th>Banner / Version</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResult.open_ports.map((p, i) => (
                      <tr key={i}>
                        <td className="port-num">{p.port}</td>
                        <td>{p.service}</td>
                        <td>
                          <span style={{ color: 'var(--accent-green)', fontWeight: 600, fontSize: '0.8rem' }}>
                            ● {p.state}
                          </span>
                        </td>
                        <td>
                          <span className={`severity-badge ${p.risk}`}>
                            {(p.risk || 'info').toUpperCase()}
                          </span>
                        </td>
                        <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                          {p.version ? p.version.slice(0, 60) : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="empty-state">
                  <div className="empty-state-icon">🔒</div>
                  <div className="empty-state-title">No open ports detected</div>
                </div>
              )}
            </div>
          )}

          {/* SSL Tab */}
          {activeTab === 'ssl' && (
            <div className="glass-card" style={{ padding: '1.5rem' }}>
              <div className="section-title" style={{ marginBottom: '1rem' }}>🔒 SSL/TLS Certificate</div>
              {scanResult.ssl_info ? (
                <div className="ssl-grid">
                  {[
                    { key: 'Status', val: scanResult.ssl_info.valid ? '✅ Valid' : '❌ Invalid' },
                    { key: 'Grade', val: scanResult.ssl_info.grade || 'N/A', isGrade: true },
                    { key: 'Protocol', val: scanResult.ssl_info.protocol || 'N/A' },
                    { key: 'Issuer', val: scanResult.ssl_info.issuer || 'Unknown' },
                    { key: 'Subject', val: scanResult.ssl_info.subject || 'N/A' },
                    { key: 'Expiry Date', val: scanResult.ssl_info.expiry_date || 'N/A' },
                    { key: 'Days Remaining', val: scanResult.ssl_info.days_remaining != null ? `${scanResult.ssl_info.days_remaining} days` : 'N/A' },
                  ].map(({ key, val, isGrade }) => (
                    <div key={key} className="ssl-item">
                      <div className="ssl-key">{key}</div>
                      <div className={`ssl-val ${isGrade ? `ssl-grade ${(val || '').toLowerCase()}` : ''}`}>
                        {val}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state">
                  <div className="empty-state-icon">⚠️</div>
                  <div className="empty-state-title">No SSL information available</div>
                  <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
                    Target may not support HTTPS or port 443 is not open
                  </div>
                </div>
              )}
            </div>
          )}

          {/* DNS & WHOIS Tab */}
          {activeTab === 'dns' && (
            <div style={{ display: 'grid', gap: '1rem', gridTemplateColumns: '1fr 1fr' }}>
              {/* DNS */}
              <div className="glass-card" style={{ padding: '1.5rem' }}>
                <div className="section-title" style={{ marginBottom: '1rem' }}>🌐 DNS Records</div>
                {scanResult.dns_info ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {[
                      { label: 'A Records', data: scanResult.dns_info.a_records },
                      { label: 'MX Records', data: scanResult.dns_info.mx_records },
                      { label: 'NS Records', data: scanResult.dns_info.ns_records },
                      { label: 'TXT Records', data: scanResult.dns_info.txt_records },
                      { label: 'CNAME Records', data: scanResult.dns_info.cname_records },
                    ].filter(r => r.data?.length > 0).map(({ label, data }) => (
                      <div key={label} style={{ background: 'rgba(255,255,255,0.02)', borderRadius: '6px', padding: '0.75rem' }}>
                        <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.4rem' }}>
                          {label}
                        </div>
                        {data.map((r, i) => (
                          <div key={i} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.8rem', color: 'var(--accent-cyan)', marginBottom: '2px', wordBreak: 'break-all' }}>
                            {r}
                          </div>
                        ))}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="empty-state"><div className="empty-state-icon">📭</div><div>No DNS data</div></div>
                )}
              </div>

              {/* WHOIS */}
              <div className="glass-card" style={{ padding: '1.5rem' }}>
                <div className="section-title" style={{ marginBottom: '1rem' }}>📋 WHOIS Data</div>
                {scanResult.whois_data && Object.keys(scanResult.whois_data).length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    {Object.entries(scanResult.whois_data)
                      .filter(([, v]) => v && v !== 'Unknown' && v !== 'None')
                      .map(([k, v]) => (
                        <div key={k} style={{ background: 'rgba(255,255,255,0.02)', borderRadius: '6px', padding: '0.65rem 0.9rem' }}>
                          <div style={{ fontSize: '0.68rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.2rem' }}>
                            {k.replace(/_/g, ' ')}
                          </div>
                          <div style={{ fontSize: '0.82rem', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                            {Array.isArray(v) ? v.join(', ') : String(v)}
                          </div>
                        </div>
                      ))}
                  </div>
                ) : (
                  <div className="empty-state"><div className="empty-state-icon">📭</div><div>No WHOIS data</div></div>
                )}
              </div>
            </div>
          )}
        </>
      )}

      {scanResult.status === 'failed' && (
        <div className="error-banner glass-card" style={{ padding: '2rem', textAlign: 'center', flexDirection: 'column', alignItems: 'center' }}>
          <div style={{ fontSize: '2rem', marginBottom: '0.75rem' }}>❌</div>
          <div style={{ fontWeight: 700, marginBottom: '0.5rem' }}>Scan Failed</div>
          <div style={{ fontSize: '0.85rem' }}>{scanResult.error || 'An unexpected error occurred'}</div>
          <button onClick={() => navigate('/')} className="scan-btn" style={{ marginTop: '1rem' }}>
            ← Try Again
          </button>
        </div>
      )}
    </div>
  );
}
