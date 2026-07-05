import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import ScanForm from '../components/ScanForm';
import ScanProgress from '../components/ScanProgress';
import { startScan, getScanStatus, listScans, deleteScan } from '../api/scanner';

export default function Home() {
  const navigate = useNavigate();
  const [isScanning, setIsScanning] = useState(false);
  const [activeScan, setActiveScan] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [error, setError] = useState('');

  // Load scan history on mount
  useEffect(() => {
    loadHistory();
  }, []);

  // Poll active scan
  useEffect(() => {
    if (!activeScan || activeScan.status === 'completed' || activeScan.status === 'failed') return;

    const interval = setInterval(async () => {
      try {
        const updated = await getScanStatus(activeScan.scan_id);
        setActiveScan(updated);
        if (updated.status === 'completed') {
          setIsScanning(false);
          clearInterval(interval);
          loadHistory();
        } else if (updated.status === 'failed') {
          setIsScanning(false);
          clearInterval(interval);
          setError(updated.error || 'Scan failed');
        }
      } catch (e) {
        console.error('Polling error:', e);
      }
    }, 1500);

    return () => clearInterval(interval);
  }, [activeScan]);

  const loadHistory = async () => {
    try {
      const scans = await listScans();
      setScanHistory(scans);
    } catch (e) {
      console.error('Failed to load history:', e);
    }
  };

  const handleScanStart = async (target, scanType) => {
    setError('');
    setIsScanning(true);
    setActiveScan(null);
    try {
      const response = await startScan(target, scanType);
      const initial = await getScanStatus(response.scan_id);
      setActiveScan(initial);
    } catch (e) {
      setIsScanning(false);
      setError(
        e.response?.data?.detail ||
        'Failed to connect to backend. Make sure the API server is running on port 8000.'
      );
    }
  };

  const handleViewResults = (scanId) => {
    navigate(`/results/${scanId}`);
  };

  const handleDeleteScan = async (e, scanId) => {
    e.stopPropagation();
    try {
      await deleteScan(scanId);
      await loadHistory();
    } catch (e) {
      console.error('Delete failed:', e);
    }
  };

  // Navigate to results when scan completes
  useEffect(() => {
    if (activeScan?.status === 'completed') {
      setTimeout(() => navigate(`/results/${activeScan.scan_id}`), 1200);
    }
  }, [activeScan?.status]);

  return (
    <main>
      {/* Hero */}
      <section className="hero">
        <div className="container">
          <div className="hero-badge">⚡ Automated Security Analysis</div>
          <h1 className="hero-title">
            Vulnerability <span className="gradient-text">Scanner</span>
          </h1>
          <p className="hero-subtitle">
            Scan any web target for security vulnerabilities, misconfigurations,
            and exposed services. Get actionable findings with downloadable PDF reports.
          </p>
        </div>
      </section>

      <div className="container" style={{ paddingBottom: '4rem' }}>
        {/* Error banner */}
        {error && (
          <div className="error-banner" style={{ maxWidth: '700px', margin: '0 auto 1rem' }}>
            ⚠️ {error}
          </div>
        )}

        {/* Scan Form */}
        <ScanForm onScanStart={handleScanStart} isScanning={isScanning} />

        {/* Scan Progress */}
        {activeScan && (
          <ScanProgress scanResult={activeScan} />
        )}

        {/* Recent Scans */}
        {scanHistory.length > 0 && (
          <div style={{ maxWidth: '700px', margin: '2rem auto 0' }}>
            <div className="section-header" style={{ marginBottom: '0.75rem' }}>
              <div className="section-title">📋 Recent Scans</div>
              <button
                onClick={loadHistory}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                  fontSize: '0.8rem',
                }}
              >
                ↻ Refresh
              </button>
            </div>
            <div className="glass-card" style={{ padding: '0.5rem' }}>
              {scanHistory.slice(0, 8).map((scan) => (
                <div
                  key={scan.scan_id}
                  className="history-item"
                  onClick={() => handleViewResults(scan.scan_id)}
                >
                  <div className={`status-dot ${scan.status}`} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="history-target">{scan.target}</div>
                    <div style={{ display: 'flex', gap: '0.75rem', marginTop: '2px' }}>
                      <span className="history-time">
                        {new Date(scan.started_at).toLocaleString()}
                      </span>
                      {scan.summary && (
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          {scan.summary.total || 0} findings
                          {scan.summary.critical > 0 && <span style={{ color: 'var(--critical)' }}> · {scan.summary.critical} critical</span>}
                        </span>
                      )}
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    {scan.status === 'running' && (
                      <span style={{ fontSize: '0.78rem', color: 'var(--accent-blue)' }}>{scan.progress}%</span>
                    )}
                    <button
                      onClick={(e) => handleDeleteScan(e, scan.scan_id)}
                      title="Delete scan"
                      style={{
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-muted)',
                        cursor: 'pointer',
                        padding: '0.25rem',
                        fontSize: '0.9rem',
                        borderRadius: '4px',
                        transition: 'all 0.2s',
                      }}
                      onMouseEnter={(e) => e.currentTarget.style.color = 'var(--critical)'}
                      onMouseLeave={(e) => e.currentTarget.style.color = 'var(--text-muted)'}
                    >
                      ✕
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </main>
  );
}
