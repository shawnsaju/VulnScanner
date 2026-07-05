import { useState } from 'react';

const SCAN_TYPES = [
  { id: 'full', label: '🔍 Full Scan', desc: 'Complete analysis' },
  { id: 'quick', label: '⚡ Quick Scan', desc: 'Fast essentials' },
  { id: 'headers', label: '📋 Headers', desc: 'HTTP / SSL only' },
  { id: 'ports', label: '🔌 Ports', desc: 'Port discovery' },
];

const EXAMPLE_TARGETS = [
  'example.com',
  'scanme.nmap.org',
  'httpbin.org',
  'testphp.vulnweb.com',
];

export default function ScanForm({ onScanStart, isScanning }) {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('full');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    const trimmed = target.trim();
    if (!trimmed) {
      setError('Please enter a target URL or IP address');
      return;
    }
    setError('');
    onScanStart(trimmed, scanType);
  };

  return (
    <div className="scan-form-container">
      <div className="glass-card scan-form">
        <form onSubmit={handleSubmit}>
          {/* Target input */}
          <label className="form-label">Target URL or IP Address</label>
          <div className="input-wrapper">
            <span className="input-icon">🎯</span>
            <input
              className="target-input"
              type="text"
              placeholder="e.g., example.com or 192.168.1.1"
              value={target}
              onChange={(e) => { setTarget(e.target.value); setError(''); }}
              disabled={isScanning}
              autoFocus
            />
            <button
              type="submit"
              className={`scan-btn ${isScanning ? 'scanning' : ''}`}
              disabled={isScanning}
            >
              {isScanning ? (
                <>
                  <span className="spinner" />
                  Scanning...
                </>
              ) : (
                <>🚀 Start Scan</>
              )}
            </button>
          </div>

          {error && (
            <div className="error-banner">
              ⚠️ {error}
            </div>
          )}

          {/* Scan type */}
          <div style={{ marginTop: '1.25rem' }}>
            <label className="form-label">Scan Type</label>
            <div className="scan-type-grid">
              {SCAN_TYPES.map((type) => (
                <button
                  key={type.id}
                  type="button"
                  className={`scan-type-btn ${scanType === type.id ? 'active' : ''}`}
                  onClick={() => setScanType(type.id)}
                  disabled={isScanning}
                >
                  <div>{type.label}</div>
                  <div style={{ fontSize: '0.7rem', opacity: 0.7, marginTop: '2px' }}>{type.desc}</div>
                </button>
              ))}
            </div>
          </div>
        </form>

        {/* Quick targets */}
        <div style={{ marginTop: '1.25rem', paddingTop: '1rem', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
          <label className="form-label" style={{ marginBottom: '0.6rem', display: 'block' }}>
            Quick Test Targets
          </label>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {EXAMPLE_TARGETS.map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setTarget(t)}
                disabled={isScanning}
                style={{
                  background: 'rgba(255,255,255,0.04)',
                  border: '1px solid rgba(255,255,255,0.08)',
                  borderRadius: '6px',
                  padding: '0.3rem 0.75rem',
                  color: 'var(--text-muted)',
                  fontSize: '0.78rem',
                  fontFamily: "'JetBrains Mono', monospace",
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.borderColor = 'var(--accent-blue)';
                  e.currentTarget.style.color = 'var(--accent-cyan)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)';
                  e.currentTarget.style.color = 'var(--text-muted)';
                }}
              >
                {t}
              </button>
            ))}
          </div>
          <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.75rem' }}>
            ⚠️ Only scan targets you own or have explicit written permission to test.
          </p>
        </div>
      </div>
    </div>
  );
}
