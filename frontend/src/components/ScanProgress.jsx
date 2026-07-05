const STAGE_ICONS = {
  pending: '○',
  running: '◉',
  completed: '✓',
  failed: '✗',
};

const STATUS_LABELS = {
  pending: 'Pending',
  running: 'Scanning...',
  completed: 'Complete',
  failed: 'Failed',
};

export default function ScanProgress({ scanResult }) {
  if (!scanResult) return null;

  const { progress, stages, status, target } = scanResult;

  return (
    <div className="glass-card stages-container" style={{ marginTop: '1.5rem', maxWidth: '700px', margin: '1.5rem auto 0' }}>
      {/* Header */}
      <div className="stages-header">
        <div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
            Scanning
          </div>
          <div style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '0.95rem',
            color: 'var(--accent-cyan)',
            fontWeight: 600,
          }}>
            {target}
          </div>
        </div>
        <div style={{ textAlign: 'right' }}>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--accent-blue)', lineHeight: 1 }}>
            {progress}%
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            {status}
          </div>
        </div>
      </div>

      {/* Overall progress bar */}
      <div className="overall-progress" style={{ marginBottom: '1.5rem' }}>
        <div className="progress-track">
          <div
            className="progress-fill"
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      {/* Individual stages */}
      {stages && stages.map((stage, idx) => (
        <div key={idx} className="stage-item animate-in">
          <div className={`stage-icon ${stage.status}`}>
            {STAGE_ICONS[stage.status] || '○'}
          </div>
          <div className="stage-info">
            <div className="stage-name">{stage.name}</div>
            {stage.message && (
              <div className="stage-msg">{stage.message}</div>
            )}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <span style={{
              fontSize: '0.72rem',
              color: stage.status === 'completed' ? 'var(--accent-green)' :
                     stage.status === 'running' ? 'var(--accent-blue)' :
                     stage.status === 'failed' ? 'var(--critical)' :
                     'var(--text-muted)',
              fontWeight: 600,
            }}>
              {STATUS_LABELS[stage.status]}
            </span>
            <div className="stage-bar-wrap">
              <div
                className={`stage-bar ${stage.status}`}
                style={{ width: `${stage.progress || 0}%` }}
              />
            </div>
          </div>
        </div>
      ))}

      {/* Completion message */}
      {status === 'completed' && (
        <div style={{
          marginTop: '1rem',
          padding: '0.75rem 1rem',
          background: 'rgba(16, 185, 129, 0.08)',
          border: '1px solid rgba(16, 185, 129, 0.2)',
          borderRadius: 'var(--radius-sm)',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          fontSize: '0.85rem',
          color: 'var(--accent-green)',
        }}>
          ✅ Scan completed successfully! Scroll down to view results.
        </div>
      )}

      {status === 'failed' && (
        <div className="error-banner" style={{ marginTop: '1rem' }}>
          ❌ Scan failed: {scanResult.error || 'Unknown error occurred'}
        </div>
      )}
    </div>
  );
}
