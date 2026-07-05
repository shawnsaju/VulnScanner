import { getReportUrl } from '../api/scanner';

export default function ReportDownload({ scanId, target, summary }) {
  const handleDownload = () => {
    const url = getReportUrl(scanId);
    const link = document.createElement('a');
    link.href = url;
    link.download = `vuln_report_${(target || 'scan').replace(/[^a-z0-9]/gi, '_')}_${scanId.slice(0, 8)}.pdf`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const totalVulns = summary?.total || 0;
  const hasCritical = (summary?.critical || 0) > 0;

  return (
    <div className="glass-card" style={{ padding: '1.5rem 2rem', marginBottom: '2rem' }}>
      <div className="download-section">
        <div>
          <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.3rem' }}>
            📄 Security Assessment Report
          </div>
          <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            Complete PDF report with {totalVulns} findings, port analysis, SSL details, and remediation guidance.
          </div>
        </div>
        <button className="download-btn" onClick={handleDownload}>
          ⬇️ Download PDF Report
        </button>
      </div>

      {hasCritical && (
        <div style={{
          marginTop: '1rem',
          padding: '0.65rem 1rem',
          background: 'rgba(239, 68, 68, 0.08)',
          border: '1px solid rgba(239, 68, 68, 0.2)',
          borderRadius: '6px',
          fontSize: '0.82rem',
          color: 'var(--critical)',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
        }}>
          🚨 <strong>{summary.critical} Critical</strong> vulnerabilities found — immediate remediation recommended.
        </div>
      )}
    </div>
  );
}
