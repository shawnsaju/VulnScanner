import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
};

const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    return (
      <div className="custom-tooltip">
        <strong>{payload[0].name}</strong>: {payload[0].value}
      </div>
    );
  }
  return null;
};

export default function SeverityChart({ summary, vulnerabilities }) {
  if (!summary) return null;

  // Pie chart data
  const pieData = Object.entries(SEVERITY_COLORS)
    .map(([key, color]) => ({
      name: key.charAt(0).toUpperCase() + key.slice(1),
      value: summary[key] || 0,
      color,
    }))
    .filter((d) => d.value > 0);

  // Bar chart: vulnerabilities by category
  const categoryMap = {};
  (vulnerabilities || []).forEach((v) => {
    const cat = v.category || 'Other';
    if (!categoryMap[cat]) categoryMap[cat] = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    categoryMap[cat][v.severity] = (categoryMap[cat][v.severity] || 0) + 1;
  });

  const barData = Object.entries(categoryMap)
    .map(([cat, counts]) => ({
      name: cat.length > 14 ? cat.slice(0, 12) + '…' : cat,
      ...counts,
      total: Object.values(counts).reduce((a, b) => a + b, 0),
    }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 8);

  return (
    <div className="charts-grid">
      {/* Pie Chart */}
      <div className="glass-card chart-card">
        <div className="chart-title">📊 Severity Distribution</div>
        {pieData.length > 0 ? (
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie
                data={pieData}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={90}
                paddingAngle={3}
                dataKey="value"
              >
                {pieData.map((entry, index) => (
                  <Cell
                    key={index}
                    fill={entry.color}
                    stroke="rgba(0,0,0,0.3)"
                    strokeWidth={1}
                  />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
              <Legend
                iconType="circle"
                iconSize={8}
                formatter={(value) => (
                  <span style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>{value}</span>
                )}
              />
            </PieChart>
          </ResponsiveContainer>
        ) : (
          <div className="empty-state" style={{ padding: '2rem' }}>
            <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>🎉</div>
            <div style={{ color: 'var(--accent-green)' }}>No vulnerabilities found!</div>
          </div>
        )}
      </div>

      {/* Bar Chart */}
      <div className="glass-card chart-card">
        <div className="chart-title">📈 Vulnerabilities by Category</div>
        {barData.length > 0 ? (
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={barData} margin={{ top: 5, right: 10, left: -15, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis
                dataKey="name"
                tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip content={<CustomTooltip />} />
              <Bar dataKey="critical" fill={SEVERITY_COLORS.critical} stackId="a" radius={0} name="Critical" />
              <Bar dataKey="high" fill={SEVERITY_COLORS.high} stackId="a" name="High" />
              <Bar dataKey="medium" fill={SEVERITY_COLORS.medium} stackId="a" name="Medium" />
              <Bar dataKey="low" fill={SEVERITY_COLORS.low} stackId="a" name="Low" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="empty-state" style={{ padding: '2rem' }}>
            <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>📭</div>
            <div style={{ color: 'var(--text-muted)' }}>No category data</div>
          </div>
        )}
      </div>
    </div>
  );
}
