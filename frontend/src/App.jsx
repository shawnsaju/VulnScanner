import { BrowserRouter, Routes, Route, NavLink, useLocation } from 'react-router-dom';
import Home from './pages/Home';
import Results from './pages/Results';

function Navbar() {
  return (
    <nav className="navbar">
      <div className="container navbar-inner">
        <NavLink to="/" className="navbar-brand">
          <div className="brand-icon">🔒</div>
          <div className="brand-text">
            Vuln<span>Scanner</span>
          </div>
        </NavLink>
        <div className="navbar-links">
          <NavLink
            to="/"
            end
            className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
          >
            🏠 Scanner
          </NavLink>

        </div>
      </div>
    </nav>
  );
}

function App() {
  return (
    <BrowserRouter>
      <div className="app-layout">
        <div className="grid-bg" />
        <Navbar />
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/results/:scanId" element={<Results />} />
        </Routes>
        <footer style={{
          textAlign: 'center',
          padding: '1.5rem',
          borderTop: '1px solid rgba(255,255,255,0.05)',
          color: 'var(--text-muted)',
          fontSize: '0.78rem',
          marginTop: 'auto',
        }}>
          ⚠️ VulnScanner is for authorized security testing only. Always obtain written permission before scanning.
          &nbsp;|&nbsp; Built with FastAPI + React + Recharts
        </footer>
      </div>
    </BrowserRouter>
  );
}

export default App;
