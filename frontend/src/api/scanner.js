import axios from 'axios';

const API_BASE = 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

export const startScan = async (target, scanType = 'full') => {
  const response = await api.post('/scan', { target, scan_type: scanType });
  return response.data;
};

export const getScanStatus = async (scanId) => {
  const response = await api.get(`/scan/${scanId}`);
  return response.data;
};

export const listScans = async () => {
  const response = await api.get('/scans');
  return response.data;
};

export const deleteScan = async (scanId) => {
  const response = await api.delete(`/scan/${scanId}`);
  return response.data;
};

export const getReportUrl = (scanId) => `${API_BASE}/scan/${scanId}/report`;

export default api;
