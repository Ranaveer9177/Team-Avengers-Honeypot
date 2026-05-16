// BUG-008 FIX: No credentials in JS — uses session cookies for auth
const serviceData = typeof _serviceData !== 'undefined' ? _serviceData : {};
const attackTypeData = typeof _attackTypeData !== 'undefined' ? _attackTypeData : {};
const countriesData = typeof _countriesData !== 'undefined' ? _countriesData : {};
const allAttacks = typeof _allAttacks !== 'undefined' ? _allAttacks : [];
const topCountries = typeof _topCountries !== 'undefined' ? _topCountries : [];
const topISPs = typeof _topISPs !== 'undefined' ? _topISPs : [];

// VULN-042 FIX: Escape HTML entities to prevent XSS from attacker-controlled data
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

const chartColors = ['#6366f1','#8b5cf6','#ec4899','#06b6d4','#10b981','#f59e0b','#ef4444','#14b8a6','#f472b6','#a78bfa'];

// Tab switching
function switchTab(tab, el) {
  document.querySelectorAll('.tab-view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('tab-' + tab).classList.add('active');
  if (el) el.classList.add('active');
  document.querySelector('.sidebar').classList.remove('open');
  if (tab === 'logs') renderLogs();
  if (tab === 'connections') renderConnections();
  if (tab === 'dashboard' && !window._mapInit) initMap();
}

// Theme
function toggleTheme() {
  const t = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem('theme', t);
  document.getElementById('themeToggle').textContent = t === 'light' ? '☀️' : '🌙';
}

// Charts
function makeChart(id, label, data, type) {
  const ctx = document.getElementById(id);
  if (!ctx || !data || !Object.keys(data).length) {
    if (ctx) ctx.parentElement.innerHTML = '<div style="padding:40px;text-align:center;color:var(--text-muted)">No data</div>';
    return;
  }
  const style = getComputedStyle(document.documentElement);
  new Chart(ctx, {
    type: type || 'doughnut',
    data: { labels: Object.keys(data), datasets: [{ data: Object.values(data), backgroundColor: chartColors, borderWidth: 2, borderColor: style.getPropertyValue('--bg-primary') }] },
    options: {
      responsive: true, maintainAspectRatio: true, cutout: type ? undefined : '65%',
      plugins: {
        legend: { position: 'right', labels: { color: style.getPropertyValue('--text-primary'), font: { family: 'Inter', size: 11 }, padding: 12, boxWidth: 14 } },
        title: { display: true, text: label, color: style.getPropertyValue('--text-primary'), font: { family: 'Inter', size: 14, weight: '600' }, padding: { bottom: 16 } }
      },
      animation: { duration: 800 }
    }
  });
}

// Map
window._mapInit = false;
function initMap() {
  if (window._mapInit) return;
  window._mapInit = true;
  const map = L.map('attackMap').setView([20, 0], 2);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '©OpenStreetMap ©CARTO', maxZoom: 18
  }).addTo(map);
  const icon = L.divIcon({ className: '', html: '<div style="width:10px;height:10px;background:#ef4444;border:2px solid #fff;border-radius:50%;box-shadow:0 0 12px #ef4444"></div>', iconSize: [10, 10] });
  const markers = [];
  allAttacks.forEach(a => {
    const lat = parseFloat(a.lat), lon = parseFloat(a.lon);
    if (!isNaN(lat) && !isNaN(lon)) {
      markers.push(L.marker([lat, lon], { icon }).addTo(map).bindPopup(
        `<div style="font-family:Inter,sans-serif"><strong style="color:#6366f1">${escapeHtml(a.city||'?')}, ${escapeHtml(a.country||'?')}</strong><br>` +
        `<span style="font-family:JetBrains Mono,monospace;font-size:0.85rem">IP: ${escapeHtml(a.ip)}</span><br>Service: ${escapeHtml(a.service||'?')}<br>Type: ${escapeHtml(a.attack_type||'?')}</div>`
      ));
    }
  });
  if (markers.length) map.fitBounds(L.featureGroup(markers).getBounds().pad(0.1));
}

// Logs tab
let logsPage = 1, logsPerPage = 25, sortCol = -1, sortAsc = true, filteredLogs = [];

function renderLogs() {
  filteredLogs = filterLogData();
  if (sortCol >= 0) sortLogData();
  renderLogTable();
  renderPagination();
}

function filterLogData() {
  const q = (document.getElementById('logSearch')?.value || '').toLowerCase();
  const svc = document.getElementById('logServiceFilter')?.value || '';
  const typ = document.getElementById('logSeverity')?.value || '';
  return allAttacks.filter(a => {
    if (q && !JSON.stringify(a).toLowerCase().includes(q)) return false;
    if (svc && (a.service || '').toLowerCase() !== svc.toLowerCase()) return false;
    if (typ && (a.attack_type || '').toLowerCase() !== typ.toLowerCase()) return false;
    return true;
  });
}

function sortTable(col) {
  if (sortCol === col) sortAsc = !sortAsc; else { sortCol = col; sortAsc = true; }
  renderLogs();
}

function sortLogData() {
  const keys = ['timestamp','ip','country','service','attack_type','username','tools_detected'];
  const k = keys[sortCol] || 'timestamp';
  filteredLogs.sort((a, b) => {
    const va = (a[k] || '').toString().toLowerCase(), vb = (b[k] || '').toString().toLowerCase();
    return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
  });
}

function renderLogTable() {
  const body = document.getElementById('logsBody');
  if (!body) return;
  const start = (logsPage - 1) * logsPerPage, page = filteredLogs.slice(start, start + logsPerPage);
  if (!page.length) { body.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:40px;color:var(--text-muted)">No logs found</td></tr>'; return; }
  body.innerHTML = page.map((a, i) => `<tr onclick="toggleDetail(${start+i})" style="cursor:pointer">
    <td style="font-family:JetBrains Mono,monospace;font-size:0.82rem;color:var(--text-muted)">${escapeHtml(a.timestamp||'N/A')}</td>
    <td style="font-family:JetBrains Mono,monospace;color:var(--primary-light);font-weight:600">${escapeHtml(a.ip||'N/A')}</td>
    <td>${escapeHtml(a.city||'?')}, ${escapeHtml(a.country||'?')}</td>
    <td><span class="badge badge-service">${escapeHtml(a.service||'N/A')}</span></td>
    <td><span class="badge badge-attack">${escapeHtml(a.attack_type||'N/A')}</span></td>
    <td>${escapeHtml(a.username||'N/A')}</td>
    <td>${a.tools_detected&&a.tools_detected!=='N/A'?'<span class="badge badge-warning">'+escapeHtml(a.tools_detected)+'</span>':'<span style="color:var(--text-muted)">—</span>'}</td>
    <td><span class="badge badge-info" style="cursor:pointer">⤢</span></td>
  </tr><tr><td colspan="8" style="padding:0"><div class="log-entry-detail" id="detail-${start+i}"><div class="detail-grid">
    <div class="detail-item"><label>IP Address</label><p>${escapeHtml(a.ip||'N/A')}</p></div>
    <div class="detail-item"><label>Location</label><p>${escapeHtml(a.city||'?')}, ${escapeHtml(a.region||'?')}, ${escapeHtml(a.country||'?')}</p></div>
    <div class="detail-item"><label>ISP</label><p>${escapeHtml(a.isp||'Unknown')}</p></div>
    <div class="detail-item"><label>Organization</label><p>${escapeHtml(a.org||'Unknown')}</p></div>
    <div class="detail-item"><label>Auth Method</label><p>${escapeHtml(a.auth_method||'N/A')}</p></div>
    <div class="detail-item"><label>Device</label><p>${escapeHtml(a.device_name||'Unknown')}</p></div>
  </div></div></td></tr>`).join('');
}

function toggleDetail(i) {
  const el = document.getElementById('detail-' + i);
  if (el) el.classList.toggle('show');
}

function renderPagination() {
  const el = document.getElementById('logsPagination');
  if (!el) return;
  const total = Math.ceil(filteredLogs.length / logsPerPage) || 1;
  let html = `<button onclick="goPage(${logsPage-1})" ${logsPage<=1?'disabled':''}>◀</button>`;
  const start = Math.max(1, logsPage - 2), end = Math.min(total, logsPage + 2);
  for (let p = start; p <= end; p++) html += `<button class="${p===logsPage?'active':''}" onclick="goPage(${p})">${p}</button>`;
  html += `<button onclick="goPage(${logsPage+1})" ${logsPage>=total?'disabled':''}>▶</button>`;
  html += `<span>${filteredLogs.length} entries</span>`;
  el.innerHTML = html;
}

function goPage(p) { const total = Math.ceil(filteredLogs.length / logsPerPage); if (p >= 1 && p <= total) { logsPage = p; renderLogTable(); renderPagination(); } }

// Connections tab
function renderConnections() {
  renderTopAttackers();
  renderCountryList();
  renderISPList();
  renderConnServiceChart();
  renderTimeline();
}

function renderTopAttackers() {
  const el = document.getElementById('topAttackersList');
  if (!el) return;
  const counts = {};
  allAttacks.forEach(a => { if (a.ip) counts[a.ip] = (counts[a.ip]||0) + 1; });
  const sorted = Object.entries(counts).sort((a,b) => b[1]-a[1]).slice(0, 10);
  const max = sorted[0] ? sorted[0][1] : 1;
  el.innerHTML = sorted.map(([ip, c]) => `<div class="ip-item">
    <div style="flex:1"><div class="ip-addr">${ip}</div><div class="ip-bar" style="width:${(c/max*100).toFixed(0)}%"></div></div>
    <div class="ip-count">${c} attacks</div>
  </div>`).join('') || '<div style="padding:20px;color:var(--text-muted);text-align:center">No data</div>';
}

function renderCountryList() {
  const el = document.getElementById('countryList');
  if (!el) return;
  const max = topCountries[0] ? topCountries[0][1] : 1;
  el.innerHTML = topCountries.slice(0, 8).map(([name, count]) => `<div class="country-item">
    <span class="country-name">${name}</span>
    <div class="country-bar-bg"><div class="country-bar" style="width:${(count/max*100).toFixed(0)}%"></div></div>
    <span class="country-count">${count}</span>
  </div>`).join('') || '<div style="padding:20px;color:var(--text-muted);text-align:center">No data</div>';
}

function renderISPList() {
  const el = document.getElementById('ispList');
  if (!el) return;
  const max = topISPs[0] ? topISPs[0][1] : 1;
  el.innerHTML = topISPs.slice(0, 8).map(([name, count]) => `<div class="country-item">
    <span class="country-name">${name}</span>
    <div class="country-bar-bg"><div class="country-bar" style="width:${(count/max*100).toFixed(0)}%"></div></div>
    <span class="country-count">${count}</span>
  </div>`).join('') || '<div style="padding:20px;color:var(--text-muted);text-align:center">No data</div>';
}

function renderConnServiceChart() { makeChart('connServiceChart', 'Service Distribution', serviceData, 'doughnut'); }

function renderTimeline() {
  const ctx = document.getElementById('timelineChart');
  if (!ctx) return;
  const buckets = {};
  allAttacks.forEach(a => { const d = (a.timestamp||'').substring(0, 10); if (d) buckets[d] = (buckets[d]||0) + 1; });
  const labels = Object.keys(buckets).sort(), data = labels.map(l => buckets[l]);
  if (!labels.length) { ctx.parentElement.innerHTML = '<div style="padding:40px;text-align:center;color:var(--text-muted)">No timeline data</div>'; return; }
  const style = getComputedStyle(document.documentElement);
  new Chart(ctx, {
    type: 'line',
    data: { labels, datasets: [{ label: 'Attacks', data, borderColor: '#6366f1', backgroundColor: 'rgba(99,102,241,0.1)', fill: true, tension: 0.4, pointRadius: 3, pointBackgroundColor: '#6366f1' }] },
    options: {
      responsive: true, maintainAspectRatio: true,
      plugins: { legend: { display: false }, title: { display: true, text: 'Attack Timeline', color: style.getPropertyValue('--text-primary'), font: { family:'Inter', size:14, weight:'600' } } },
      scales: {
        x: { ticks: { color: style.getPropertyValue('--text-muted'), font: { size: 10 } }, grid: { color: 'rgba(99,102,241,0.06)' } },
        y: { beginAtZero: true, ticks: { color: style.getPropertyValue('--text-muted') }, grid: { color: 'rgba(99,102,241,0.06)' } }
      }
    }
  });
}

// Filters
function toggleFilters() { const p = document.getElementById('filterPanel'); if (p) p.style.display = p.style.display === 'none' ? 'block' : 'none'; }

async function applyFilters() {
  const f = {
    start_date: document.getElementById('startDate')?.value ? new Date(document.getElementById('startDate').value).toISOString() : null,
    end_date: document.getElementById('endDate')?.value ? new Date(document.getElementById('endDate').value).toISOString() : null,
    service: document.getElementById('filterService')?.value,
    attack_type: document.getElementById('filterAttackType')?.value,
    country: document.getElementById('filterCountry')?.value,
    ip: document.getElementById('filterIP')?.value
  };
  try {
    const r = await fetch('/api/attacks/filter', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(f) });
    const d = await r.json();
    showToast({severity:'success',message:`${d.count} attacks found`,timestamp:new Date().toISOString()});
  } catch(e) { showToast({severity:'critical',message:'Filter error: '+e.message,timestamp:new Date().toISOString()}); }
}

function clearFilters() { ['startDate','endDate','filterIP'].forEach(id=>{const e=document.getElementById(id);if(e)e.value='';}); ['filterService','filterAttackType','filterCountry'].forEach(id=>{const e=document.getElementById(id);if(e)e.value='';}); location.reload(); }

// Alerts
let alertCount = 0;
function toggleAlertPanel() { document.getElementById('alertPanel')?.classList.toggle('active'); if (document.getElementById('alertPanel')?.classList.contains('active')) loadAlerts(); }

function showToast(alert) {
  const c = document.getElementById('toastContainer'); if (!c) return;
  const icons = {critical:'🚨',high:'⚠️',medium:'ℹ️',info:'ℹ️',success:'✅'};
  const t = document.createElement('div'); t.className = 'toast ' + (alert.severity||'info');
  t.innerHTML = `<span style="font-size:1.3rem">${icons[alert.severity]||'ℹ️'}</span><div><div style="font-weight:600">${alert.message}</div><div style="font-size:0.72rem;color:var(--text-muted);margin-top:3px">${new Date(alert.timestamp).toLocaleString()}</div></div>`;
  c.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transform = 'translateX(40px)'; setTimeout(() => t.remove(), 300); }, 4000);
}

async function loadAlerts() {
  try {
    const r = await fetch('/api/alerts');
    const d = await r.json();
    const list = document.getElementById('alertList');
    if (list && d.alerts) {
      list.innerHTML = d.alerts.slice(0, 50).map(a => `<div class="alert-item ${a.severity}"><div style="font-weight:600;margin-bottom:3px">${a.message}</div><div style="font-size:0.72rem;color:var(--text-muted)">${new Date(a.timestamp).toLocaleString()}</div></div>`).join('');
      alertCount = d.count || 0;
      const el = document.getElementById('alertCount');
      if (el) { el.textContent = alertCount; el.style.display = alertCount > 0 ? 'flex' : 'none'; }
    }
  } catch(e) { console.error('Alert load error:', e); }
}

// Export
function openExportModal() { const m=document.getElementById('exportModal'); if(m){m.style.display='flex';m.classList.add('active');} }
function closeExportModal() { const m=document.getElementById('exportModal'); if(m){m.style.display='none';m.classList.remove('active');} }
async function performExport() {
  const fmt = document.getElementById('exportFormat')?.value || 'json';
  try {
    const r = await fetch('/api/attacks/export', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({format:fmt}) });
    if (fmt === 'csv') { const b = await r.blob(); const u = URL.createObjectURL(b); const a = document.createElement('a'); a.href=u; a.download='attacks.csv'; a.click(); URL.revokeObjectURL(u); }
    else { const d = await r.json(); const b = new Blob([JSON.stringify(d,null,2)],{type:'application/json'}); const u = URL.createObjectURL(b); const a = document.createElement('a'); a.href=u; a.download='attacks.json'; a.click(); URL.revokeObjectURL(u); }
    closeExportModal(); showToast({severity:'success',message:'Exported!',timestamp:new Date().toISOString()});
  } catch(e) { showToast({severity:'critical',message:'Export error',timestamp:new Date().toISOString()}); }
}

function exportTable() {
  let csv = 'Timestamp,IP,Location,Service,Type,Username,Tools\n';
  filteredLogs.forEach(a => { csv += `"${a.timestamp||''}","${a.ip||''}","${(a.city||'')}, ${a.country||''}","${a.service||''}","${a.attack_type||''}","${a.username||''}","${a.tools_detected||''}"\n`; });
  const b = new Blob([csv],{type:'text/csv'}); const u = URL.createObjectURL(b); const a = document.createElement('a'); a.href=u; a.download='logs.csv'; a.click();
}

// Reset
function openResetModal() { const m=document.getElementById('resetModal'); if(m){m.style.display='flex';m.classList.add('active');} }
function closeResetModal() { const m=document.getElementById('resetModal'); if(m){m.style.display='none';m.classList.remove('active');} }
async function performReset() {
  const btn = document.getElementById('resetConfirmBtn');
  try {
    if(btn){btn.disabled=true;btn.textContent='Processing...';}
    const r = await fetch('/api/reset',{method:'POST',headers:{'Content-Type':'application/json'}});
    const d = await r.json();
    if(d.success){showToast({severity:'success',message:'Reset complete!',timestamp:new Date().toISOString()});closeResetModal();setTimeout(()=>location.reload(),1500);}
    else throw new Error(d.error);
  } catch(e){showToast({severity:'critical',message:'Reset failed: '+e.message,timestamp:new Date().toISOString()});if(btn){btn.disabled=false;btn.textContent='🗑️ Confirm';}}
}

// Log search events
document.addEventListener('DOMContentLoaded', function() {
  const saved = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  const tb = document.getElementById('themeToggle');
  if (tb) tb.textContent = saved === 'light' ? '☀️' : '🌙';

  makeChart('serviceChart', 'Service Distribution', serviceData);
  makeChart('attackTypeChart', 'Attack Types', attackTypeData);
  makeChart('countriesChart', 'Top Countries', countriesData);
  initMap();
  loadAlerts();

  ['logSearch','logServiceFilter','logSeverity'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('input', () => { logsPage = 1; renderLogs(); });
    if (el) el.addEventListener('change', () => { logsPage = 1; renderLogs(); });
  });

  // Modal close on outside click
  ['exportModal','resetModal'].forEach(id => {
    const m = document.getElementById(id);
    if (m) m.addEventListener('click', e => { if (e.target === m) { m.style.display='none'; m.classList.remove('active'); } });
  });
});

// Global
window.switchTab = switchTab; window.toggleTheme = toggleTheme; window.toggleFilters = toggleFilters;
window.applyFilters = applyFilters; window.clearFilters = clearFilters; window.sortTable = sortTable;
window.toggleDetail = toggleDetail; window.goPage = goPage; window.toggleAlertPanel = toggleAlertPanel;
window.openExportModal = openExportModal; window.closeExportModal = closeExportModal;
window.performExport = performExport; window.exportTable = exportTable;
window.openResetModal = openResetModal; window.closeResetModal = closeResetModal;
window.performReset = performReset;

setInterval(() => { if (document.visibilityState === 'visible') loadAlerts(); }, 60000);
