/**
 * ThreatScope V2 — Main JavaScript
 * Author: 0xSABRY
 *
 * Core UI interactions, file upload handling, and API calls.
 */

// ============================================================
// Security helpers
// ============================================================
function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

// Escape untrusted text before inserting into HTML.
function escapeHtml(value) {
    return String(value == null ? '' : value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// fetch() wrapper that attaches the CSRF token to state-changing requests.
function csrfFetch(url, options = {}) {
    const opts = Object.assign({}, options);
    const method = (opts.method || 'GET').toUpperCase();
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
        opts.headers = Object.assign({}, opts.headers, {
            'X-CSRF-Token': getCsrfToken()
        });
    }
    return fetch(url, opts);
}

// ============================================================
// Sidebar Toggle
// ============================================================
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('open');
}

// ============================================================
// Toast Notifications
// ============================================================
function showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100px)';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// ============================================================
// Loading Overlay
// ============================================================
function showLoading(text = 'Analyzing...') {
    const overlay = document.getElementById('loading-overlay');
    const loadingText = document.getElementById('loading-text');
    if (overlay) overlay.style.display = 'flex';
    if (loadingText) loadingText.textContent = text;
}

function hideLoading() {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) overlay.style.display = 'none';
}

// ============================================================
// File Upload
// ============================================================
function handleDrop(event) {
    event.preventDefault();
    event.currentTarget.classList.remove('drag-over');
    const files = event.dataTransfer.files;
    if (files.length > 0) uploadFile(files[0]);
}

function handleFileSelect(input) {
    if (input.files.length > 0) uploadFile(input.files[0]);
}

async function uploadFile(file) {
    showLoading('Uploading...');
    updateStatus('Uploading');

    const formData = new FormData();
    formData.append('file', file);

    try {
        const resp = await csrfFetch('/api/upload', { method: 'POST', body: formData });
        const data = await resp.json();

        if (data.error) {
            showToast(data.error, 'error');
            hideLoading();
            return;
        }

        showToast(`File uploaded: ${data.filename}`, 'success');
        showLoading('Analyzing events...');
        updateStatus('Analyzing');

        // Auto-analyze
        const analyzeResp = await csrfFetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filepath: data.filepath })
        });
        const result = await analyzeResp.json();

        hideLoading();

        if (result.error) {
            showToast(`Analysis error: ${result.error}`, 'error');
            return;
        }

        showToast(
            `Analysis complete! Score: ${result.threat_score}% (${result.threat_level})`,
            result.threat_score >= 60 ? 'error' : 'success'
        );

        // Reload page to show results
        window.location.reload();
    } catch (e) {
        hideLoading();
        showToast(`Upload failed: ${e.message}`, 'error');
    }
}

// ============================================================
// Export Report
// ============================================================
async function exportReport(format) {
    showToast(`Exporting ${format.toUpperCase()} report...`, 'info');
    try {
        const resp = await csrfFetch(`/api/export/${format}`, { method: 'POST' });
        if (!resp.ok) {
            const err = await resp.json();
            showToast(err.error || 'Export failed', 'error');
            return;
        }

        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        const ext = format === 'stix' ? 'json' : format;
        a.href = url;
        a.download = `threatscope_report.${ext}`;
        a.click();
        URL.revokeObjectURL(url);
        showToast(`${format.toUpperCase()} report downloaded!`, 'success');
    } catch (e) {
        showToast(`Export failed: ${e.message}`, 'error');
    }
}

// ============================================================
// Status Indicator
// ============================================================
function updateStatus(text) {
    const indicator = document.getElementById('status-indicator');
    if (indicator) {
        indicator.querySelector('span:last-child').textContent = text;
    }
}

// ============================================================
// Animation on scroll (stat cards)
// ============================================================
function animateCounters() {
    document.querySelectorAll('.stat-value').forEach(el => {
        const target = parseInt(el.textContent.replace(/,/g, ''));
        if (isNaN(target) || target === 0) return;

        let current = 0;
        const step = Math.max(1, Math.floor(target / 30));
        const timer = setInterval(() => {
            current += step;
            if (current >= target) {
                current = target;
                clearInterval(timer);
            }
            el.textContent = current.toLocaleString();
        }, 30);
    });
}

// ============================================================
// Init
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
    // Animate counters on load
    setTimeout(animateCounters, 200);

    // Keyboard shortcut for upload
    document.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.key === 'u') {
            e.preventDefault();
            const input = document.getElementById('file-input');
            if (input) input.click();
        }
    });
});
