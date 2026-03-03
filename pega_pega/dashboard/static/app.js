/* pega-pega dashboard -- utility functions (primary logic lives in index.html) */

/**
 * Format a hex string into a traditional hex-dump view:
 * offset | 16 hex bytes | ASCII sidebar
 */
function hexDump(hexStr) {
    if (!hexStr) return '';
    const bytes = [];
    for (let i = 0; i < hexStr.length; i += 2) {
        bytes.push(parseInt(hexStr.substr(i, 2), 16));
    }
    const lines = [];
    for (let offset = 0; offset < bytes.length; offset += 16) {
        const chunk = bytes.slice(offset, offset + 16);
        const hex = chunk.map(b => b.toString(16).padStart(2, '0')).join(' ');
        const ascii = chunk.map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
        const addr = offset.toString(16).padStart(8, '0');
        lines.push(`${addr}  ${hex.padEnd(48)}  |${ascii}|`);
    }
    return lines.join('\n');
}

/**
 * Escape HTML special characters to prevent XSS.
 */
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    const s = String(str);
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(s));
    return div.innerHTML;
}

/**
 * Format an ISO timestamp to a short time string.
 */
function formatTime(isoStr) {
    try {
        const d = new Date(isoStr);
        return d.toLocaleTimeString('en-GB', { hour12: false });
    } catch {
        return isoStr || '';
    }
}

/**
 * Format an ISO timestamp to a full date-time string.
 */
function formatDateTime(isoStr) {
    try {
        const d = new Date(isoStr);
        return d.toLocaleString('en-GB', { hour12: false });
    } catch {
        return isoStr || '';
    }
}
