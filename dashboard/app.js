/* ============================================
   NetSentinel — Application Logic
   ============================================ */

// ── Utility Helpers ──────────────────────────
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);
const rand = (min, max) => Math.random() * (max - min) + min;
const randInt = (min, max) => Math.floor(rand(min, max + 1));
const pick = (arr) => arr[randInt(0, arr.length - 1)];
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const pad = (n) => String(n).padStart(2, '0');

// ── Data Sources ─────────────────────────────
const ATTACK_TYPES = [
    'SYN Flood', 'Port Scan', 'SQL Injection', 'XSS Attempt',
    'Brute Force SSH', 'DNS Amplification', 'ICMP Flood',
    'Buffer Overflow', 'Path Traversal', 'Credential Stuffing',
    'DDoS', 'Malware C2', 'Data Exfiltration', 'Privilege Escalation',
    'Man-in-the-Middle', 'ARP Spoofing', 'Zero-Day Exploit'
];

const LOG_MESSAGES = {
    critical: [
        'Unauthorized root access detected from <hl>{ip}</hl>',
        'Critical: Ransomware signature identified in payload from <hl>{ip}</hl>',
        'Kernel panic recovered — potential rootkit activity on <hl>eth0</hl>',
        'Multiple failed sudo attempts from user <hl>admin</hl> (source: {ip})',
        'Anomalous outbound traffic spike: <hl>4.2GB/s</hl> to unknown endpoint',
        'Database dump detected — exfiltration attempt from <hl>{ip}</hl>',
    ],
    warning: [
        'Unusual login pattern: 47 attempts in 60s from <hl>{ip}</hl>',
        'SSL certificate mismatch on port <hl>443</hl> — possible MITM',
        'DNS query volume anomaly: 3200% above baseline from <hl>{ip}</hl>',
        'Suspicious process <hl>nc -lvp 4444</hl> spawned by www-data',
        'Firewall rule bypass detected on interface <hl>vlan200</hl>',
        'Memory anomaly: heap corruption in <hl>nginx</hl> worker process',
    ],
    info: [
        'Routine scan completed — <hl>2,847</hl> hosts reachable',
        'Firewall rules synced across <hl>12</hl> nodes',
        'Certificate rotation complete for <hl>*.sentinel.io</hl>',
        'Network segment <hl>10.0.4.0/24</hl> health check passed',
        'IDS signature database updated to version <hl>v4.12.7</hl>',
        'Backup completed: <hl>847GB</hl> compressed, stored off-site',
    ],
    success: [
        'Threat <hl>{ip}</hl> successfully quarantined and blocked',
        'Auto-remediation applied: <hl>iptables</hl> rules updated',
        'Incident #<hl>4892</hl> resolved — all systems nominal',
        'DDoS mitigation effective — traffic normalized to <hl>baseline</hl>',
    ]
};

const PROTOCOLS = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'ICMP', 'FTP', 'SMTP'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const STATUSES = ['blocked', 'monitoring', 'mitigated'];
const TARGETS = [
    'web-server-01', 'db-master', 'api-gateway', 'load-balancer',
    'dns-primary', 'mail-server', 'auth-service', 'cdn-edge-03',
    'vpn-gateway', 'k8s-master', 'redis-cache', 'elastic-node-02'
];

const PORT_DATA = [
    { port: 22, name: 'SSH', color: '#3b82f6' },
    { port: 80, name: 'HTTP', color: '#10b981' },
    { port: 443, name: 'HTTPS', color: '#7c3aed' },
    { port: 3306, name: 'MySQL', color: '#f59e0b' },
    { port: 8080, name: 'Proxy', color: '#00f0ff' },
    { port: 21, name: 'FTP', color: '#f97316' },
    { port: 25, name: 'SMTP', color: '#ec4899' },
    { port: 53, name: 'DNS', color: '#6366f1' },
];

// Geographic attack origins (lon, lat pairs approximated for canvas)
const GEO_ORIGINS = [
    { name: 'Beijing', x: 0.77, y: 0.32 },
    { name: 'Moscow', x: 0.58, y: 0.25 },
    { name: 'São Paulo', x: 0.32, y: 0.68 },
    { name: 'Lagos', x: 0.50, y: 0.55 },
    { name: 'Mumbai', x: 0.68, y: 0.45 },
    { name: 'Seoul', x: 0.82, y: 0.32 },
    { name: 'Tehran', x: 0.62, y: 0.35 },
    { name: 'Bucharest', x: 0.55, y: 0.30 },
    { name: 'Jakarta', x: 0.78, y: 0.58 },
    { name: 'Kiev', x: 0.56, y: 0.27 },
    { name: 'Buenos Aires', x: 0.30, y: 0.75 },
    { name: 'Hanoi', x: 0.76, y: 0.42 },
];

// Target location (centered US East Coast)
const TARGET_LOC = { x: 0.22, y: 0.33 };

function randomIP() {
    return `${randInt(1,223)}.${randInt(0,255)}.${randInt(0,255)}.${randInt(1,254)}`;
}

function formatTime(d) {
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

// ── State ────────────────────────────────────
const state = {
    totalEvents: randInt(124000, 186000),
    totalAnomalies: randInt(380, 620),
    blockedIPs: randInt(42, 78),
    bandwidth: rand(120, 280).toFixed(1),
    alerts: [],
    threats: [],
    portCounts: PORT_DATA.map(() => randInt(200, 2000)),
    trafficData: { inbound: [], outbound: [], anomaly: [], labels: [] },
    severityData: [0, 0, 0, 0],
    attackAnimations: [],
};

// Initialize traffic data (60 data points)
for (let i = 60; i >= 0; i--) {
    const t = new Date(Date.now() - i * 2000);
    state.trafficData.labels.push(formatTime(t));
    state.trafficData.inbound.push(rand(50, 200));
    state.trafficData.outbound.push(rand(30, 150));
    state.trafficData.anomaly.push(Math.random() < 0.12 ? rand(180, 350) : null);
}

state.severityData = [randInt(15, 40), randInt(25, 55), randInt(45, 80), randInt(60, 120)];

// ── Background Particles ─────────────────────
function initParticles() {
    const canvas = $('#bg-particles');
    const ctx = canvas.getContext('2d');
    let particles = [];
    let W, H;

    function resize() {
        W = canvas.width = window.innerWidth;
        H = canvas.height = window.innerHeight;
    }
    resize();
    window.addEventListener('resize', resize);

    for (let i = 0; i < 60; i++) {
        particles.push({
            x: rand(0, W),
            y: rand(0, H),
            r: rand(0.5, 1.5),
            vx: rand(-0.15, 0.15),
            vy: rand(-0.15, 0.15),
            alpha: rand(0.15, 0.5),
        });
    }

    function draw() {
        ctx.clearRect(0, 0, W, H);
        particles.forEach((p) => {
            p.x += p.vx;
            p.y += p.vy;
            if (p.x < 0) p.x = W;
            if (p.x > W) p.x = 0;
            if (p.y < 0) p.y = H;
            if (p.y > H) p.y = 0;

            ctx.beginPath();
            ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(0, 240, 255, ${p.alpha})`;
            ctx.fill();
        });

        // Draw connections
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 120) {
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.strokeStyle = `rgba(0, 240, 255, ${0.06 * (1 - dist / 120)})`;
                    ctx.lineWidth = 0.5;
                    ctx.stroke();
                }
            }
        }
        requestAnimationFrame(draw);
    }
    draw();
}

// ── Clock ────────────────────────────────────
function updateClock() {
    const now = new Date();
    $('#header-clock').textContent = formatTime(now);
}

// ── Counters Animation ──────────────────────
function animateValue(el, target, duration = 1200, suffix = '') {
    const start = parseInt(el.textContent.replace(/[^0-9]/g, '')) || 0;
    const diff = target - start;
    const startTime = performance.now();

    function step(time) {
        const progress = Math.min((time - startTime) / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(start + diff * eased);
        el.textContent = current.toLocaleString() + suffix;
        if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
}

function updateStats() {
    state.totalEvents += randInt(3, 18);
    state.totalAnomalies += Math.random() < 0.3 ? randInt(1, 3) : 0;
    state.blockedIPs += Math.random() < 0.15 ? 1 : 0;
    state.bandwidth = clamp(parseFloat(state.bandwidth) + rand(-15, 15), 80, 400).toFixed(1);

    animateValue($('#total-events'), state.totalEvents);
    animateValue($('#total-anomalies'), state.totalAnomalies);
    animateValue($('#blocked-ips'), state.blockedIPs);
    $('#bandwidth').textContent = state.bandwidth;

    $('#events-trend').textContent = `+${rand(1.2, 4.8).toFixed(1)}%`;
    $('#anomalies-trend').textContent = `+${rand(0.5, 3.2).toFixed(1)}%`;
    $('#blocked-trend').textContent = `+${randInt(1, 5)}`;
    const bwDelta = rand(-2.5, 2.5);
    $('#bandwidth-trend').textContent = `${bwDelta > 0 ? '+' : ''}${bwDelta.toFixed(1)}%`;
}

// ── Threat Level ─────────────────────────────
function updateThreatLevel() {
    const level = rand(0, 100);
    const fill = $('#threat-fill');
    const value = $('#threat-value');
    const container = $('#threat-level-widget');

    fill.style.width = level + '%';

    if (level < 25) {
        value.textContent = 'LOW';
        value.style.color = '#10b981';
        container.style.borderColor = 'rgba(16, 185, 129, 0.2)';
        container.style.background = 'rgba(16, 185, 129, 0.06)';
    } else if (level < 55) {
        value.textContent = 'MODERATE';
        value.style.color = '#f59e0b';
        container.style.borderColor = 'rgba(245, 158, 11, 0.2)';
        container.style.background = 'rgba(245, 158, 11, 0.06)';
    } else if (level < 80) {
        value.textContent = 'HIGH';
        value.style.color = '#f97316';
        container.style.borderColor = 'rgba(249, 115, 22, 0.2)';
        container.style.background = 'rgba(249, 115, 22, 0.06)';
    } else {
        value.textContent = 'CRITICAL';
        value.style.color = '#ff3366';
        container.style.borderColor = 'rgba(255, 51, 102, 0.3)';
        container.style.background = 'rgba(255, 51, 102, 0.08)';
    }
}

// ── Traffic Chart ────────────────────────────
let trafficChart;

function initTrafficChart() {
    const ctx = $('#traffic-chart').getContext('2d');

    const gradientIn = ctx.createLinearGradient(0, 0, 0, 220);
    gradientIn.addColorStop(0, 'rgba(0, 240, 255, 0.2)');
    gradientIn.addColorStop(1, 'rgba(0, 240, 255, 0)');

    const gradientOut = ctx.createLinearGradient(0, 0, 0, 220);
    gradientOut.addColorStop(0, 'rgba(124, 58, 237, 0.15)');
    gradientOut.addColorStop(1, 'rgba(124, 58, 237, 0)');

    trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: state.trafficData.labels,
            datasets: [
                {
                    label: 'Inbound',
                    data: state.trafficData.inbound,
                    borderColor: '#00f0ff',
                    backgroundColor: gradientIn,
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    pointHoverBackgroundColor: '#00f0ff',
                },
                {
                    label: 'Outbound',
                    data: state.trafficData.outbound,
                    borderColor: '#7c3aed',
                    backgroundColor: gradientOut,
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 4,
                    pointHoverBackgroundColor: '#7c3aed',
                },
                {
                    label: 'Anomaly',
                    data: state.trafficData.anomaly,
                    borderColor: '#ff3366',
                    backgroundColor: 'rgba(255, 51, 102, 0.1)',
                    borderWidth: 2,
                    fill: false,
                    tension: 0,
                    pointRadius: (ctx) => ctx.raw != null ? 5 : 0,
                    pointBackgroundColor: '#ff3366',
                    pointBorderColor: 'rgba(255, 51, 102, 0.3)',
                    pointBorderWidth: 4,
                    showLine: false,
                },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false,
            },
            plugins: {
                legend: {
                    display: true,
                    position: 'top',
                    align: 'end',
                    labels: {
                        color: '#94a3b8',
                        font: { family: "'Inter'", size: 11 },
                        usePointStyle: true,
                        pointStyle: 'circle',
                        padding: 16,
                    },
                },
                tooltip: {
                    backgroundColor: 'rgba(13, 17, 23, 0.95)',
                    borderColor: 'rgba(0, 240, 255, 0.15)',
                    borderWidth: 1,
                    titleColor: '#e2e8f0',
                    bodyColor: '#94a3b8',
                    titleFont: { family: "'JetBrains Mono'", size: 11 },
                    bodyFont: { family: "'JetBrains Mono'", size: 11 },
                    cornerRadius: 8,
                    padding: 10,
                },
            },
            scales: {
                x: {
                    ticks: {
                        color: '#64748b',
                        font: { family: "'JetBrains Mono'", size: 10 },
                        maxTicksLimit: 10,
                    },
                    grid: {
                        color: 'rgba(255,255,255,0.03)',
                    },
                    border: { display: false },
                },
                y: {
                    ticks: {
                        color: '#64748b',
                        font: { family: "'JetBrains Mono'", size: 10 },
                        callback: (v) => v + ' MB/s',
                    },
                    grid: {
                        color: 'rgba(255,255,255,0.03)',
                    },
                    border: { display: false },
                },
            },
        },
    });
}

function updateTrafficChart() {
    const now = new Date();
    state.trafficData.labels.push(formatTime(now));
    state.trafficData.inbound.push(rand(50, 220));
    state.trafficData.outbound.push(rand(30, 160));
    state.trafficData.anomaly.push(Math.random() < 0.08 ? rand(200, 380) : null);

    if (state.trafficData.labels.length > 61) {
        state.trafficData.labels.shift();
        state.trafficData.inbound.shift();
        state.trafficData.outbound.shift();
        state.trafficData.anomaly.shift();
    }

    trafficChart.data.labels = state.trafficData.labels;
    trafficChart.data.datasets[0].data = state.trafficData.inbound;
    trafficChart.data.datasets[1].data = state.trafficData.outbound;
    trafficChart.data.datasets[2].data = state.trafficData.anomaly;
    trafficChart.update('none');
}

// ── Protocol Chart ───────────────────────────
let protocolChart;
const protocolColors = ['#00f0ff', '#3b82f6', '#7c3aed', '#f59e0b', '#10b981', '#ff3366', '#ec4899', '#f97316', '#6366f1'];
const protocolData = [28, 18, 22, 14, 8, 4, 3, 2, 1];

function initProtocolChart() {
    const ctx = $('#protocol-chart').getContext('2d');

    protocolChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: PROTOCOLS,
            datasets: [{
                data: protocolData,
                backgroundColor: protocolColors.map(c => c + '33'),
                borderColor: protocolColors,
                borderWidth: 2,
                hoverBackgroundColor: protocolColors.map(c => c + '66'),
                hoverBorderWidth: 3,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '68%',
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(13, 17, 23, 0.95)',
                    borderColor: 'rgba(0, 240, 255, 0.15)',
                    borderWidth: 1,
                    titleColor: '#e2e8f0',
                    bodyColor: '#94a3b8',
                    titleFont: { family: "'JetBrains Mono'", size: 11 },
                    bodyFont: { family: "'JetBrains Mono'", size: 11 },
                    cornerRadius: 8,
                    callbacks: {
                        label: (c) => ` ${c.label}: ${c.parsed}%`,
                    },
                },
            },
        },
    });

    // Build legend
    const legend = $('#protocol-legend');
    PROTOCOLS.forEach((p, i) => {
        const item = document.createElement('div');
        item.className = 'legend-item';
        item.innerHTML = `<span class="legend-dot" style="background:${protocolColors[i]}"></span>${p} <span style="color:var(--text-muted);margin-left:2px">${protocolData[i]}%</span>`;
        legend.appendChild(item);
    });
}

// ── Severity Chart ───────────────────────────
let severityChart;

function initSeverityChart() {
    const ctx = $('#severity-chart').getContext('2d');

    severityChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: state.severityData,
                backgroundColor: [
                    'rgba(255, 51, 102, 0.25)',
                    'rgba(249, 115, 22, 0.25)',
                    'rgba(245, 158, 11, 0.25)',
                    'rgba(59, 130, 246, 0.25)',
                ],
                borderColor: ['#ff3366', '#f97316', '#f59e0b', '#3b82f6'],
                borderWidth: 2,
                borderRadius: 6,
                barPercentage: 0.6,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(13, 17, 23, 0.95)',
                    borderColor: 'rgba(0, 240, 255, 0.15)',
                    borderWidth: 1,
                    titleColor: '#e2e8f0',
                    bodyColor: '#94a3b8',
                    titleFont: { family: "'JetBrains Mono'", size: 11 },
                    bodyFont: { family: "'JetBrains Mono'", size: 11 },
                    cornerRadius: 8,
                },
            },
            scales: {
                x: {
                    ticks: {
                        color: '#64748b',
                        font: { family: "'JetBrains Mono'", size: 10 },
                    },
                    grid: { color: 'rgba(255,255,255,0.03)' },
                    border: { display: false },
                },
                y: {
                    ticks: {
                        color: '#94a3b8',
                        font: { family: "'Inter'", size: 11, weight: 600 },
                    },
                    grid: { display: false },
                    border: { display: false },
                },
            },
        },
    });
}

function updateSeverityChart() {
    state.severityData = state.severityData.map((v, i) => {
        const delta = i === 0 ? randInt(0, 2) : randInt(0, 4);
        return v + delta;
    });
    severityChart.data.datasets[0].data = state.severityData;
    severityChart.update('none');
}

// ── Threat Map (Canvas) ──────────────────────
let mapCanvas, mapCtx, mapW, mapH;

function initThreatMap() {
    mapCanvas = $('#threat-map');
    mapCtx = mapCanvas.getContext('2d');

    function resize() {
        const rect = mapCanvas.parentElement.getBoundingClientRect();
        mapW = mapCanvas.width = rect.width * window.devicePixelRatio;
        mapH = mapCanvas.height = rect.height * window.devicePixelRatio;
        mapCtx.scale(window.devicePixelRatio, window.devicePixelRatio);
    }
    resize();

    const resizeObserver = new ResizeObserver(() => {
        resize();
    });
    resizeObserver.observe(mapCanvas.parentElement);

    // Spawn initial attacks
    for (let i = 0; i < 5; i++) {
        spawnAttack();
    }

    drawMap();
}

function spawnAttack() {
    const origin = pick(GEO_ORIGINS);
    state.attackAnimations.push({
        ox: origin.x,
        oy: origin.y,
        tx: TARGET_LOC.x,
        ty: TARGET_LOC.y,
        progress: 0,
        speed: rand(0.003, 0.012),
        color: pick(['#ff3366', '#f97316', '#f59e0b', '#00f0ff']),
        name: origin.name,
        trail: [],
    });
}

function drawMap() {
    const w = mapW / window.devicePixelRatio;
    const h = mapH / window.devicePixelRatio;

    mapCtx.clearRect(0, 0, w, h);

    // Draw grid
    mapCtx.strokeStyle = 'rgba(0, 240, 255, 0.04)';
    mapCtx.lineWidth = 0.5;
    for (let x = 0; x < w; x += 40) {
        mapCtx.beginPath();
        mapCtx.moveTo(x, 0);
        mapCtx.lineTo(x, h);
        mapCtx.stroke();
    }
    for (let y = 0; y < h; y += 40) {
        mapCtx.beginPath();
        mapCtx.moveTo(0, y);
        mapCtx.lineTo(w, y);
        mapCtx.stroke();
    }

    // Draw simplified continents (dots pattern)
    drawWorldDots(w, h);

    // Draw target (pulsing)
    const tx = TARGET_LOC.x * w;
    const ty = TARGET_LOC.y * h;
    const pulseR = 6 + Math.sin(Date.now() / 400) * 3;

    mapCtx.beginPath();
    mapCtx.arc(tx, ty, pulseR + 10, 0, Math.PI * 2);
    mapCtx.fillStyle = 'rgba(0, 240, 255, 0.06)';
    mapCtx.fill();

    mapCtx.beginPath();
    mapCtx.arc(tx, ty, pulseR, 0, Math.PI * 2);
    mapCtx.fillStyle = 'rgba(0, 240, 255, 0.15)';
    mapCtx.fill();

    mapCtx.beginPath();
    mapCtx.arc(tx, ty, 3, 0, Math.PI * 2);
    mapCtx.fillStyle = '#00f0ff';
    mapCtx.fill();

    // Label
    mapCtx.font = '10px "JetBrains Mono"';
    mapCtx.fillStyle = 'rgba(0, 240, 255, 0.6)';
    mapCtx.fillText('HQ', tx + 10, ty + 4);

    // Draw attack animations
    state.attackAnimations.forEach((atk, idx) => {
        atk.progress += atk.speed;
        if (atk.progress >= 1) {
            // Impact flash
            mapCtx.beginPath();
            mapCtx.arc(tx, ty, 15, 0, Math.PI * 2);
            mapCtx.fillStyle = atk.color + '40';
            mapCtx.fill();
            state.attackAnimations.splice(idx, 1);
            return;
        }

        const ox = atk.ox * w;
        const oy = atk.oy * h;

        // Bezier curve
        const cpx = (ox + tx) / 2;
        const cpy = Math.min(oy, ty) - 40 - rand(0, 30);

        const t = atk.progress;
        const cx = (1 - t) * (1 - t) * ox + 2 * (1 - t) * t * cpx + t * t * tx;
        const cy = (1 - t) * (1 - t) * oy + 2 * (1 - t) * t * cpy + t * t * ty;

        // Trail
        atk.trail.push({ x: cx, y: cy });
        if (atk.trail.length > 20) atk.trail.shift();

        // Draw trail
        if (atk.trail.length > 1) {
            for (let i = 1; i < atk.trail.length; i++) {
                const alpha = (i / atk.trail.length) * 0.6;
                mapCtx.beginPath();
                mapCtx.moveTo(atk.trail[i - 1].x, atk.trail[i - 1].y);
                mapCtx.lineTo(atk.trail[i].x, atk.trail[i].y);
                mapCtx.strokeStyle = atk.color + Math.round(alpha * 255).toString(16).padStart(2, '0');
                mapCtx.lineWidth = 1.5;
                mapCtx.stroke();
            }
        }

        // Draw head
        mapCtx.beginPath();
        mapCtx.arc(cx, cy, 3, 0, Math.PI * 2);
        mapCtx.fillStyle = atk.color;
        mapCtx.shadowColor = atk.color;
        mapCtx.shadowBlur = 8;
        mapCtx.fill();
        mapCtx.shadowBlur = 0;

        // Origin dot
        mapCtx.beginPath();
        mapCtx.arc(ox, oy, 2.5, 0, Math.PI * 2);
        mapCtx.fillStyle = atk.color + '80';
        mapCtx.fill();

        // Origin label
        mapCtx.font = '9px "JetBrains Mono"';
        mapCtx.fillStyle = atk.color + 'aa';
        mapCtx.fillText(atk.name, ox + 6, oy - 4);
    });

    // Spawn new attacks
    if (Math.random() < 0.03) spawnAttack();

    requestAnimationFrame(drawMap);
}

// Simplified world map using dots
function drawWorldDots(w, h) {
    // A rough dot-matrix representation of continents
    const continents = [
        // North America
        ...generateDots(0.10, 0.18, 0.28, 0.42, 50),
        // South America
        ...generateDots(0.25, 0.52, 0.38, 0.82, 35),
        // Europe
        ...generateDots(0.45, 0.15, 0.58, 0.35, 35),
        // Africa
        ...generateDots(0.45, 0.38, 0.58, 0.72, 45),
        // Asia
        ...generateDots(0.58, 0.15, 0.88, 0.48, 70),
        // Australia
        ...generateDots(0.80, 0.60, 0.92, 0.72, 20),
    ];

    mapCtx.fillStyle = 'rgba(0, 240, 255, 0.08)';
    continents.forEach(({ x, y }) => {
        mapCtx.beginPath();
        mapCtx.arc(x * w, y * h, 1.2, 0, Math.PI * 2);
        mapCtx.fill();
    });
}

function generateDots(x1, y1, x2, y2, count) {
    const dots = [];
    for (let i = 0; i < count; i++) {
        dots.push({ x: rand(x1, x2), y: rand(y1, y2) });
    }
    return dots;
}

// ── Log Feed ─────────────────────────────────
let currentFilter = 'all';

function addLogEntry() {
    const severity = pick(Math.random() < 0.06 ? ['critical'] : Math.random() < 0.2 ? ['warning'] : Math.random() < 0.7 ? ['info'] : ['success']);
    const messages = LOG_MESSAGES[severity];
    let message = pick(messages).replace('{ip}', randomIP());
    message = message.replace(/<hl>/g, '<span class="highlight">').replace(/<\/hl>/g, '</span>');

    const now = new Date();
    const entry = document.createElement('div');
    entry.className = `log-entry ${severity}`;
    entry.dataset.severity = severity;
    entry.innerHTML = `
        <span class="log-time">${formatTime(now)}</span>
        <span class="log-severity ${severity}">${severity === 'success' ? 'OK' : severity.slice(0, 4).toUpperCase()}</span>
        <span class="log-message">${message}</span>
    `;

    const feed = $('#log-feed');
    feed.insertBefore(entry, feed.firstChild);

    // Limit entries
    while (feed.children.length > 80) {
        feed.removeChild(feed.lastChild);
    }

    applyLogFilter();

    // Create alert for critical events
    if (severity === 'critical') {
        addAlert(message.replace(/<[^>]*>/g, ''));
    }
}

function applyLogFilter() {
    const entries = $$('.log-entry');
    entries.forEach((el) => {
        if (currentFilter === 'all' || el.dataset.severity === currentFilter) {
            el.style.display = '';
        } else {
            el.style.display = 'none';
        }
    });
}

// Filter chips for logs
document.addEventListener('click', (e) => {
    if (e.target.matches('#card-logs .chip')) {
        $$('#card-logs .chip').forEach(c => c.classList.remove('active'));
        e.target.classList.add('active');
        currentFilter = e.target.dataset.filter;
        applyLogFilter();
    }
});

// ── Alerts ───────────────────────────────────
function addAlert(message) {
    const now = new Date();
    const alert = {
        title: pick(['Intrusion Detected', 'Anomaly Alert', 'Security Breach', 'Critical Event']),
        desc: message,
        time: formatTime(now),
        type: Math.random() < 0.7 ? 'critical' : 'warning',
    };
    state.alerts.unshift(alert);
    if (state.alerts.length > 30) state.alerts.pop();

    $('#alert-badge').textContent = Math.min(state.alerts.length, 99);

    // Update drawer if open
    renderAlerts();
}

function renderAlerts() {
    const container = $('#drawer-alerts');
    container.innerHTML = state.alerts.map(a => `
        <div class="alert-item ${a.type === 'warning' ? 'warning' : ''}">
            <div class="alert-title">${a.title}</div>
            <div class="alert-desc">${a.desc}</div>
            <div class="alert-time">${a.time}</div>
        </div>
    `).join('');
}

// Drawer toggle
$('#btn-alerts').addEventListener('click', () => {
    $('#alert-drawer').classList.add('open');
    $('#drawer-overlay').classList.add('open');
});

$('#btn-close-drawer').addEventListener('click', closeDrawer);
$('#drawer-overlay').addEventListener('click', closeDrawer);

function closeDrawer() {
    $('#alert-drawer').classList.remove('open');
    $('#drawer-overlay').classList.remove('open');
}

// ── Threats Table ────────────────────────────
function generateThreat() {
    return {
        severity: pick(SEVERITIES),
        type: pick(ATTACK_TYPES),
        source: randomIP(),
        target: pick(TARGETS),
        protocol: pick(PROTOCOLS),
        time: formatTime(new Date()),
        status: pick(STATUSES),
    };
}

function updateThreatsTable() {
    // Add new threat
    state.threats.unshift(generateThreat());
    if (state.threats.length > 15) state.threats.pop();

    const tbody = $('#threats-tbody');
    tbody.innerHTML = state.threats.map((t) => `
        <tr>
            <td><span class="severity-badge ${t.severity}">${t.severity}</span></td>
            <td>${t.type}</td>
            <td style="color:var(--cyan)">${t.source}</td>
            <td>${t.target}</td>
            <td>${t.protocol}</td>
            <td>${t.time}</td>
            <td><span class="status-badge ${t.status}">${t.status}</span></td>
        </tr>
    `).join('');

    const activeCount = state.threats.filter(t => t.status !== 'mitigated').length;
    $('#active-threat-count').textContent = `${activeCount} active`;
}

// ── Ports ────────────────────────────────────
function updatePorts() {
    state.portCounts = state.portCounts.map(c => c + randInt(0, 15));
    const maxCount = Math.max(...state.portCounts);

    const container = $('#ports-list');
    container.innerHTML = PORT_DATA.map((p, i) => {
        const pct = (state.portCounts[i] / maxCount * 100).toFixed(0);
        return `
            <div class="port-item">
                <span class="port-number">:${p.port}</span>
                <span class="port-name">${p.name}</span>
                <div class="port-bar-bg">
                    <div class="port-bar-fill" style="width:${pct}%;background:${p.color};box-shadow:0 0 6px ${p.color}44"></div>
                </div>
                <span class="port-count">${state.portCounts[i].toLocaleString()}</span>
            </div>
        `;
    }).join('');
}

// ── Traffic range chips ──────────────────────
document.addEventListener('click', (e) => {
    if (e.target.matches('#card-traffic .chip')) {
        $$('#card-traffic .chip').forEach(c => c.classList.remove('active'));
        e.target.classList.add('active');
    }
});

// ── Real Data Loading ────────────────────────
let realData = null;

async function loadRealData() {
    // Try multiple possible paths for dashboard_data.json
    const paths = [
        '../data/results/dashboard_data.json',
        'dashboard_data.json',
        '../dashboard_data.json',
    ];

    for (const path of paths) {
        try {
            const resp = await fetch(path);
            if (resp.ok) {
                realData = await resp.json();
                console.log('✓ Real pipeline data loaded from:', path);
                return true;
            }
        } catch (e) {
            // Continue trying other paths
        }
    }
    console.log('ℹ No pipeline data found — running in simulation mode');
    return false;
}

function applyRealData() {
    if (!realData) return;

    // Apply summary stats
    const s = realData.summary || {};
    if (s.total_events) {
        state.totalEvents = s.total_events;
        animateValue($('#total-events'), s.total_events);
    }
    if (s.total_anomalies) {
        state.totalAnomalies = s.total_anomalies;
        animateValue($('#total-anomalies'), s.total_anomalies);
    }
    if (s.blocked_ips) {
        state.blockedIPs = s.blocked_ips;
        animateValue($('#blocked-ips'), s.blocked_ips);
    }
    if (s.bandwidth) {
        state.bandwidth = s.bandwidth;
        $('#bandwidth').textContent = s.bandwidth;
    }
    if (s.attack_ratio) {
        const ratio = s.attack_ratio;
        $('#events-trend').textContent = `${ratio.toFixed(1)}% attacks`;
        $('#events-trend').className = 'stat-trend up danger';
    }

    // Apply threat level based on attack ratio
    if (s.attack_ratio) {
        const fill = $('#threat-fill');
        const value = $('#threat-value');
        const container = $('#threat-level-widget');
        const level = Math.min(s.attack_ratio * 2, 100);
        fill.style.width = level + '%';
        if (level >= 40) {
            value.textContent = 'HIGH';
            value.style.color = '#f97316';
            container.style.borderColor = 'rgba(249, 115, 22, 0.2)';
            container.style.background = 'rgba(249, 115, 22, 0.06)';
        }
    }

    // Apply protocol/attack distribution to doughnut chart
    const protDist = realData.protocol_distribution;
    if (protDist && protocolChart) {
        const labels = Object.keys(protDist);
        const data = labels.map(l => protDist[l].percentage || 0);
        protocolChart.data.labels = labels;
        protocolChart.data.datasets[0].data = data;
        protocolChart.data.datasets[0].backgroundColor = protocolColors.slice(0, labels.length).map(c => c + '33');
        protocolChart.data.datasets[0].borderColor = protocolColors.slice(0, labels.length);
        protocolChart.data.datasets[0].hoverBackgroundColor = protocolColors.slice(0, labels.length).map(c => c + '66');
        protocolChart.update('none');

        // Rebuild legend
        const legend = $('#protocol-legend');
        legend.innerHTML = '';
        labels.forEach((l, i) => {
            const item = document.createElement('div');
            item.className = 'legend-item';
            const color = protocolColors[i % protocolColors.length];
            item.innerHTML = `<span class="legend-dot" style="background:${color}"></span>${l} <span style="color:var(--text-muted);margin-left:2px">${data[i].toFixed(1)}%</span>`;
            legend.appendChild(item);
        });
    }

    // Apply severity breakdown
    const sevBreakdown = realData.severity_breakdown;
    if (sevBreakdown && severityChart) {
        const sevOrder = ['critical', 'high', 'medium', 'low'];
        const sevData = sevOrder.map(s => sevBreakdown[s] || 0);
        state.severityData = sevData;
        severityChart.data.datasets[0].data = sevData;
        severityChart.update('none');
    }

    // Apply threats table
    const threats = realData.top_threats;
    if (threats && threats.length > 0) {
        state.threats = threats.slice(0, 15).map(t => ({
            severity: t.severity || 'medium',
            type: t.type || 'Unknown',
            source: t.source_ip || randomIP(),
            target: t.target || pick(TARGETS),
            protocol: t.protocol || pick(PROTOCOLS),
            time: formatTime(new Date()),
            status: t.status || pick(STATUSES),
        }));
        updateThreatsTable();
    }

    // Apply port attacks
    const portAttacks = realData.port_attacks;
    if (portAttacks && portAttacks.length > 0) {
        const container = $('#ports-list');
        const maxCount = Math.max(...portAttacks.map(p => p.count));
        container.innerHTML = portAttacks.map(p => {
            const pct = (p.count / maxCount * 100).toFixed(0);
            const color = p.color || '#00f0ff';
            return `
                <div class="port-item">
                    <span class="port-number">:${p.port}</span>
                    <span class="port-name">${p.name}</span>
                    <div class="port-bar-bg">
                        <div class="port-bar-fill" style="width:${pct}%;background:${color};box-shadow:0 0 6px ${color}44"></div>
                    </div>
                    <span class="port-count">${p.count.toLocaleString()}</span>
                </div>
            `;
        }).join('');
    }

    // Apply model metrics as a log entry
    const metrics = realData.model_metrics;
    if (metrics) {
        const rf = metrics.random_forest || {};
        const ifo = metrics.isolation_forest || {};

        if (rf.accuracy) {
            const entry = document.createElement('div');
            entry.className = 'log-entry success';
            entry.dataset.severity = 'success';
            entry.innerHTML = `
                <span class="log-time">${formatTime(new Date())}</span>
                <span class="log-severity success">DATA</span>
                <span class="log-message">Pipeline results loaded — RF accuracy: <span class="highlight">${(rf.accuracy * 100).toFixed(1)}%</span>, F1: <span class="highlight">${(rf.f1_weighted * 100).toFixed(1)}%</span> | IF F1: <span class="highlight">${(ifo.f1_score * 100).toFixed(1)}%</span></span>
            `;
            const feed = $('#log-feed');
            feed.insertBefore(entry, feed.firstChild);
        }
    }

    // Add "REAL DATA" indicator to header
    const statusEl = $('#system-status');
    statusEl.textContent = 'Pipeline Data Active';
    statusEl.style.color = '#10b981';
}

// ── Initialization ───────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
    initParticles();
    updateClock();
    updateStats();
    updateThreatLevel();
    initTrafficChart();
    initProtocolChart();
    initSeverityChart();
    initThreatMap();
    updatePorts();

    // Initial threats
    for (let i = 0; i < 8; i++) {
        state.threats.push(generateThreat());
    }
    updateThreatsTable();

    // Initial logs
    for (let i = 0; i < 15; i++) {
        addLogEntry();
    }

    // Try loading real pipeline data
    const hasRealData = await loadRealData();
    if (hasRealData) {
        applyRealData();
    }

    // ── Update Intervals ──
    setInterval(updateClock, 1000);
    setInterval(updateStats, 3000);
    setInterval(updateThreatLevel, 8000);
    setInterval(updateTrafficChart, 2000);
    setInterval(updateSeverityChart, 5000);
    setInterval(addLogEntry, 1800);
    setInterval(updateThreatsTable, 4000);
    setInterval(updatePorts, 3000);

    // Protocol chart subtle update
    setInterval(() => {
        protocolChart.data.datasets[0].data = protocolChart.data.datasets[0].data.map(d => d + rand(-0.3, 0.3));
        protocolChart.update('none');
    }, 6000);
});
