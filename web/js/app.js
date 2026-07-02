// ZENIHT AI - App principal con botones funcionando
let currentUser = null;
let token = null;
const AI = window.zenihtAI;
const NET = window.networkMonitor;

// ===== AUTH =====
function doLogin() {
    const user = document.getElementById('authUser').value.trim();
    const pass = document.getElementById('authPass').value;
    const err = document.getElementById('authError');

    if (!user || !pass) { err.textContent = 'Completa todos los campos'; return; }

    const users = JSON.parse(localStorage.getItem('zeniht_users') || '{}');
    if (!users[user]) { err.textContent = 'Usuario no registrado'; return; }

    const hash = simpleHash(pass + user);
    if (users[user].password !== hash) { err.textContent = 'Password incorrecto'; return; }

    currentUser = users[user];
    currentUser.username = user;
    token = btoa(user + ':' + Date.now());
    localStorage.setItem('zeniht_token', token);
    err.textContent = '';
    showDashboard();
}

function doRegister() {
    const user = document.getElementById('authUser').value.trim();
    const pass = document.getElementById('authPass').value;
    const err = document.getElementById('authError');

    if (!user || !pass) { err.textContent = 'Completa todos los campos'; return; }
    if (user.length < 3) { err.textContent = 'Usuario: minimo 3 caracteres'; return; }
    if (pass.length < 4) { err.textContent = 'Password: minimo 4 caracteres'; return; }

    const users = JSON.parse(localStorage.getItem('zeniht_users') || '{}');
    if (users[user]) { err.textContent = 'Usuario ya existe'; return; }

    users[user] = {
        password: simpleHash(pass + user),
        created: Date.now(),
        packets_analyzed: 0,
        threats_found: 0,
        level: 1,
        xp: 0
    };
    localStorage.setItem('zeniht_users', JSON.stringify(users));

    currentUser = users[user];
    currentUser.username = user;
    token = btoa(user + ':' + Date.now());
    localStorage.setItem('zeniht_token', token);
    err.textContent = '';
    showDashboard();
}

function doLogout() {
    localStorage.removeItem('zeniht_token');
    currentUser = null;
    token = null;
    NET.stop();
    document.getElementById('dashboardScreen').classList.remove('active');
    document.getElementById('authScreen').classList.add('active');
}

function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash |= 0;
    }
    return 'h_' + Math.abs(hash).toString(36);
}

function showDashboard() {
    document.getElementById('authScreen').classList.remove('active');
    document.getElementById('dashboardScreen').classList.add('active');
    document.getElementById('headerStatus').textContent = 'Usuario: ' + currentUser.username;
    NET.start();
    AI.buildModel();
    startUIUpdate();
}

// ===== UI UPDATE =====
let uiInterval = null;
function startUIUpdate() {
    if (uiInterval) return;
    uiInterval = setInterval(updateUI, 1500);
    updateUI();
}

function updateUI() {
    const stats = NET.getStats();
    document.getElementById('sPackets').textContent = formatNum(stats.packets);
    document.getElementById('sAnomalies').textContent = stats.anomalies;
    document.getElementById('sCritical').textContent = stats.critical;
    document.getElementById('sHealth').textContent = stats.health;

    const healthEl = document.getElementById('sHealth');
    healthEl.className = 'stat-val ' + (stats.health >= 80 ? 'ok' : stats.health >= 50 ? 'warn' : 'danger');

    const sev = AI.trained ? getThreatName(stats) : 'SAFE';
    const badge = document.getElementById('threatBadge');
    badge.textContent = sev;
    badge.className = 'threat-badge threat-' + sev;

    document.getElementById('headerStatus').textContent =
        AI.trained ? `IA activa | ${stats.packets} paq | Umbral: ${AI.threshold ? AI.threshold.toFixed(4) : '-'}` : `Capturando... ${stats.packets} paquetes`;

    renderHosts();
    renderFlows();
    renderEvents();
}

function getThreatName(stats) {
    if (stats.critical > 0) return 'CRITICAL';
    if (stats.anomalies > 10) return 'HIGH';
    if (stats.anomalies > 3) return 'MEDIUM';
    if (stats.anomalies > 0) return 'LOW';
    return 'SAFE';
}

function formatNum(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
    return n;
}

// ===== RENDER =====
function renderHosts() {
    const hosts = NET.getHosts();
    const el = document.getElementById('hostsList');
    if (!hosts.length) { el.innerHTML = '<div class="empty">Capturando trafico de red...</div>'; return; }

    el.innerHTML = hosts.slice(0, 15).map(h => {
        const badge = h.threatScore > 30 ? 'badge-danger' : h.threatScore > 10 ? 'badge-warn' : 'badge-ok';
        return `<div class="list-item">
            <div><div class="list-ip">${h.ip}</div>
            <div class="list-info"><span>${h.deviceType}</span><span>${h.country}</span></div></div>
            <div style="text-align:right"><div class="badge ${badge}">${h.threatScore.toFixed(1)}</div>
            <div class="list-info"><span>${h.packets} paq</span></div></div></div>`;
    }).join('');
}

function renderFlows() {
    const flows = NET.getFlows();
    const el = document.getElementById('flowsList');
    if (!flows.length) { el.innerHTML = '<div class="empty">Sin flujos activos</div>'; return; }

    el.innerHTML = flows.slice(0, 15).map(f =>
        `<div class="flow-row"><div><div class="list-ip">${f.src}</div><div class="list-info">${f.sport || '?'}</div></div>
        <div class="flow-arrow">&#10132;</div>
        <div style="text-align:right"><div class="list-ip">${f.dst}</div><div class="list-info">${f.dport} | ${f.proto}</div></div></div>`
    ).join('');
}

function renderEvents() {
    const events = NET.getEvents();
    const el = document.getElementById('eventsList');
    if (!events.length) { el.innerHTML = '<div class="empty">Sin eventos aun</div>'; return; }

    el.innerHTML = events.slice(0, 20).map(e => {
        const cls = e.severity === 'CRITICAL' ? 'event-CRITICAL' : e.severity === 'SUSPICIOUS' ? 'event-SUSPICIOUS' : 'event-OK';
        return `<div class="event-row"><span class="event-time">${e.time || ''}</span>
        <span class="${cls}">[${e.severity || 'OK'}]</span>
        <span>${e.src || ''} &#10132; ${e.dst || ''}</span></div>`;
    }).join('');
}

// ===== TABS =====
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById('panel-' + tab.dataset.tab).classList.add('active');
    });
});

// ===== AI CONTROLS =====
function updateAIStatus(epoch, loss, threshold) {
    document.getElementById('aiEpoch').textContent = epoch;
    document.getElementById('aiLoss').textContent = typeof loss === 'number' ? loss.toFixed(6) : loss;
    document.getElementById('aiThreshold').textContent = AI.threshold ? AI.threshold.toFixed(6) : '-';
    document.getElementById('aiProgress').style.width = Math.min(100, (epoch / 30) * 100) + '%';
}

async function startTraining() {
    const btn = event.target;
    btn.disabled = true;
    btn.textContent = 'Entrenando...';
    updateAIStatus(AI.epoch, 'entrenando...', '-');

    try {
        const result = await AI.train();
        if (result.error) {
            updateAIStatus(AI.epoch, result.error, '-');
        } else {
            updateAIStatus(result.epochs, result.finalLoss, result.threshold);
            NET.addEvent({
                type: 'ai_train', severity: 'OK',
                src: 'IA', dst: 'Modelo',
                time: new Date().toLocaleTimeString('es-AR')
            });
        }
    } catch(e) {
        updateAIStatus(AI.epoch, 'Error: ' + e.message, '-');
    }

    btn.disabled = false;
    btn.textContent = 'Entrenar';
}

async function saveModelGithub() {
    const owner = prompt('GitHub username (owner del repo):');
    if (!owner) return;
    const repo = prompt('Nombre del repo (debe existir):');
    if (!repo) return;
    const token = prompt('GitHub Personal Access Token:');
    if (!token) return;

    const data = {
        ...AI.getModelJSON(),
        weights: AI.getWeightsBase64(),
        saved_at: new Date().toISOString(),
        saved_by: currentUser ? currentUser.username : 'unknown'
    };

    const btn = event.target;
    btn.disabled = true;
    btn.textContent = 'Guardando...';

    try {
        const url = `https://api.github.com/repos/${owner}/${repo}/contents/models/zeniht_model.json`;
        let sha = null;
        try {
            const existing = await fetch(url);
            if (existing.ok) {
                const json = await existing.json();
                sha = json.sha;
            }
        } catch(e) {}

        const body = {
            message: `ZENIHT AI model update - ${new Date().toISOString()}`,
            content: btoa(unescape(encodeURIComponent(JSON.stringify(data, null, 2))))
        };
        if (sha) body.sha = sha;

        const res = await fetch(url, {
            method: 'PUT',
            headers: { 'Authorization': `token ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (res.ok) {
            alert('Modelo guardado en GitHub! 🎉');
            NET.addEvent({ type: 'model_save', severity: 'OK', src: 'IA', dst: `github.com/${owner}/${repo}`, time: new Date().toLocaleTimeString('es-AR') });
        } else {
            const err = await res.json();
            alert('Error: ' + (err.message || 'No se pudo guardar'));
        }
    } catch(e) {
        alert('Error de conexion: ' + e.message);
    }

    btn.disabled = false;
    btn.textContent = 'Guardar en GitHub';
}

async function loadModelGithub() {
    const owner = prompt('GitHub username (owner del repo):');
    if (!owner) return;
    const repo = prompt('Nombre del repo:');
    if (!repo) return;

    const btn = event.target;
    btn.disabled = true;
    btn.textContent = 'Cargando...';

    try {
        const url = `https://api.github.com/repos/${owner}/${repo}/contents/models/zeniht_model.json`;
        const res = await fetch(url);
        if (!res.ok) throw new Error('No encontrado');

        const json = await res.json();
        const content = decodeURIComponent(escape(atob(json.content)));
        const data = JSON.parse(content);

        await AI.loadModel(data, data.weights);
        updateAIStatus(AI.epoch, 'Cargado', AI.threshold);
        alert('Modelo cargado de GitHub! 🎉');
        NET.addEvent({ type: 'model_load', severity: 'OK', src: `github.com/${owner}/${repo}`, dst: 'IA', time: new Date().toLocaleTimeString('es-AR') });
    } catch(e) {
        alert('Error: ' + e.message);
    }

    btn.disabled = false;
    btn.textContent = 'Cargar de GitHub';
}

// ===== SCAN =====
async function startScan() {
    const target = document.getElementById('scanTarget').value.trim();
    const type = document.getElementById('scanType').value;
    const resultsEl = document.getElementById('scanResults');

    if (!target) { resultsEl.innerHTML = '<div class="empty">Ingresa una IP o subred</div>'; return; }

    resultsEl.innerHTML = '<div class="empty">Escaneando ' + target + '...</div>';

    if (type === 'trace') {
        const result = await NET.traceRoute(target);
        resultsEl.innerHTML = `<div class="scan-result"><b>Traceroute a ${result.target}</b></div>` +
            result.hops.map(h => `<div class="scan-result">${h.hop}. ${h.ip} - ${h.ms}ms</div>`).join('');
    } else {
        const result = await NET.scanNetwork(target, type);
        resultsEl.innerHTML = `<div class="scan-result"><b>Escaneo ${result.type} de ${result.target}</b> - ${result.hosts.length} hosts encontrados</div>` +
            result.hosts.map(h =>
                `<div class="scan-result">${h.ip} - ${h.alive ? '🟢 Activo' : '🔴 Inactivo'} - Latencia: ${h.latency ? h.latency + 'ms' : 'N/A'} - Puertos: ${h.openPorts.join(', ') || 'ninguno'}</div>`
            ).join('');
    }

    NET.addEvent({ type: 'scan', severity: 'OK', src: 'Usuario', dst: target, time: new Date().toLocaleTimeString('es-AR') });
}

// ===== INIT =====
window.addEventListener('load', () => {
    const savedToken = localStorage.getItem('zeniht_token');
    if (savedToken) {
        const users = JSON.parse(localStorage.getItem('zeniht_users') || '{}');
        const username = atob(savedToken).split(':')[0];
        if (users[username]) {
            currentUser = users[username];
            currentUser.username = username;
            token = savedToken;
            showDashboard();
        }
    }

    document.getElementById('authPass').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') doLogin();
    });
    document.getElementById('authUser').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') document.getElementById('authPass').focus();
    });
});
