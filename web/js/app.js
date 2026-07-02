// ZENIHT AI v15 - App con admin ZENIHT y usuarios limitados
const AI = window.zenihtAI;
const NET = window.networkMonitor;
let currentUser = null;
let isAdmin = false;

// ===== STORAGE =====
function getUsers() { return JSON.parse(localStorage.getItem('zh_users') || '{}'); }
function saveUsers(u) { localStorage.setItem('zh_users', JSON.stringify(u)); }
function getLogs() { return JSON.parse(localStorage.getItem('zh_logs') || '[]'); }
function saveLog(log) {
    const logs = getLogs();
    logs.push({ ...log, time: new Date().toISOString() });
    if (logs.length > 200) logs.splice(0, logs.length - 200);
    localStorage.setItem('zh_logs', JSON.stringify(logs));
}
function hash(s) { let h = 0; for (let i = 0; i < s.length; i++) { h = ((h << 5) - h) + s.charCodeAt(i); h |= 0; } return 'h' + Math.abs(h).toString(36); }

// ===== AUTH =====
function doLogin() {
    const user = document.getElementById('inpUser').value.trim();
    const pass = document.getElementById('inpPass').value;
    const msg = document.getElementById('authMsg');
    if (!user || !pass) { msg.textContent = 'Completa todos los campos'; return; }

    const users = getUsers();
    if (!users[user]) { msg.textContent = 'Usuario no registrado'; return; }
    if (users[user].password !== hash(pass + user)) { msg.textContent = 'Password incorrecto'; return; }

    currentUser = user;
    isAdmin = (user.toUpperCase() === 'ZENIHT');

    saveLog({ action: 'login', user, ip: 'browser', admin: isAdmin });

    if (isAdmin) {
        document.getElementById('authScreen').classList.remove('active');
        document.getElementById('adminScreen').classList.add('active');
        document.getElementById('adminInfo').textContent = `Admin | ${new Date().toLocaleDateString('es-AR')}`;
        NET.start();
        AI.buildModel();
        startAdminUI();
    } else {
        document.getElementById('authScreen').classList.remove('active');
        document.getElementById('userScreen').classList.add('active');
        document.getElementById('uName').textContent = user;
        document.getElementById('userInfo').textContent = `Usuario: ${user}`;
        NET.start();
        startUserUI();
    }
    msg.textContent = '';
}

function doRegister() {
    const user = document.getElementById('inpUser').value.trim();
    const pass = document.getElementById('inpPass').value;
    const msg = document.getElementById('authMsg');
    if (!user || !pass) { msg.textContent = 'Completa todos los campos'; return; }
    if (user.length < 3) { msg.textContent = 'Minimo 3 caracteres'; return; }
    if (pass.length < 4) { msg.textContent = 'Password: minimo 4 caracteres'; return; }
    if (user.toUpperCase() === 'ZENIHT') { msg.textContent = 'No podes registrar ZENIHT'; return; }

    const users = getUsers();
    if (users[user]) { msg.textContent = 'Usuario ya existe'; return; }

    users[user] = { password: hash(pass + user), created: Date.now(), level: 1 };
    saveUsers(users);

    saveLog({ action: 'register', user, ip: 'browser', by: currentUser || 'sistema' });
    msg.textContent = 'Cuenta creada! Ahora podes entrar.';
    msg.style.color = 'var(--ok)';
    setTimeout(() => { msg.style.color = ''; }, 3000);
}

function doLogout() {
    saveLog({ action: 'logout', user: currentUser });
    currentUser = null; isAdmin = false;
    NET.stop();
    ['adminScreen', 'userScreen'].forEach(id => document.getElementById(id).classList.remove('active'));
    document.getElementById('authScreen').classList.add('active');
}

// ===== ADMIN UI =====
let adminInterval = null;
function startAdminUI() {
    if (adminInterval) return;
    adminInterval = setInterval(updateAdminUI, 2000);
    updateAdminUI();
}

function updateAdminUI() {
    const stats = NET.getStats();
    const users = getUsers();
    const userCount = Object.keys(users).length;

    document.getElementById('aUsers').textContent = userCount;
    document.getElementById('aPackets').textContent = fmtN(stats.packets);
    document.getElementById('aAnomalies').textContent = stats.anomalies;
    document.getElementById('aHealth').textContent = stats.health;
    const hv = document.getElementById('aHealth');
    hv.className = 'sv ' + (stats.health >= 80 ? 'ok' : stats.health >= 50 ? 'warn' : 'danger');

    document.getElementById('adminInfo').textContent = `Admin | Paquetes: ${fmtN(stats.packets)} | IA: ${AI.trained ? 'Activa' : 'Esperando'}`;

    // Users list
    const ul = document.getElementById('adminUsersList');
    ul.innerHTML = Object.entries(users).map(([name, u]) => {
        const isAdminUser = name.toUpperCase() === 'ZENIHT';
        const created = new Date(u.created).toLocaleString('es-AR');
        return `<div class="li"><div><div class="li-ip">${name} ${isAdminUser ? '<span class="badge b-admin">ADMIN</span>' : '<span class="badge b-info">USER</span>'}</div><div class="li-sub">Creado: ${created}</div></div></div>`;
    }).join('') || '<div class="empty">Sin usuarios</div>';

    // Log list
    const logs = getLogs().slice(-20).reverse();
    const ll = document.getElementById('adminLogList');
    ll.innerHTML = logs.map(l => {
        const t = new Date(l.time).toLocaleTimeString('es-AR');
        const action = l.action === 'register' ? '<span class="badge b-info">REGISTRO</span>' : l.action === 'login' ? '<span class="badge b-ok">LOGIN</span>' : '<span class="badge b-warn">LOGOUT</span>';
        return `<div class="li"><div><div class="li-ip">${l.user || '?'} ${action}</div><div class="li-sub">${t} | IP: ${l.ip || 'N/A'}</div></div></div>`;
    }).join('') || '<div class="empty">Sin actividad</div>';

    // Hosts
    const hosts = NET.getHosts();
    const hl = document.getElementById('adminHostsList');
    hl.innerHTML = hosts.slice(0, 15).map(h => {
        const badge = h.threatScore > 30 ? 'b-danger' : h.threatScore > 10 ? 'b-warn' : 'b-ok';
        return `<div class="li"><div><div class="li-ip">${h.ip}</div><div class="li-sub">${h.deviceType} | ${h.country} | ${h.packets} paq | ${Array.from(h.ports || []).slice(0, 5).join(', ')}</div></div><span class="badge ${badge}">${h.threatScore.toFixed(1)}</span></div>`;
    }).join('') || '<div class="empty">Capturando trafico...</div>';

    // Flows
    const flows = NET.getFlows();
    const fl = document.getElementById('adminFlowsList');
    fl.innerHTML = flows.slice(0, 10).map(f =>
        `<div class="fl"><div>${f.src}<br><span style="color:var(--dim)">${f.sport}</span></div><div class="fl-a">&#10132;</div><div style="text-align:right">${f.dst}<br><span style="color:var(--dim)">${f.dport} | ${f.proto}</span></div></div>`
    ).join('') || '<div class="empty">Sin flujos</div>';

    // Events
    const events = NET.getEvents();
    const el = document.getElementById('adminEventsList');
    el.innerHTML = events.slice(0, 15).map(e => {
        const cls = e.severity === 'CRITICAL' ? 'ev-CRITICAL' : e.severity === 'SUSPICIOUS' ? 'ev-SUSPICIOUS' : 'ev-OK';
        return `<div class="ev"><span class="ev-t">${e.time}</span><span class="${cls}">[${e.severity || 'OK'}]</span><span>${e.src || ''} &#10132; ${e.dst || ''}</span><span style="color:var(--dim)">${e.msg || ''}</span></div>`;
    }).join('') || '<div class="empty">Sin eventos</div>';
}

// ===== USER UI =====
let userInterval = null;
function startUserUI() {
    if (userInterval) return;
    userInterval = setInterval(updateUserUI, 3000);
    updateUserUI();
}

function updateUserUI() {
    const stats = NET.getStats();
    document.getElementById('uMyIP').textContent = stats.myIP || 'Detectando...';
    document.getElementById('uGateway').textContent = stats.gateway || 'Detectando...';
    document.getElementById('uConn').textContent = stats.connType || 'Detectando...';
    document.getElementById('uPackets').textContent = fmtN(stats.packets);

    const logs = getLogs().filter(l => l.user === currentUser).slice(-10).reverse();
    const ll = document.getElementById('userLogList');
    ll.innerHTML = logs.map(l => {
        const t = new Date(l.time).toLocaleTimeString('es-AR');
        return `<div class="li"><div><div class="li-ip">${l.action}</div><div class="li-sub">${t}</div></div></div>`;
    }).join('') || '<div class="empty">Sin actividad</div>';
}

// ===== USER ACTIONS =====
async function userTrainAI() {
    const btn = event.target; btn.disabled = true; btn.textContent = 'ENTRENANDO...';
    try {
        const r = await AI.train((epoch, loss) => {
            document.getElementById('uEpoch').textContent = epoch;
            document.getElementById('uLoss').textContent = loss.toFixed(6);
            document.getElementById('uTrainProgress').style.width = Math.min(100, (epoch / 50) * 100) + '%';
        });
        if (r.error) { alert(r.error); } else {
            document.getElementById('uThreshold').textContent = r.threshold.toFixed(6);
            saveLog({ action: 'entrenar_ia', user: currentUser, result: `OK: ${r.samples} muestras, umbral: ${r.threshold.toFixed(6)}` });
        }
    } catch(e) { alert('Error: ' + e.message); }
    btn.disabled = false; btn.textContent = 'ENTRENAR IA';
}

// ===== ADMIN: AI CONTROLS =====
async function startTraining() {
    const btn = event.target; btn.disabled = true; btn.textContent = 'ENTRENANDO...';
    try {
        const r = await AI.train((epoch, loss) => {
            document.getElementById('aEpoch').textContent = epoch;
            document.getElementById('aLoss').textContent = loss.toFixed(6);
            document.getElementById('aProgress').style.width = Math.min(100, (epoch / 50) * 100) + '%';
        });
        if (r.error) { alert(r.error); } else {
            document.getElementById('aThreshold').textContent = r.threshold.toFixed(6);
            NET.addEvent({ type: 'ai', severity: 'OK', src: 'IA', dst: 'Modelo', msg: `Entrenado: ${r.samples} muestras, umbral: ${r.threshold.toFixed(6)}` });
        }
    } catch(e) { alert('Error: ' + e.message); }
    btn.disabled = false; btn.textContent = 'ENTRENAR';
}

async function saveModelGithub() {
    const owner = prompt('GitHub username:'); if (!owner) return;
    const repo = prompt('Nombre del repo:'); if (!repo) return;
    const token = prompt('GitHub token:'); if (!token) return;
    const data = { ...AI.getJSON(), weights: AI.getWeightsB64(), saved_at: new Date().toISOString(), saved_by: currentUser };
    try {
        const url = `https://api.github.com/repos/${owner}/${repo}/contents/models/zeniht_model.json`;
        let sha = null;
        try { const e = await fetch(url); if (e.ok) { const j = await e.json(); sha = j.sha; } } catch(e) {}
        const body = { message: `ZENIHT model ${new Date().toISOString()}`, content: btoa(unescape(encodeURIComponent(JSON.stringify(data)))) };
        if (sha) body.sha = sha;
        const res = await fetch(url, { method: 'PUT', headers: { 'Authorization': `token ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        if (res.ok) { alert('Modelo guardado en GitHub!'); NET.addEvent({ type: 'save', severity: 'OK', src: 'IA', dst: `github.com/${owner}/${repo}`, msg: 'Modelo guardado' }); }
        else { const err = await res.json(); alert('Error: ' + err.message); }
    } catch(e) { alert('Error: ' + e.message); }
}

async function loadModelGithub() {
    const owner = prompt('GitHub username:'); if (!owner) return;
    const repo = prompt('Nombre del repo:'); if (!repo) return;
    try {
        const url = `https://api.github.com/repos/${owner}/${repo}/contents/models/zeniht_model.json`;
        const res = await fetch(url);
        if (!res.ok) throw new Error('No encontrado');
        const json = await res.json();
        const content = decodeURIComponent(escape(atob(json.content)));
        const data = JSON.parse(content);
        await AI.loadJSON(data, data.weights);
        document.getElementById('aEpoch').textContent = AI.epoch;
        document.getElementById('aThreshold').textContent = AI.threshold?.toFixed(6) || '-';
        alert('Modelo cargado de GitHub!');
        NET.addEvent({ type: 'load', severity: 'OK', src: `github`, dst: 'IA', msg: 'Modelo cargado' });
    } catch(e) { alert('Error: ' + e.message); }
}

// ===== ADMIN: SCAN =====
async function doScan() {
    const target = document.getElementById('scanTarget').value.trim();
    const type = document.getElementById('scanType').value;
    const el = document.getElementById('scanResults');
    if (!target) { el.innerHTML = '<div class="empty">Ingresa una IP o subred</div>'; return; }
    el.innerHTML = `<div class="sr">Escaneando ${target}...</div>`;

    if (type === 'trace') {
        const r = await NET.traceRoute(target);
        el.innerHTML = `<div class="sr"><b>Traceroute a ${r.target}</b></div>` + r.hops.map(h => `<div class="sr">${h.hop}. ${h.ip} - ${h.ms}ms</div>`).join('');
    } else {
        const r = await NET.scanNetwork(target, type);
        el.innerHTML = `<div class="sr"><b>${r.type} de ${r.target}</b> - ${r.hosts.length} hosts</div>` +
            r.hosts.map(h => `<div class="sr">${h.ip} - ${h.alive ? '🟢' : '🔴'} - ${h.ms ? h.ms + 'ms' : 'N/A'} - Puertos: ${h.openPorts.join(', ') || 'ninguno'}</div>`).join('');
    }
}

// ===== TABS =====
document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    document.getElementById('panel-' + t.dataset.tab)?.classList.add('active');
}));

function fmtN(n) { return n >= 1000000 ? (n / 1000000).toFixed(1) + 'M' : n >= 1000 ? (n / 1000).toFixed(1) + 'K' : n; }

// ===== INIT =====
window.addEventListener('load', () => {
    // Pre-crear admin ZENIHT si no existe
    const users = getUsers();
    if (!users['ZENIHT']) {
        users['ZENIHT'] = { password: hash('admin123ZENIHT'), created: Date.now(), level: 10, isRealAdmin: true };
        saveUsers(users);
    }
    document.getElementById('inpPass').addEventListener('keypress', e => { if (e.key === 'Enter') doLogin(); });
    document.getElementById('inpUser').addEventListener('keypress', e => { if (e.key === 'Enter') document.getElementById('inpPass').focus(); });
});
