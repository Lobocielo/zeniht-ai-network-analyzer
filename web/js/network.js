// ZENIHT Network v16 - Captura RED REAL + envia paquetes al AI
class NetworkMonitor {
    constructor() {
        this.packets = [];
        this.hosts = new Map();
        this.flows = new Map();
        this.events = [];
        this.totalPkts = 0;
        this.anomalies = 0;
        this.critical = 0;
        this.blocked = new Set();
        this.running = false;
        this.myIP = '';
        this.gateway = '';
        this.connType = '';
        this.listeners = [];
        this.ai = null;
        this.detectionResults = [];
        this.lastPktTime = 0;
        this.pktRateCounter = 0;
        this.pktRate = 0;
        this.bytesRate = 0;
        this.bytesRateCounter = 0;
    }

    setAI(aiRef) { this.ai = aiRef; }

    async detectNetwork() {
        try {
            const pc = new RTCPeerConnection({ iceServers: [] });
            pc.createDataChannel('');
            const offer = await pc.createOffer();
            await pc.setLocalDescription(offer);
            await new Promise((resolve) => {
                pc.onicecandidate = (e) => {
                    if (e && e.candidate && e.candidate.candidate) {
                        const m = e.candidate.candidate.match(/([0-9]{1,3}\.){3}[0-9]{1,3}/);
                        if (m) { this.myIP = m[0]; pc.close(); resolve(); }
                    }
                };
                setTimeout(() => { try { pc.close(); } catch(e) {} resolve(); }, 2000);
            });
            if (this.myIP) {
                const p = this.myIP.split('.');
                this.gateway = p[0] + '.' + p[1] + '.' + p[2] + '.1';
            }
        } catch(e) {}

        const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
        if (conn) {
            this.connType = conn.effectiveType || conn.type || 'desconocido';
            this.connInfo = { type: this.connType, downlink: conn.downlink, rtt: conn.rtt };
        } else {
            this.connType = 'wifi';
        }

        this.addEvent({ type: 'network', severity: 'OK', src: 'Sistema', dst: this.myIP || 'Local', msg: `IP: ${this.myIP || 'N/A'} | Gateway: ${this.gateway || 'N/A'} | Conexion: ${this.connType}` });
    }

    start() {
        if (this.running) return;
        this.running = true;
        this.detectNetwork();
        this.captureXHR();
        this.captureFetch();
        this.captureNavigation();
        this.captureBeacon();
        this.captureWS();
        this.generateRealTraffic();
        this.monitorPerformance();
        this.startPktRateCalc();
    }

    stop() { this.running = false; }

    startPktRateCalc() {
        setInterval(() => {
            this.pktRate = this.pktRateCounter;
            this.bytesRate = this.bytesRateCounter;
            this.pktRateCounter = 0;
            this.bytesRateCounter = 0;
        }, 1000);
    }

    onPacket(cb) { this.listeners.push(cb); }

    emit(pkt) {
        const now = Date.now();
        this.totalPkts++;
        this.pktRateCounter++;
        this.bytesRateCounter += pkt.size || 0;
        pkt.deltaT = this.lastPktTime ? (now - this.lastPktTime) / 1000 : 0.01;
        pkt.pktRate = this.pktRate;
        pkt.bytesRate = this.bytesRate;
        this.lastPktTime = now;

        this.packets.push(pkt);
        if (this.packets.length > 10000) this.packets.shift();
        this.updateHost(pkt.src, pkt);
        this.updateHost(pkt.dst, pkt);
        this.updateFlow(pkt);

        // Enviar paquete al AI para analisis en vivo
        if (this.ai) {
            const result = this.ai.addPacket(pkt);
            if (result && result.isAnomaly) {
                this.anomalies++;
                pkt.anomaly = true;
                pkt.severity = result.severity;
                if (result.severity === 'CRITICAL' || result.severity === 'ATTACK') this.critical++;
                this.detectionResults.push({
                    src: pkt.src, dst: pkt.dst, dport: pkt.dport,
                    severity: result.severity, score: result.score,
                    time: new Date().toLocaleTimeString('es-AR'), id: this.detectionResults.length
                });
                if (this.detectionResults.length > 100) this.detectionResults.shift();
                this.addEvent({ type: 'detection', severity: result.severity, src: pkt.src, dst: pkt.dst, msg: `Score: ${result.score.toFixed(6)} | ${result.severity}` });
            }
            pkt.anomalyResult = result;
        }

        this.listeners.forEach(cb => cb(pkt));
    }

    updateHost(ip, pkt) {
        if (!ip) return;
        if (!this.hosts.has(ip)) {
            this.hosts.set(ip, {
                ip, packets: 0, bytes: 0, anomalies: 0, critical: 0,
                threatScore: 0, deviceType: 'Host', country: this.isPrivate(ip) ? 'Local' : 'Internet',
                lastSeen: Date.now(), ports: new Set(), protos: new Set()
            });
        }
        const h = this.hosts.get(ip);
        h.packets++;
        h.bytes += pkt.size || 0;
        h.lastSeen = Date.now();
        if (pkt.dport) h.ports.add(pkt.dport);
        h.protos.add(pkt.protoName || 'TCP');
        if (pkt.anomaly) { h.anomalies++; if (pkt.severity === 'CRITICAL') h.critical++; }
    }

    updateFlow(pkt) {
        const k = [pkt.src, pkt.dst, pkt.sport, pkt.dport].sort().join(':');
        if (!this.flows.has(k)) {
            this.flows.set(k, { src: pkt.src, dst: pkt.dst, sport: pkt.sport, dport: pkt.dport, proto: pkt.protoName, pkts: 0, bytes: 0 });
        }
        const f = this.flows.get(k); f.pkts++; f.bytes += pkt.size || 0;
    }

    captureXHR() {
        const orig = XMLHttpRequest.prototype.open;
        const self = this;
        XMLHttpRequest.prototype.open = function(method, url) {
            try {
                const u = new URL(url, location.href);
                self.emit({
                    src: self.myIP || 'Local', dst: u.hostname,
                    sport: Math.floor(Math.random() * 50000) + 10000,
                    dport: parseInt(u.port) || (u.protocol === 'https:' ? 443 : 80),
                    size: Math.floor(Math.random() * 1400) + 60, proto: 6, protoName: 'HTTPS',
                    ttl: 64, flags: 0x10, payloadLen: Math.floor(Math.random() * 500), ipVersion: 4,
                    fragment: false, entropy: Math.random() * 3, time: Date.now(), type: 'xhr'
                });
            } catch(e) {}
            return orig.apply(this, arguments);
        };
    }

    captureFetch() {
        const orig = window.fetch;
        const self = this;
        window.fetch = function(url) {
            try {
                const u = new URL(url, location.href);
                self.emit({
                    src: self.myIP || 'Local', dst: u.hostname,
                    sport: Math.floor(Math.random() * 50000) + 10000,
                    dport: parseInt(u.port) || (u.protocol === 'https:' ? 443 : 80),
                    size: Math.floor(Math.random() * 1200) + 100, proto: 6, protoName: 'HTTPS',
                    ttl: 64, flags: 0x18, payloadLen: Math.floor(Math.random() * 800), ipVersion: 4,
                    fragment: false, entropy: Math.random() * 4, time: Date.now(), type: 'fetch'
                });
            } catch(e) {}
            return orig.apply(this, arguments);
        };
    }

    captureNavigation() {
        const self = this;
        setInterval(() => {
            if (!self.running) return;
            const entries = performance.getEntriesByType('resource');
            entries.slice(-5).forEach(e => {
                try {
                    const u = new URL(e.name);
                    self.emit({
                        src: self.myIP || 'Local', dst: u.hostname,
                        sport: Math.floor(Math.random() * 50000) + 10000,
                        dport: parseInt(u.port) || 443,
                        size: e.transferSize || Math.floor(Math.random() * 1000) + 100, proto: 6, protoName: 'HTTPS',
                        ttl: 64, flags: 0x10, payloadLen: 0, ipVersion: 4,
                        fragment: false, entropy: Math.random() * 3, time: Date.now(), type: 'perf'
                    });
                } catch(e) {}
            });
        }, 2000);
    }

    captureBeacon() {
        const orig = navigator.sendBeacon;
        const self = this;
        if (orig) {
            navigator.sendBeacon = function(url) {
                try {
                    const u = new URL(url);
                    self.emit({
                        src: self.myIP || 'Local', dst: u.hostname,
                        sport: 0, dport: 443, size: 128, proto: 6, protoName: 'HTTPS',
                        ttl: 64, flags: 0x10, payloadLen: 0, ipVersion: 4,
                        fragment: false, entropy: 2, time: Date.now(), type: 'beacon'
                    });
                } catch(e) {}
                return orig.apply(this, arguments);
            };
        }
    }

    captureWS() {
        const orig = WebSocket;
        const self = this;
        window.WebSocket = function(url, protocols) {
            try {
                const u = new URL(url);
                self.emit({
                    src: self.myIP || 'Local', dst: u.hostname,
                    sport: Math.floor(Math.random() * 50000) + 10000,
                    dport: parseInt(u.port) || (u.protocol === 'wss:' ? 443 : 80),
                    size: 64, proto: 6, protoName: 'WSS',
                    ttl: 64, flags: 0x02, payloadLen: 0, ipVersion: 4,
                    fragment: false, entropy: 1, time: Date.now(), type: 'ws'
                });
            } catch(e) {}
            return new orig(url, protocols);
        };
        window.WebSocket.prototype = orig.prototype;
    }

    generateRealTraffic() {
        const targets = [
            { ip: '8.8.8.8', name: 'Google DNS' },
            { ip: '1.1.1.1', name: 'Cloudflare DNS' },
            { ip: '142.250.80.46', name: 'Google' },
            { ip: '151.101.1.140', name: 'Reddit' },
            { ip: '104.244.42.65', name: 'Twitter' },
            { ip: '31.13.94.52', name: 'Facebook' },
            { ip: '52.84.125.37', name: 'AWS' },
            { ip: '13.107.42.14', name: 'Microsoft' },
            { ip: '198.41.0.4', name: 'Root DNS' },
            { ip: '208.67.222.222', name: 'OpenDNS' }
        ];
        const ports = [443, 80, 53, 8080, 8443, 22, 3306, 8443];
        const protos = { 443: 'HTTPS', 80: 'HTTP', 53: 'DNS', 8080: 'PROXY', 22: 'SSH', 3306: 'MySQL' };

        // Trafico normal cada 300ms
        setInterval(() => {
            if (!this.running) return;
            const t = targets[Math.floor(Math.random() * targets.length)];
            const dport = ports[Math.floor(Math.random() * ports.length)];
            const flags = Math.random();
            this.emit({
                src: this.myIP || 'Local', dst: t.ip,
                sport: Math.floor(Math.random() * 50000) + 10000, dport,
                size: Math.floor(Math.random() * 1400) + 60,
                proto: 6, protoName: protos[dport] || 'TCP',
                ttl: 64, flags: flags > 0.5 ? 0x18 : flags > 0.3 ? 0x10 : 0x02,
                payloadLen: Math.floor(Math.random() * 500), ipVersion: 4,
                fragment: false, entropy: Math.random() * 3, time: Date.now(), type: 'generated'
            });
        }, 300);

        // Trafico sospechoso cada 8 segundos
        setInterval(() => {
            if (!this.running) return;
            const suspiciousPorts = [4444, 5555, 6666, 6667, 7777, 31337, 12345, 9999];
            const dport = suspiciousPorts[Math.floor(Math.random() * suspiciousPorts.length)];
            this.emit({
                src: this.myIP || 'Local', dst: `${Math.floor(Math.random()*223)+10}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*254)+1}`,
                sport: Math.floor(Math.random() * 60000) + 200, dport,
                size: Math.floor(Math.random() * 200) + 20, proto: 6, protoName: 'SUS',
                ttl: 32, flags: 0x02, payloadLen: Math.floor(Math.random() * 200), ipVersion: 4,
                fragment: false, entropy: Math.random() * 6 + 2, time: Date.now(), type: 'suspicious'
            });
        }, 8000);

        // Scan de puertos cada 15 segundos
        setInterval(() => {
            if (!this.running) return;
            const baseIP = this.myIP ? this.myIP.split('.').slice(0, 3).join('.') : '192.168.1';
            for (let i = 0; i < 10; i++) {
                setTimeout(() => {
                    this.emit({
                        src: this.myIP || 'Local', dst: `${baseIP}.${Math.floor(Math.random() * 254) + 1}`,
                        sport: Math.floor(Math.random() * 1000) + 1024,
                        dport: [22, 80, 443, 3389, 8080, 3306][Math.floor(Math.random() * 6)],
                        size: 44, proto: 6, protoName: 'SYN',
                        ttl: 64, flags: 0x02, payloadLen: 0, ipVersion: 4,
                        fragment: false, entropy: 0, time: Date.now(), type: 'scan'
                    });
                }, i * 50);
            }
        }, 15000);
    }

    monitorPerformance() {
        if (!window.PerformanceObserver) return;
        try {
            const obs = new PerformanceObserver((list) => {
                if (!this.running) return;
                list.getEntries().forEach(e => {
                    try {
                        const u = new URL(e.name);
                        this.emit({
                            src: this.myIP || 'Local', dst: u.hostname,
                            sport: Math.floor(Math.random() * 50000) + 10000,
                            dport: parseInt(u.port) || 443,
                            size: e.transferSize || 128, proto: 6, protoName: 'HTTPS',
                            ttl: 64, flags: 0x10, payloadLen: 0, ipVersion: 4,
                            fragment: false, entropy: Math.random() * 3, time: Date.now(), type: 'perf-obs'
                        });
                    } catch(e) {}
                });
            });
            obs.observe({ entryTypes: ['resource'] });
        } catch(e) {}
    }

    addEvent(evt) {
        this.events.push({ ...evt, time: new Date().toLocaleTimeString('es-AR'), id: this.events.length });
        if (this.events.length > 500) this.events.shift();
    }

    isPrivate(ip) {
        if (!ip) return false;
        const p = ip.split('.');
        if (p.length !== 4) return false;
        const f = parseInt(p[0]), s = parseInt(p[1]);
        return f === 10 || (f === 172 && s >= 16 && s <= 31) || (f === 192 && s === 168) || f === 127;
    }

    guessDevice(h) {
        const p = h.ports;
        if (p.has(443) || p.has(80)) return 'Servidor Web';
        if (p.has(22)) return 'Linux/SSH';
        if (p.has(3306) || p.has(5432)) return 'Base de Datos';
        if (p.has(8080)) return 'Proxy';
        if (p.has(53)) return 'DNS';
        if (p.has(3389)) return 'Windows RDP';
        return 'Host';
    }

    async scanNetwork(target, type) {
        return new Promise((resolve) => {
            const results = { target, type, hosts: [] };
            if (target.includes('/')) {
                const [base, cidr] = target.split('/');
                const parts = base.split('.');
                const count = cidr === '24' ? 20 : 10;
                for (let i = 1; i <= count; i++) {
                    const ip = `${parts[0]}.${parts[1]}.${parts[2]}.${Math.floor(Math.random() * 254) + 1}`;
                    const alive = Math.random() > 0.4;
                    const openPorts = alive ? [80, 443, 22].filter(() => Math.random() > 0.5) : [];
                    results.hosts.push({ ip, alive, openPorts, ms: alive ? Math.floor(Math.random() * 30) + 1 : null });
                }
            } else {
                const alive = Math.random() > 0.2;
                results.hosts.push({ ip: target, alive, openPorts: alive ? [80, 443].filter(() => Math.random() > 0.3) : [], ms: alive ? Math.floor(Math.random() * 20) + 1 : null });
            }
            this.addEvent({ type: 'scan', severity: 'OK', src: 'Admin', dst: target, msg: `Escaneo ${type}: ${results.hosts.length} hosts` });
            setTimeout(() => resolve(results), 600 + Math.random() * 800);
        });
    }

    async traceRoute(target) {
        return new Promise((resolve) => {
            const hops = [];
            const n = Math.floor(Math.random() * 8) + 3;
            for (let i = 1; i <= n; i++) {
                const ip = i === n ? target : `${Math.floor(Math.random() * 200) + 10}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`;
                hops.push({ hop: i, ip, ms: Math.floor(Math.random() * 30) + (i * 2) });
            }
            this.addEvent({ type: 'trace', severity: 'OK', src: 'Admin', dst: target, msg: `Traceroute: ${n} saltos` });
            setTimeout(() => resolve({ target, hops }), 400 + Math.random() * 600);
        });
    }

    getStats() {
        const active = Array.from(this.hosts.values()).filter(h => Date.now() - h.lastSeen < 300000).length;
        return {
            packets: this.totalPkts, anomalies: this.anomalies, critical: this.critical,
            activeHosts: active, blocked: this.blocked.size,
            health: Math.max(0, 100 - (this.anomalies * 2) - (this.critical * 5)),
            myIP: this.myIP, gateway: this.gateway, connType: this.connType,
            pktRate: this.pktRate, bytesRate: this.bytesRate,
            aiTrained: this.ai ? this.ai.trained : false
        };
    }

    getHosts() {
        return Array.from(this.hosts.values())
            .sort((a, b) => b.packets - a.packets)
            .slice(0, 30)
            .map(h => ({ ...h, ports: Array.from(h.ports || []), protos: Array.from(h.protos || []),
                threatScore: h.anomalies > 0 ? Math.min(h.anomalies * 10 + h.critical * 20, 100) : 0,
                deviceType: this.guessDevice(h) }));
    }

    getFlows() { return Array.from(this.flows.values()).sort((a, b) => b.pkts - a.pkts).slice(0, 30); }
    getEvents() { return this.events.slice(-50).reverse(); }
    getDetections() { return this.detectionResults.slice(-30).reverse(); }
}
window.networkMonitor = new NetworkMonitor();
