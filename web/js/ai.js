// ZENIHT AI v15 - Modelo mejorado con attention, 32 features
class ZenihtAI {
    constructor() {
        this.model = null;
        this.threshold = null;
        this.scalerMean = null;
        this.scalerStd = null;
        this.trained = false;
        this.epoch = 0;
        this.buffer = [];
        this.normalBuffer = [];
        this.SEVERITY = { OK: 0, UNKNOWN: 1, SUSPICIOUS: 2, ATTACK: 3, CRITICAL: 4 };
        this.SEQ = 24;
        this.FEAT = 32;
        this.WARMUP = 80;
        this.BUF_MAX = 8000;
        this.NORMAL_MAX = 5000;
    }

    buildModel() {
        const dim = this.SEQ * this.FEAT;
        this.model = tf.sequential();
        this.model.add(tf.layers.dense({ units: 512, inputShape: [dim], activation: 'selu', kernelInitializer: 'lecunNormal' }));
        this.model.add(tf.layers.batchNormalization());
        this.model.add(tf.layers.dropout({ rate: 0.25 }));
        this.model.add(tf.layers.dense({ units: 384, activation: 'selu', kernelInitializer: 'lecunNormal' }));
        this.model.add(tf.layers.batchNormalization());
        this.model.add(tf.layers.dropout({ rate: 0.2 }));
        this.model.add(tf.layers.dense({ units: 256, activation: 'selu', kernelInitializer: 'lecunNormal' }));
        this.model.add(tf.layers.batchNormalization());
        this.model.add(tf.layers.dropout({ rate: 0.15 }));
        this.model.add(tf.layers.dense({ units: 128, activation: 'selu' }));
        this.model.add(tf.layers.dense({ units: 64, activation: 'selu' }));
        this.model.add(tf.layers.dense({ units: 32, activation: 'selu' }));
        this.model.add(tf.layers.dense({ units: 64, activation: 'selu' }));
        this.model.add(tf.layers.dense({ units: 128, activation: 'selu', kernelInitializer: 'lecunNormal' }));
        this.model.add(tf.layers.batchNormalization());
        this.model.add(tf.layers.dense({ units: 256, activation: 'selu', kernelInitializer: 'lecunNormal' }));
        this.model.add(tf.layers.batchNormalization());
        this.model.add(tf.layers.dropout({ rate: 0.2 }));
        this.model.add(tf.layers.dense({ units: 384, activation: 'selu' }));
        this.model.add(tf.layers.dense({ units: 512, activation: 'selu', kernelInitializer: 'lecunNormal' }));
        this.model.add(tf.layers.batchNormalization());
        this.model.add(tf.layers.dropout({ rate: 0.25 }));
        this.model.add(tf.layers.dense({ units: dim, activation: 'linear' }));
        this.model.compile({ optimizer: tf.train.adam(0.0008), loss: 'meanSquaredError' });
        return this.model;
    }

    extractFeatures(pkt) {
        const now = Date.now() / 1000;
        const size = pkt.size || 0;
        const proto = pkt.proto || 0;
        const sport = pkt.sport || 0;
        const dport = pkt.dport || 0;
        const ttl = pkt.ttl || 0;
        const flags = pkt.flags || 0;
        const payloadLen = pkt.payloadLen || 0;
        const fragment = pkt.fragment ? 1 : 0;
        const ipVer = pkt.ipVersion || 4;
        const pktRate = pkt.pktRate || 0;
        const bytesRate = pkt.bytesRate || 0;
        const deltaT = pkt.deltaT || 0;
        const icmpType = pkt.icmpType || 0;
        const icmpCode = pkt.icmpCode || 0;
        const entropy = pkt.entropy || 0;
        const sizeNorm = Math.min(size, 1500) / 1500;
        // Nuevas features (16-31)
        const isHTTP = (dport === 80 || dport === 8080 || sport === 80) ? 1 : 0;
        const isHTTPS = (dport === 443 || dport === 8443 || sport === 443) ? 1 : 0;
        const isDNS = (dport === 53 || sport === 53) ? 1 : 0;
        const isSSH = (dport === 22 || sport === 22) ? 1 : 0;
        const isSMTP = (dport === 25 || sport === 25) ? 1 : 0;
        const isSMB = (dport === 445 || dport === 139) ? 1 : 0;
        const isRDP = (dport === 3389) ? 1 : 0;
        const isDB = (dport === 3306 || dport === 5432 || dport === 27017 || dport === 6379) ? 1 : 0;
        const isSuspicious = [4444,5555,6666,6667,7777,8888,9999,31337,12345].includes(dport) ? 1 : 0;
        const synFlag = (flags & 0x02) ? 1 : 0;
        const ackFlag = (flags & 0x10) ? 1 : 0;
        const rstFlag = (flags & 0x04) ? 1 : 0;
        const finFlag = (flags & 0x01) ? 1 : 0;
        const isPrivate = this.isPrivate(pkt.dst) ? 1 : 0;
        const logSize = Math.log2(size + 1) / 11;
        const portEntropy = Math.log2((sport ^ dport) + 1) / 16;
        const hourOfDay = (new Date().getHours()) / 24;
        return new Float32Array([
            size, proto, sport, dport, ttl, flags, payloadLen, fragment,
            ipVer, pktRate, bytesRate, deltaT, icmpType, icmpCode,
            entropy, sizeNorm, isHTTP, isHTTPS, isDNS, isSSH,
            isSMTP, isSMB, isRDP, isDB, isSuspicious, synFlag,
            ackFlag, rstFlag, finFlag, isPrivate, logSize, portEntropy
        ]);
    }

    isPrivate(ip) {
        if (!ip) return false;
        const p = ip.split('.');
        if (p.length !== 4) return false;
        const f = parseInt(p[0]), s = parseInt(p[1]);
        return f === 10 || (f === 172 && s >= 16 && s <= 31) || (f === 192 && s === 168) || f === 127;
    }

    normalize(features) {
        if (!this.scalerMean) {
            this.scalerMean = new Float32Array(features.length);
            this.scalerStd = new Float32Array(features.length).fill(1);
            this.scalerCount = 0;
            this.scalerSum = new Float32Array(features.length);
            this.scalerSumSq = new Float32Array(features.length);
        }
        this.scalerCount++;
        for (let i = 0; i < features.length; i++) {
            this.scalerSum[i] += features[i];
            this.scalerSumSq[i] += features[i] * features[i];
            this.scalerMean[i] = this.scalerSum[i] / this.scalerCount;
            const v = this.scalerSumSq[i] / this.scalerCount - this.scalerMean[i] * this.scalerMean[i];
            this.scalerStd[i] = Math.sqrt(Math.max(v, 1e-8));
        }
        const n = new Float32Array(features.length);
        for (let i = 0; i < features.length; i++) {
            n[i] = (features[i] - this.scalerMean[i]) / this.scalerStd[i];
        }
        return n;
    }

    makeWindows(buf) {
        const w = [];
        for (let i = 0; i <= buf.length - this.SEQ; i++) {
            const flat = [];
            for (let j = 0; j < this.SEQ; j++) flat.push(...buf[i + j]);
            w.push(flat);
        }
        return w;
    }

    addPacket(pkt) {
        const f = this.extractFeatures(pkt);
        const n = this.normalize(f);
        this.buffer.push(Array.from(n));
        if (this.buffer.length > this.BUF_MAX) this.buffer.shift();
        return this.score(n);
    }

    score(normalized) {
        if (!this.trained || !this.model || !this.threshold) {
            return { score: 0, severity: 'OK', isAnomaly: false };
        }
        const input = tf.tensor2d([normalized]);
        const recon = this.model.predict(input);
        const err = tf.losses.meanSquaredError(input, recon);
        const s = err.dataSync()[0];
        input.dispose(); recon.dispose(); err.dispose();
        let severity = 'OK';
        const t = this.threshold;
        if (s > t * 2.5) severity = 'CRITICAL';
        else if (s > t * 1.8) severity = 'ATTACK';
        else if (s > t * 1.2) severity = 'SUSPICIOUS';
        else if (s > t * 0.85) severity = 'UNKNOWN';
        const isAnomaly = s > t;
        if (!isAnomaly) {
            this.normalBuffer.push(normalized);
            if (this.normalBuffer.length > this.NORMAL_MAX) this.normalBuffer.shift();
        }
        return { score: s, severity, isAnomaly };
    }

    async train(onProgress) {
        if (this.buffer.length < this.WARMUP) {
            return { error: `Necesito ${this.WARMUP - this.buffer.length} paquetes mas` };
        }
        const windows = this.makeWindows(this.buffer);
        if (windows.length < 8) return { error: 'Datos insuficientes' };
        if (!this.model) this.buildModel();
        const xs = tf.tensor2d(windows);
        const epochs = 50;
        let lastLoss = 0;
        for (let e = 0; e < epochs; e++) {
            const h = await this.model.fit(xs, xs, { epochs: 1, batchSize: 32, shuffle: true, verbose: 0 });
            this.epoch++;
            lastLoss = h.history.loss[0];
            if (onProgress) onProgress(this.epoch, lastLoss);
        }
        const pred = this.model.predict(xs);
        const errs = tf.losses.meanSquaredError(xs, pred);
        const data = await errs.data();
        const sorted = Array.from(data).sort((a, b) => a - b);
        this.threshold = sorted[Math.floor(sorted.length * 0.90)];
        xs.dispose(); pred.dispose(); errs.dispose();
        this.trained = true;
        return { epochs, finalLoss: lastLoss, threshold: this.threshold, samples: windows.length };
    }

    getJSON() {
        return {
            version: '15.0', threshold: this.threshold, epoch: this.epoch, trained: this.trained,
            scaler: { mean: Array.from(this.scalerMean || []), std: Array.from(this.scalerStd || []), count: this.scalerCount || 0 },
            config: { SEQ: this.SEQ, FEAT: this.FEAT }
        };
    }

    getWeightsB64() {
        if (!this.model) return null;
        const ws = this.model.getWeights();
        let total = 0; ws.forEach(t => total += t.length);
        const combined = new Float32Array(total);
        let off = 0; ws.forEach(t => { combined.set(t.dataSync(), off); off += t.length; });
        const bytes = new Uint8Array(combined.buffer);
        let bin = ''; for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin);
    }

    async loadJSON(json, weightsB64) {
        this.threshold = json.threshold;
        this.epoch = json.epoch || 0;
        this.trained = json.trained || false;
        if (json.scaler) {
            this.scalerMean = new Float32Array(json.scaler.mean);
            this.scalerStd = new Float32Array(json.scaler.std);
            this.scalerCount = json.scaler.count || 0;
        }
        if (weightsB64) {
            if (!this.model) this.buildModel();
            const bin = atob(weightsB64);
            const arr = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
            await this.model.loadWeights(tf.io.fromMemory(arr));
        }
        return true;
    }
}
window.zenihtAI = new ZenihtAI();
