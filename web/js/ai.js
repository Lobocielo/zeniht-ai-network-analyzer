// ZENIHT AI - TensorFlow.js Autoencoder para analisis de red
class ZenihtAI {
    constructor() {
        this.model = null;
        this.threshold = null;
        this.scaler = { mean: null, std: null };
        this.trained = false;
        this.epoch = 0;
        this.featureBuffer = [];
        this.normalBuffer = [];
        this.SEQ_LEN = 24;
        this.FEATURE_DIM = 16;
        this.WARMUP = 100;
        this.BUFFER_MAX = 5000;
        this.NORMAL_MAX = 3000;
        this.lastScore = 0;
    }

    buildModel() {
        const inputDim = this.SEQ_LEN * this.FEATURE_DIM;

        this.model = tf.sequential();

        // Encoder
        this.model.add(tf.layers.dense({ units: 256, inputShape: [inputDim], activation: 'selu', kernelInitializer: 'lecunNormal' }));
        this.model.add(tf.layers.batchNormalization());
        this.model.add(tf.layers.dropout({ rate: 0.2 }));

        this.model.add(tf.layers.dense({ units: 128, activation: 'selu', kernelInitializer: 'lecunNormal' }));
        this.model.add(tf.layers.batchNormalization());
        this.model.add(tf.layers.dropout({ rate: 0.15 }));

        this.model.add(tf.layers.dense({ units: 64, activation: 'selu', kernelInitializer: 'lecunNormal' }));
        this.model.add(tf.layers.dense({ units: 32, activation: 'selu' }));

        // Decoder
        this.model.add(tf.layers.dense({ units: 64, activation: 'selu' }));
        this.model.add(tf.layers.dense({ units: 128, activation: 'selu', kernelInitializer: 'lecunNormal' }));
        this.model.add(tf.layers.batchNormalization());
        this.model.add(tf.layers.dropout({ rate: 0.15 }));

        this.model.add(tf.layers.dense({ units: 256, activation: 'selu', kernelInitializer: 'lecunNormal' }));
        this.model.add(tf.layers.batchNormalization());
        this.model.add(tf.layers.dropout({ rate: 0.2 }));

        this.model.add(tf.layers.dense({ units: inputDim, activation: 'linear' }));

        this.model.compile({
            optimizer: tf.train.adam(0.001),
            loss: 'meanSquaredError'
        });

        return this.model;
    }

    extractFeatures(packetData) {
        const now = Date.now() / 1000;
        const size = packetData.size || 0;
        const proto = packetData.proto || 0;
        const sport = packetData.sport || 0;
        const dport = packetData.dport || 0;
        const ttl = packetData.ttl || 0;
        const flags = packetData.flags || 0;
        const payloadLen = packetData.payloadLen || 0;
        const isFragment = packetData.fragment ? 1 : 0;
        const ipVersion = packetData.ipVersion || 4;
        const pktRate = packetData.pktRate || 0;
        const bytesRate = packetData.bytesRate || 0;
        const deltaT = packetData.deltaT || 0;
        const icmpType = packetData.icmpType || 0;
        const icmpCode = packetData.icmpCode || 0;
        const entropy = packetData.entropy || 0;
        const sizeNorm = Math.min(size, 1500) / 1500;

        return new Float32Array([
            size, proto, sport, dport, ttl, flags, payloadLen, isFragment,
            ipVersion, pktRate, bytesRate, deltaT, icmpType, icmpCode,
            entropy, sizeNorm
        ]);
    }

    normalizeFeatures(features) {
        if (!this.scaler.mean) {
            // Initialize with first batch
            this.scaler.mean = new Float32Array(features.length);
            this.scaler.std = new Float32Array(features.length).fill(1);
            this.scaler.count = 0;
            this.scaler.sum = new Float32Array(features.length);
            this.scaler.sumSq = new Float32Array(features.length);
        }

        // Update running stats
        this.scaler.count++;
        for (let i = 0; i < features.length; i++) {
            this.scaler.sum[i] += features[i];
            this.scaler.sumSq[i] += features[i] * features[i];
            this.scaler.mean[i] = this.scaler.sum[i] / this.scaler.count;
            const variance = this.scaler.sumSq[i] / this.scaler.count - this.scaler.mean[i] * this.scaler.mean[i];
            this.scaler.std[i] = Math.sqrt(Math.max(variance, 1e-8));
        }

        // Normalize
        const normalized = new Float32Array(features.length);
        for (let i = 0; i < features.length; i++) {
            normalized[i] = (features[i] - this.scaler.mean[i]) / this.scaler.std[i];
        }
        return normalized;
    }

    makeWindows(buffer) {
        const windows = [];
        for (let i = 0; i <= buffer.length - this.SEQ_LEN; i++) {
            const window = [];
            for (let j = 0; j < this.SEQ_LEN; j++) {
                window.push(...buffer[i + j]);
            }
            windows.push(window);
        }
        return windows;
    }

    addPacket(packetData) {
        const features = this.extractFeatures(packetData);
        const normalized = this.normalizeFeatures(features);
        this.featureBuffer.push(Array.from(normalized));

        if (this.featureBuffer.length > this.BUFFER_MAX) {
            this.featureBuffer.shift();
        }

        return this.scorePacket(normalized);
    }

    scorePacket(normalizedFeatures) {
        if (!this.trained || !this.model || !this.threshold) {
            return { score: 0, severity: 'OK', isAnomaly: false };
        }

        const input = tf.tensor2d([normalizedFeatures]);
        const reconstructed = this.model.predict(input);
        const err = tf.losses.meanSquaredError(input, reconstructed);
        const score = err.dataSync()[0];

        input.dispose();
        reconstructed.dispose();
        err.dispose();

        this.lastScore = score;

        let severity = 'OK';
        const thr = this.threshold;
        if (score > thr * 2.5) severity = 'CRITICAL';
        else if (score > thr * 1.8) severity = 'ATTACK';
        else if (score > thr * 1.2) severity = 'SUSPICIOUS';
        else if (score > thr * 0.9) severity = 'UNKNOWN';

        const isAnomaly = score > thr;

        if (!isAnomaly) {
            this.normalBuffer.push(normalizedFeatures);
            if (this.normalBuffer.length > this.NORMAL_MAX) {
                this.normalBuffer.shift();
            }
        }

        return { score, severity, isAnomaly };
    }

    async train() {
        if (this.featureBuffer.length < this.WARMUP) {
            return { error: `Necesito ${this.WARMUP - this.featureBuffer.length} paquetes mas para entrenar` };
        }

        const windows = this.makeWindows(this.featureBuffer);
        if (windows.length < 8) {
            return { error: 'No hay suficientes ventanas para entrenar' };
        }

        if (!this.model) this.buildModel();

        const xs = tf.tensor2d(windows);

        const results = [];
        const totalEpochs = 30;

        for (let epoch = 0; epoch < totalEpochs; epoch++) {
            const history = await this.model.fit(xs, xs, {
                epochs: 1,
                batchSize: 32,
                shuffle: true,
                verbose: 0
            });

            this.epoch++;
            const loss = history.history.loss[0];
            results.push({ epoch: this.epoch, loss });

            // Update UI
            if (typeof updateAIStatus === 'function') {
                updateAIStatus(this.epoch, loss, 0);
            }
        }

        // Calibrate threshold
        const predictions = this.model.predict(xs);
        const errors = tf.losses.meanSquaredError(xs, predictions);
        const errorData = await errors.data();

        const sorted = Array.from(errorData).sort((a, b) => a - b);
        this.threshold = sorted[Math.floor(sorted.length * 0.92)];

        xs.dispose();
        predictions.dispose();
        errors.dispose();

        this.trained = true;

        return {
            epochs: totalEpochs,
            finalLoss: results[results.length - 1].loss,
            threshold: this.threshold,
            samples: windows.length
        };
    }

    getModelJSON() {
        return {
            version: '15.0',
            threshold: this.threshold,
            scaler: {
                mean: Array.from(this.scaler.mean || []),
                std: Array.from(this.scaler.std || []),
                count: this.scaler.count || 0
            },
            epoch: this.epoch,
            trained: this.trained,
            config: {
                SEQ_LEN: this.SEQ_LEN,
                FEATURE_DIM: this.FEATURE_DIM
            }
        };
    }

    async loadModel(json, weights) {
        this.threshold = json.threshold;
        this.epoch = json.epoch || 0;
        this.trained = json.trained || false;

        if (json.scaler) {
            this.scaler.mean = new Float32Array(json.scaler.mean);
            this.scaler.std = new Float32Array(json.scaler.std);
            this.scaler.count = json.scaler.count || 0;
        }

        if (weights) {
            if (!this.model) this.buildModel();
            const weightData = atob(weights);
            const weightArray = new Uint8Array(weightData.length);
            for (let i = 0; i < weightData.length; i++) {
                weightArray[i] = weightData.charCodeAt(i);
            }
            await this.model.loadWeights(tf.io.fromMemory(weightArray));
        }

        return true;
    }

    getWeightsBase64() {
        if (!this.model) return null;
        const weights = this.model.getWeights();
        const tensors = weights.map(t => t.dataSync());
        let totalLen = 0;
        tensors.forEach(t => totalLen += t.length);
        const combined = new Float32Array(totalLen);
        let offset = 0;
        tensors.forEach(t => {
            combined.set(t, offset);
            offset += t.length;
        });
        const bytes = new Uint8Array(combined.buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
}

window.zenihtAI = new ZenihtAI();
