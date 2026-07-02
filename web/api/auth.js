const crypto = require('crypto');

module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();

    const url = new URL(req.url, 'http://localhost');
    const action = url.searchParams.get('action') || 'status';

    if (action === 'status') {
        return res.status(200).json({
            ok: true,
            version: '15.0.0',
            name: 'ZENIHT AI Network Analyzer',
            features: [
                'Autoencoder AI con TensorFlow.js',
                'Monitoreo de red en tiempo real',
                'Deteccion de anomalias',
                'Identificacion de dispositivos',
                'Descubrimiento de redes',
                'Guardado en GitHub'
            ]
        });
    }

    if (req.method !== 'POST') return res.status(405).json({ error: 'GET /api/auth?action=status para info' });

    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
        try {
            const { action: act, username, password } = JSON.parse(body);
            if (act === 'register') {
                if (!username || !password) return res.status(400).json({ error: 'Faltan campos' });
                if (username.length < 3) return res.status(400).json({ error: 'Usuario: min 3 chars' });
                if (password.length < 4) return res.status(400).json({ error: 'Password: min 4 chars' });
                const token = crypto.createHash('sha256').update(username + password + Date.now()).digest('hex');
                return res.status(201).json({ ok: true, token, user: { username, level: 1 } });
            }
            if (act === 'login') {
                if (!username || !password) return res.status(400).json({ error: 'Faltan campos' });
                const token = crypto.createHash('sha256').update(username + password).digest('hex');
                return res.status(200).json({ ok: true, token, user: { username, level: 1 } });
            }
            return res.status(400).json({ error: 'Accion invalida' });
        } catch(e) {
            return res.status(400).json({ error: 'JSON invalido' });
        }
    });
};
