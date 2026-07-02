module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { action, user, pass, ip } = req.body || req.query || {};
  const adminUser = 'ZENIHT';
  const hash = (s) => { let h = 0; for (let i = 0; i < s.length; i++) { h = ((h << 5) - h) + s.charCodeAt(i); h |= 0; } return 'h' + Math.abs(h).toString(36); };

  return res.status(200).json({
    ok: true,
    message: 'ZENIHT AI Auth endpoint',
    version: '15.0',
    endpoints: ['/api/auth?action=status', '/api/auth?action=log&user=...'],
    timestamp: new Date().toISOString()
  });
};