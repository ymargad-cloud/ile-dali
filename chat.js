// ═══════════════════════════════════════════════════════════════
// Vercel Serverless Function — Proxy Anthropic API
// Route : POST /api/chat
// La clé API reste côté serveur, jamais exposée au navigateur
// ═══════════════════════════════════════════════════════════════

export default async function handler(req, res) {
  // CORS — autoriser uniquement ton domaine Vercel en production
  const origin = req.headers.origin || '';
  const allowed = [
    process.env.ALLOWED_ORIGIN,          // ex: https://ile-aux-eleves.vercel.app
    'http://localhost:3000',              // dev local
    'http://127.0.0.1:5500',             // Live Server VS Code
  ].filter(Boolean);

  if (allowed.length === 0 || allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  } else {
    res.setHeader('Access-Control-Allow-Origin', allowed[0]);
  }

  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return res.status(500).json({ error: 'API key not configured' });
  }

  try {
    const { model, max_tokens, messages } = req.body;

    // Validation minimale
    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({ error: 'Invalid request body' });
    }

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: model || 'claude-sonnet-4-6',
        max_tokens: max_tokens || 1000,
        messages,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({ error: data });
    }

    return res.status(200).json(data);

  } catch (err) {
    console.error('Proxy error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
