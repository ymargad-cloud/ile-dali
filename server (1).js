const http   = require('http');
const https  = require('https');
const fs     = require('fs');
const path   = require('path');
const jwt    = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const PORT       = process.env.PORT || 3000;
const HTML_FILE  = path.join(__dirname, 'compta-app.html');
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET manquant dans les variables d\'environnement');
  process.exit(1);
}
const SUPA_URL   = (process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const SUPA_KEY   = process.env.SUPABASE_KEY || '';

console.log('=== NEOEXPERT ComptaAI demarrage ===');
console.log('SUPABASE_URL:', SUPA_URL || 'MANQUANTE');
console.log('SUPABASE_KEY:', SUPA_KEY ? SUPA_KEY.slice(0,20)+'...' : 'MANQUANTE');

// Helper HTTP request
function httpReq(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// Supabase REST call
async function supa(method, table, { filter, body, select } = {}) {
  let urlPath = `/rest/v1/${table}`;
  const qs = [];
  if (select) qs.push(`select=${select}`);
  if (filter) qs.push(filter);
  if (qs.length) urlPath += '?' + qs.join('&');

  const parsed = new URL(SUPA_URL + urlPath);
  const bodyStr = body ? JSON.stringify(Array.isArray(body) ? body : body) : null;

  const options = {
    hostname: parsed.hostname,
    port: 443,
    path: parsed.pathname + parsed.search,
    method,
    headers: {
      'apikey': SUPA_KEY,
      'Authorization': `Bearer ${SUPA_KEY}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'Prefer': method === 'POST' ? 'return=representation' : 'return=representation',
    }
  };
  if (bodyStr) options.headers['Content-Length'] = Buffer.byteLength(bodyStr);

  const { status, body: responseBody } = await httpReq(options, bodyStr);
  let parsed2;
  try { parsed2 = JSON.parse(responseBody); } catch { parsed2 = responseBody; }
  console.log(`SUPA ${method} ${table} → ${status}`);
  if (status >= 400) console.log('SUPA ERROR:', responseBody.slice(0, 300));
  return { data: parsed2, status };
}

function parseBody(req) {
  return new Promise(res => {
    let b = '';
    req.on('data', c => b += c);
    req.on('end', () => { try { res(JSON.parse(b)); } catch { res({}); } });
  });
}

function send(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(data));
}

async function getUser(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return null;
  try {
    const p = jwt.verify(h.slice(7), JWT_SECRET);
    const { data } = await supa('GET', 'users', { filter: `id=eq.${p.sub}` });
    return Array.isArray(data) && data[0] ? data[0] : null;
  } catch(e) { console.log('Auth error:', e.message); return null; }
}

// Handler unique — fonctionne en local (http.createServer) ET sur Vercel (module.exports)
const handler = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,x-api-key,x-client-key,anthropic-version');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  const url = req.url.split('?')[0];
  console.log(`${req.method} ${url}`);

  // Health
  if (url === '/health') {
    return send(res, 200, { ok: true, supabase_url: !!SUPA_URL, supabase_key: !!SUPA_KEY, key_preview: SUPA_KEY.slice(0,15) });
  }

  // Test Supabase direct
  if (url === '/test-supa') {
    const result = await supa('GET', 'users', { select: 'id,email' });
    return send(res, 200, { status: result.status, data: result.data });
  }

  // HTML
  if (req.method === 'GET' && !url.startsWith('/api')) {
    if (!fs.existsSync(HTML_FILE)) { res.writeHead(404); return res.end('HTML introuvable'); }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(fs.readFileSync(HTML_FILE));
  }

  // POST /api/auth/login
  if (req.method === 'POST' && url === '/api/auth/login') {
    const body = await parseBody(req);
    const { email, password } = body;
    console.log('Login attempt:', email);
    const { data, status } = await supa('GET', 'users', { filter: `email=eq.${(email||'').toLowerCase().trim()}` });
    console.log('Users found:', Array.isArray(data) ? data.length : 'not array', 'status:', status);
    const user = Array.isArray(data) && data[0] ? data[0] : null;
    if (!user) return send(res, 401, { error: 'Email ou mot de passe incorrect' });
    const ok = await bcrypt.compare(password, user.password);
    console.log('bcrypt compare:', ok, 'hash prefix:', user.password.slice(0,7));
    if (!ok) return send(res, 401, { error: 'Email ou mot de passe incorrect' });
    const token = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: '30d' });
    return send(res, 200, { token, user: { id: user.id, email: user.email, nom: user.nom, prenom: user.prenom, role: user.role } });
  }

  // POST /api/auth/register
  // Rôle autorisé : un admin connecté peut choisir n'importe quel rôle ;
  // un visiteur non authentifié est limité à 'comptable'.
  if (req.method === 'POST' && url === '/api/auth/register') {
    const body = await parseBody(req);
    const { email, password, nom, prenom, role } = body;
    if (!email || !password || !nom || !prenom) return send(res, 400, { error: 'Champs manquants' });
    if (password.length < 6) return send(res, 400, { error: 'Mot de passe trop court (6 caractères minimum)' });

    // Déterminer le rôle effectif
    const caller = await getUser(req);
    const ROLES_ALLOWED = ['comptable', 'auditeur', 'admin'];
    let effectiveRole = 'comptable'; // valeur par défaut sécurisée
    if (caller && caller.role === 'admin' && ROLES_ALLOWED.includes(role)) {
      effectiveRole = role;
    }

    const hash = await bcrypt.hash(password, 10);
    const { data, status } = await supa('POST', 'users', { body: { email: email.toLowerCase().trim(), password: hash, nom, prenom, role: effectiveRole } });
    if (status >= 400) return send(res, 409, { error: 'Email déjà utilisé ou erreur' });
    const user = Array.isArray(data) ? data[0] : data;
    const token = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: '30d' });
    return send(res, 201, { token, user: { id: user.id, email: user.email, nom: user.nom, prenom: user.prenom, role: user.role } });
  }

  // GET /api/auth/me
  if (req.method === 'GET' && url === '/api/auth/me') {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    return send(res, 200, { user: { id: user.id, email: user.email, nom: user.nom, prenom: user.prenom, role: user.role } });
  }

  // ===== ROUTES DELETE =====

  // DELETE /api/companies/:id
  if (req.method === 'DELETE' && url.startsWith('/api/companies/') && url.split('/').length === 4) {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const id = url.split('/')[3];
    const { data: co } = await supa('GET', 'companies', { filter: `id=eq.${id}` });
    const company = Array.isArray(co) && co[0] ? co[0] : null;
    if (!company) return send(res, 404, { error: 'Société introuvable' });
    if (user.role !== 'admin' && company.owner_id !== user.id) return send(res, 403, { error: 'Non autorisé' });
    await supa('DELETE', 'factures',         { filter: `company_id=eq.${id}` });
    await supa('DELETE', 'transactions',     { filter: `company_id=eq.${id}` });
    await supa('DELETE', 'declarations_tva', { filter: `company_id=eq.${id}` });
    await supa('DELETE', 'dossiers',         { filter: `company_id=eq.${id}` });
    await supa('DELETE', 'user_companies',   { filter: `company_id=eq.${id}` });
    await supa('DELETE', 'companies',        { filter: `id=eq.${id}` });
    return send(res, 200, { ok: true });
  }

  // DELETE /api/factures/:id
  if (req.method === 'DELETE' && url.startsWith('/api/factures/') && url.split('/').length === 4) {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const id = url.split('/')[3];
    await supa('DELETE', 'factures', { filter: `id=eq.${id}` });
    return send(res, 200, { ok: true });
  }

  // PATCH /api/factures/:id — modification partielle d'une facture (N°, HT, TVA, TTC)
  if (req.method === 'PATCH' && url.startsWith('/api/factures/') && url.split('/').length === 4) {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const id = url.split('/')[3];
    const body = await parseBody(req);
    // Champs autorisés à être modifiés
    const ALLOWED = ['numero','montant_ht','montant_tva','montant_ttc','taux_tva','description','categorie','date_facture','statut'];
    const patch = {};
    for(const k of ALLOWED) { if(body[k] !== undefined) patch[k] = body[k]; }
    if(!Object.keys(patch).length) return send(res, 400, { error: 'Aucun champ valide' });
    await supa('PATCH', `factures?id=eq.${id}`, { body: patch });
    return send(res, 200, { ok: true });
  }

  // DELETE /api/transactions/:id
  if (req.method === 'DELETE' && url.startsWith('/api/transactions/') && url.split('/').length === 4) {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const id = url.split('/')[3];
    await supa('DELETE', 'transactions', { filter: `id=eq.${id}` });
    return send(res, 200, { ok: true });
  }

  // DELETE /api/tva/:id
  if (req.method === 'DELETE' && url.startsWith('/api/tva/') && url.split('/').length === 4) {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const id = url.split('/')[3];
    await supa('DELETE', 'declarations_tva', { filter: `id=eq.${id}` });
    return send(res, 200, { ok: true });
  }

  // DELETE /api/dossiers/:id
  if (req.method === 'DELETE' && url.startsWith('/api/dossiers/') && url.split('/').length === 4) {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const id = url.split('/')[3];
    await supa('DELETE', 'dossiers', { filter: `id=eq.${id}` });
    return send(res, 200, { ok: true });
  }

  // ===== FIN ROUTES DELETE =====

  // GET /api/companies
  if (req.method === 'GET' && url === '/api/companies') {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    let result;
    if (user.role === 'admin') {
      result = await supa('GET', 'companies', {});
    } else {
      const links = await supa('GET', 'user_companies', { filter: `user_id=eq.${user.id}` });
      const ids = (links.data || []).map(l => l.company_id);
      if (!ids.length) return send(res, 200, []);
      result = await supa('GET', 'companies', { filter: `id=in.(${ids.join(',')})` });
    }
    return send(res, 200, result.data || []);
  }

  // POST /api/companies
  if (req.method === 'POST' && url === '/api/companies') {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const body = await parseBody(req);
    const { data } = await supa('POST', 'companies', { body: { name: body.name, ice: body.ice, if_fiscal: body.if_fiscal, ville: body.ville, exercice: body.exercice, owner_id: user.id } });
    const company = Array.isArray(data) ? data[0] : data;
    await supa('POST', 'user_companies', { body: { user_id: user.id, company_id: company.id } });
    return send(res, 201, company);
  }

  // GET /api/companies/portal/:token
  if (req.method === 'GET' && url.startsWith('/api/companies/portal/')) {
    const token = url.split('/').pop();
    const { data } = await supa('GET', 'companies', { filter: `portal_token=eq.${token}`, select: 'id,name' });
    const company = Array.isArray(data) && data[0] ? data[0] : null;
    if (!company) return send(res, 404, { error: 'Lien invalide' });
    return send(res, 200, company);
  }

  // GET /api/factures
  if (req.method === 'GET' && url === '/api/factures') {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const p = new URLSearchParams(req.url.split('?')[1] || '');
    const limit  = Math.min(parseInt(p.get('limit')  || '500', 10), 1000);
    const offset = parseInt(p.get('offset') || '0', 10);
    const { data } = await supa('GET', 'factures', {
      filter: `company_id=eq.${p.get('company_id')}&order=date_facture.desc&limit=${limit}&offset=${offset}`
    });
    return send(res, 200, data || []);
  }

  // POST /api/factures
  if (req.method === 'POST' && url === '/api/factures') {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const body = await parseBody(req);
    const payload = {
      company_id:    body.company_id,
      numero:        body.numero,
      date_facture:  body.date_facture,
      fournisseur:   body.fournisseur,
      fournisseur_ice: body.fournisseur_ice,
      categorie:     body.categorie,
      description:   body.description,
      montant_ht:    body.montant_ht,
      taux_tva:      body.taux_tva,
      montant_tva:   body.montant_tva,
      montant_ttc:   body.montant_ttc,
      devise:        body.devise || 'MAD',
      journal:       body.journal || 'A',
      type_facture:  body.type_facture || 'achat',
      dossier_id:    body.dossier_id || null,
    };
    const { data } = await supa('POST', 'factures', { body: payload });
    return send(res, 201, Array.isArray(data) ? data[0] : data);
  }

  // GET /api/transactions
  if (req.method === 'GET' && url === '/api/transactions') {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const p = new URLSearchParams(req.url.split('?')[1] || '');
    const limit  = Math.min(parseInt(p.get('limit')  || '1000', 10), 5000);
    const offset = parseInt(p.get('offset') || '0', 10);
    const { data } = await supa('GET', 'transactions', {
      filter: `company_id=eq.${p.get('company_id')}&order=date_operation.desc&limit=${limit}&offset=${offset}`
    });
    return send(res, 200, data || []);
  }

  // POST /api/transactions
  if (req.method === 'POST' && url === '/api/transactions') {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const body = await parseBody(req);
    const rows = Array.isArray(body) ? body : [body];
    const { data } = await supa('POST', 'transactions', { body: rows });
    return send(res, 201, data);
  }

  // GET /api/users
  if (req.method === 'GET' && url === '/api/users') {
    const user = await getUser(req);
    if (!user || user.role !== 'admin') return send(res, 403, { error: 'Admin requis' });
    const { data } = await supa('GET', 'users', { select: 'id,email,nom,prenom,role,created_at' });
    return send(res, 200, data || []);
  }

  // POST /api/auth/change-password
  if (req.method === 'POST' && url === '/api/auth/change-password') {
    const caller = await getUser(req);
    if (!caller) return send(res, 401, { error: 'Non authentifié' });
    const body = await parseBody(req);
    const { old_password, new_password } = body;
    if (!old_password || !new_password) return send(res, 400, { error: 'Champs manquants' });
    if (new_password.length < 6) return send(res, 400, { error: 'Nouveau mot de passe trop court (6 caractères minimum)' });
    // Recharger l'utilisateur depuis la DB pour avoir le hash à jour
    const { data } = await supa('GET', 'users', { filter: `id=eq.${caller.id}` });
    const user = Array.isArray(data) && data[0] ? data[0] : null;
    if (!user) return send(res, 401, { error: 'Utilisateur introuvable' });
    const ok = await bcrypt.compare(old_password, user.password);
    if (!ok) return send(res, 401, { error: 'Mot de passe actuel incorrect' });
    const newHash = await bcrypt.hash(new_password, 10);
    await supa('PATCH', `users?id=eq.${user.id}`, { body: { password: newHash } });
    return send(res, 200, { message: 'Mot de passe modifié avec succès' });
  }

  // POST /api/portal/upload
  if (req.method === 'POST' && url === '/api/portal/upload') {
    const body = await parseBody(req);
    const docs = (body.files || []).map(f => ({
      company_id:    body.company_id,
      original_name: f.name,
      file_size:     f.size || null,
      file_data:     f.data || null,   // base64 du fichier
      media_type:    f.type || null,
      status:        'pending',
      from_client:   true,
      client_note:   body.note || null,
    }));
    await supa('POST', 'documents', { body: docs });
    return send(res, 201, { ok: true });
  }

  // GET /api/documents?company_id=xxx  (admin/comptable seulement)
  if (req.method === 'GET' && url === '/api/documents') {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const p = new URLSearchParams(req.url.split('?')[1] || '');
    // Exclure file_data (base64 lourd) de la liste — récupéré uniquement via GET /api/documents/:id
    const { data } = await supa('GET', 'documents', {
      filter: `company_id=eq.${p.get('company_id')}&order=created_at.desc`,
      select: 'id,company_id,original_name,file_size,media_type,status,from_client,client_note,created_at'
    });
    return send(res, 200, data || []);
  }

  // GET /api/documents/:id  (télécharger un document spécifique avec son contenu)
  if (req.method === 'GET' && url.startsWith('/api/documents/') && url.split('/').length === 4) {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const id = url.split('/')[3];
    const { data } = await supa('GET', 'documents', { filter: `id=eq.${id}` });
    const doc = Array.isArray(data) && data[0] ? data[0] : null;
    if (!doc) return send(res, 404, { error: 'Document introuvable' });
    return send(res, 200, doc);
  }

  // PATCH /api/documents/:id  (changer le statut : pending → processing → done)
  if (req.method === 'PATCH' && url.startsWith('/api/documents/') && url.split('/').length === 4) {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const id = url.split('/')[3];
    const body = await parseBody(req);
    await supa('PATCH', `documents?id=eq.${id}`, { body: { status: body.status } });
    return send(res, 200, { ok: true });
  }

  // DELETE /api/documents/:id
  if (req.method === 'DELETE' && url.startsWith('/api/documents/') && url.split('/').length === 4) {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const id = url.split('/')[3];
    await supa('DELETE', 'documents', { filter: `id=eq.${id}` });
    return send(res, 200, { ok: true });
  }

  // POST /api/messages (proxy Anthropic)
  if (req.method === 'POST' && url === '/api/messages') {
    // Récupérer la clé : d'abord header, sinon Supabase, sinon localStorage via header custom
    let apiKey = req.headers['x-api-key'] || '';
    if (!apiKey.startsWith('sk-ant-')) {
      const { data } = await supa('GET', 'settings', { filter: 'key=eq.anthropic_api_key' });
      const setting = Array.isArray(data) && data[0] ? data[0] : null;
      if (setting) apiKey = setting.value;
    }
    // Clé client en fallback
    if (!apiKey.startsWith('sk-ant-')) {
      apiKey = req.headers['x-client-key'] || '';
    }
    // Log pour debug
    console.log('apiKey found:', apiKey ? apiKey.slice(0,20)+'...' : 'VIDE');
    if (!apiKey || !apiKey.startsWith('sk-ant-')) {
      return send(res, 400, { error: { message: 'Clé API non configurée. Ajoutez-la dans Supabase settings.' } });
    }
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      const opts = {
        hostname: 'api.anthropic.com', port: 443, path: '/v1/messages', method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01', 'Content-Length': Buffer.byteLength(body) }
      };
      const pr = https.request(opts, pres => {
        let rb = '';
        pres.on('data', c => rb += c);
        pres.on('end', () => { console.log('Anthropic status:', pres.statusCode, rb.slice(0,200)); res.writeHead(pres.statusCode, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }); res.end(rb); });
      });
      pr.on('error', e => send(res, 502, { error: e.message }));
      pr.write(body); pr.end();
    });
    return;
  }

  // GET /api/dossiers
  if (req.method === 'GET' && url === '/api/dossiers') {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const p = new URLSearchParams(req.url.split('?')[1] || '');
    const { data } = await supa('GET', 'dossiers', { filter: `company_id=eq.${p.get('company_id')}&order=created_at.desc` });
    return send(res, 200, data || []);
  }

  // POST /api/dossiers
  if (req.method === 'POST' && url === '/api/dossiers') {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const body = await parseBody(req);
    const { data } = await supa('POST', 'dossiers', { body: { ...body, created_by: user.id } });
    return send(res, 201, Array.isArray(data) ? data[0] : data);
  }

  // PATCH /api/dossiers/:id (affecter documents)
  if (req.method === 'PATCH' && url.startsWith('/api/dossiers/')) {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const id = url.split('/').pop();
    const body = await parseBody(req);
    await supa('PATCH', `dossiers?id=eq.${id}`, { body });
    return send(res, 200, { ok: true });
  }

  // GET /api/dossiers/:id/items — factures+releves+tva d'un dossier
  if (req.method === 'GET' && url.match(/\/api\/dossiers\/[^/]+\/items/)) {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const dossierId = url.split('/')[3];
    const [factures, releves, tva] = await Promise.all([
      supa('GET', 'factures', { filter: `dossier_id=eq.${dossierId}` }),
      supa('GET', 'transactions', { filter: `dossier_id=eq.${dossierId}` }),
      supa('GET', 'declarations_tva', { filter: `dossier_id=eq.${dossierId}` }),
    ]);
    return send(res, 200, {
      factures: factures.data || [],
      transactions: releves.data || [],
      tva: tva.data || [],
    });
  }

  // PATCH /api/factures-dossier/:id
  if (req.method === 'PATCH' && url.startsWith('/api/factures-dossier/')) {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const id = url.split('/').pop();
    const body = await parseBody(req);
    await supa('PATCH', `factures?id=eq.${id}`, { body: { dossier_id: body.dossier_id } });
    return send(res, 200, { ok: true });
  }

  // PATCH /api/releves-dossier/:id  (alias: /api/transactions-dossier/:id)
  if (req.method === 'PATCH' && (url.startsWith('/api/releves-dossier/') || url.startsWith('/api/transactions-dossier/'))) {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const id = url.split('/').pop();
    const body = await parseBody(req);
    await supa('PATCH', `transactions?id=eq.${id}`, { body: { dossier_id: body.dossier_id } });
    return send(res, 200, { ok: true });
  }

  // PATCH /api/tva-dossier/:id
  if (req.method === 'PATCH' && url.startsWith('/api/tva-dossier/')) {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const id = url.split('/').pop();
    const body = await parseBody(req);
    await supa('PATCH', `declarations_tva?id=eq.${id}`, { body: { dossier_id: body.dossier_id } });
    return send(res, 200, { ok: true });
  }

  // GET /api/tva
  if (req.method === 'GET' && url === '/api/tva') {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const p = new URLSearchParams(req.url.split('?')[1] || '');
    const { data } = await supa('GET', 'declarations_tva', { filter: `company_id=eq.${p.get('company_id')}&order=created_at.desc` });
    return send(res, 200, data || []);
  }

  // POST /api/tva
  if (req.method === 'POST' && url === '/api/tva') {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const body = await parseBody(req);
    const { data, status } = await supa('POST', 'declarations_tva', { body });
    if (status >= 400) return send(res, 400, { error: 'Erreur sauvegarde TVA' });
    return send(res, 201, Array.isArray(data) ? data[0] : data);
  }

  // GET /api/settings
  if (req.method === 'GET' && url === '/api/settings') {
    const user = await getUser(req);
    if (!user) return send(res, 401, { error: 'Non authentifié' });
    const { data } = await supa('GET', 'settings', { filter: 'key=eq.anthropic_api_key' });
    const setting = Array.isArray(data) && data[0] ? data[0] : null;
    if (user.role !== 'admin') return send(res, 200, { has_key: !!setting });
    return send(res, 200, { has_key: !!setting, key: setting ? setting.value : null });
  }

  // POST /api/settings (admin)
  if (req.method === 'POST' && url === '/api/settings') {
    const user = await getUser(req);
    if (!user || user.role !== 'admin') return send(res, 403, { error: 'Admin requis' });
    const body = await parseBody(req);
    const { key, value } = body;
    if (!key || !value) return send(res, 400, { error: 'Champs manquants' });
    const existing = await supa('GET', 'settings', { filter: `key=eq.${key}` });
    if (Array.isArray(existing.data) && existing.data.length) {
      await supa('PATCH', `settings?key=eq.${key}`, { body: { value } });
    } else {
      await supa('POST', 'settings', { body: { key, value } });
    }
    return send(res, 200, { message: 'Paramètre sauvegardé' });
  }

  // Health
  if (url === '/health') return send(res, 200, { ok: true, supabase: !!SUPA_URL });
  if (url === '/test-supa') {
    const result = await supa('GET', 'users', { select: 'id,email' });
    return send(res, 200, { status: result.status, data: result.data });
  }

  // Debug routing (à supprimer après validation)
  if (url === '/api/debug-delete') {
    return send(res, 200, {
      method: req.method,
      raw_url: req.url,
      parsed_url: url,
      parts: url.split('/'),
      parts_length: url.split('/').length,
      test_facture: url.startsWith('/api/factures/') && url.split('/').length === 4,
    });
  }

  send(res, 404, { error: 'Route inconnue: ' + url });
};

// Export pour Vercel serverless
module.exports = handler;

// Démarrage local (ignoré par Vercel)
if (require.main === module) {
  const server = http.createServer(handler);
  server.listen(PORT, '0.0.0.0', () => console.log(`Serveur démarré port ${PORT}`));
}
