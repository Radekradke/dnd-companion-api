import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'dnd-ficha-viva-secret-change-in-prod';
const allowed = (process.env.CORS_ORIGIN || '*').split(',').map(s => s.trim());
const corsOrigin = allowed.includes('*') ? '*' : allowed;

app.use(compression());
app.use(cors({ origin: corsOrigin, credentials: false }));
app.options('*', cors({ origin: corsOrigin, credentials: false }));
app.use(express.json({ limit: '25mb' }));

// Rate limiters
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas tentativas. Aguarde 15 minutos.' }
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Muitas requisições. Aguarde um momento.' }
});

// Extrai deviceId do header (compatibilidade com versão sem auth)
function getDeviceId(req) {
  return String(req.header('x-device-id') || 'default-device').slice(0, 120);
}

// Middleware de autenticação: preenche req.userId se token JWT válido, senão usa deviceId
function authMiddleware(req, _res, next) {
  const header = req.header('Authorization');
  if (header?.startsWith('Bearer ')) {
    try {
      const payload = jwt.verify(header.slice(7), JWT_SECRET);
      req.userId = payload.userId;
      req.authedEmail = payload.email;
    } catch {}
  }
  req.deviceId = getDeviceId(req);
  next();
}

// Retorna o filtro where correto: conta > deviceId
function charWhere(req, extraId) {
  const base = req.userId ? { userId: req.userId } : { deviceId: req.deviceId };
  return extraId ? { id: extraId, ...base } : base;
}

function cleanPayload(body) {
  return {
    name: String(body.name || body.summary?.name || 'Personagem sem nome').slice(0, 160),
    summary: body.summary || {},
    data: body.data || {}
  };
}

// ── HEALTH ─────────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ ok: true, service: 'dnd-ficha-viva-api' }));

// ── AUTH ────────────────────────────────────────────────────────────────────
app.post('/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });
    if (password.length < 6) return res.status(400).json({ error: 'Senha deve ter pelo menos 6 caracteres.' });

    const existing = await prisma.user.findUnique({ where: { email: email.toLowerCase().trim() } });
    if (existing) return res.status(409).json({ error: 'E-mail já cadastrado.' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({ data: { email: email.toLowerCase().trim(), passwordHash } });
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, userId: user.id, email: user.email });
  } catch (e) {
    console.error('[register]', e);
    res.status(500).json({ error: 'Erro ao criar conta.' });
  }
});

app.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });

    const user = await prisma.user.findUnique({ where: { email: email.toLowerCase().trim() } });
    if (!user) return res.status(401).json({ error: 'E-mail ou senha incorretos.' });

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.status(401).json({ error: 'E-mail ou senha incorretos.' });

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, userId: user.id, email: user.email });
  } catch (e) {
    console.error('[login]', e);
    res.status(500).json({ error: 'Erro ao fazer login.' });
  }
});

// Migra personagens salvos por deviceId para a conta do usuário logado
app.post('/auth/migrate-device', authLimiter, authMiddleware, async (req, res) => {
  if (!req.userId) return res.status(401).json({ error: 'Autenticação necessária.' });
  const { deviceId } = req.body || {};
  if (!deviceId) return res.status(400).json({ error: 'deviceId é obrigatório.' });
  try {
    const result = await prisma.character.updateMany({
      where: { deviceId, userId: null },
      data: { userId: req.userId }
    });
    res.json({ migrated: result.count });
  } catch (e) {
    console.error('[migrate-device]', e);
    res.status(500).json({ error: 'Erro ao migrar personagens.' });
  }
});

// ── CHARACTERS ──────────────────────────────────────────────────────────────
app.use('/characters', apiLimiter, authMiddleware);

app.get('/characters', async (req, res) => {
  try {
    const characters = await prisma.character.findMany({
      where: charWhere(req),
      orderBy: { updatedAt: 'desc' },
      select: { id: true, name: true, summary: true, createdAt: true, updatedAt: true }
    });
    res.json({ characters });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erro interno da API' });
  }
});

app.post('/characters', async (req, res) => {
  try {
    const payload = cleanPayload(req.body || {});
    const created = await prisma.character.create({
      data: {
        ...payload,
        deviceId: req.deviceId,
        ...(req.userId ? { userId: req.userId } : {})
      }
    });
    res.json(created);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erro interno da API' });
  }
});

app.get('/characters/:id', async (req, res) => {
  try {
    const item = await prisma.character.findFirst({ where: charWhere(req, req.params.id) });
    if (!item) return res.status(404).json({ error: 'Personagem não encontrado' });
    res.json(item);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erro interno da API' });
  }
});

app.put('/characters/:id', async (req, res) => {
  try {
    const exists = await prisma.character.findFirst({ where: charWhere(req, req.params.id) });
    if (!exists) return res.status(404).json({ error: 'Personagem não encontrado' });
    const payload = cleanPayload(req.body || {});
    const updated = await prisma.character.update({ where: { id: req.params.id }, data: payload });
    res.json(updated);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erro interno da API' });
  }
});

app.delete('/characters/:id', async (req, res) => {
  try {
    const exists = await prisma.character.findFirst({ where: charWhere(req, req.params.id) });
    if (!exists) return res.status(404).json({ error: 'Personagem não encontrado' });
    await prisma.character.delete({ where: { id: req.params.id } });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erro interno da API' });
  }
});

// Gera (ou reaproveita) um token de compartilhamento read-only para o personagem
app.post('/characters/:id/share', async (req, res) => {
  try {
    const character = await prisma.character.findFirst({ where: charWhere(req, req.params.id) });
    if (!character) return res.status(404).json({ error: 'Personagem não encontrado' });
    let share = await prisma.characterShare.findUnique({ where: { characterId: character.id } });
    if (!share) share = await prisma.characterShare.create({ data: { characterId: character.id } });
    res.json({ shareToken: share.token });
  } catch (e) {
    console.error('[share]', e);
    res.status(500).json({ error: 'Erro ao gerar link de compartilhamento.' });
  }
});

// Revoga o compartilhamento do personagem
app.delete('/characters/:id/share', async (req, res) => {
  try {
    const character = await prisma.character.findFirst({ where: charWhere(req, req.params.id) });
    if (!character) return res.status(404).json({ error: 'Personagem não encontrado' });
    await prisma.characterShare.deleteMany({ where: { characterId: character.id } });
    res.json({ ok: true });
  } catch (e) {
    console.error('[share-delete]', e);
    res.status(500).json({ error: 'Erro ao revogar compartilhamento.' });
  }
});

// ── SHARE PÚBLICO (read-only, sem autenticação) ───────────────────────────────
app.get('/share/:token', apiLimiter, async (req, res) => {
  try {
    const share = await prisma.characterShare.findUnique({
      where: { token: req.params.token },
      include: { character: true }
    });
    if (!share || !share.character) return res.status(404).json({ error: 'Ficha compartilhada não encontrada ou revogada.' });
    const c = share.character;
    res.json({ name: c.name, summary: c.summary, data: c.data, updatedAt: c.updatedAt, readOnly: true });
  } catch (e) {
    console.error('[share-get]', e);
    res.status(500).json({ error: 'Erro ao carregar ficha compartilhada.' });
  }
});

// ── ERROR HANDLER ───────────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Erro interno da API' });
});

app.listen(PORT, () => console.log(`D&D Ficha Viva API running on :${PORT}`));
