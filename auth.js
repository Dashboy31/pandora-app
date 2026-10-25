"use strict";
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { isRevoked, revokeToken, getGroupByCode } = require("./db");
const { verifyPassphrase } = require("./crypto");

const COOKIE_NAME = "pandora_session";
const TOKEN_TTL = "30d";

function getSecret() {
  const s = process.env.SESSION_SECRET;
  if (!s) throw new Error("Falta SESSION_SECRET en las variables de entorno.");
  return s;
}

/* Multi-grupo: el código identifica el grupo, la frase (comparada contra
   el hash de admin o de integrante de ESE grupo) decide el rol adentro
   de él. No se distingue en la respuesta si falló el código o la frase,
   para no filtrar cuáles códigos existen. */
async function resolveGroupAndRole(code, passphrase) {
  const group = await getGroupByCode(code);
  if (!group) return null;
  if (await verifyPassphrase(passphrase, group.admin_hash)) {
    return { groupId: group.id, groupName: group.name, groupCode: group.code, role: "admin" };
  }
  if (await verifyPassphrase(passphrase, group.member_hash)) {
    return { groupId: group.id, groupName: group.name, groupCode: group.code, role: "member" };
  }
  return null;
}

function issueToken(groupId, role) {
  const jti = crypto.randomBytes(12).toString("hex");
  return jwt.sign({ gid: groupId, role: role, jti: jti }, getSecret(), { expiresIn: TOKEN_TTL });
}

/* Devuelve { role, groupId } o null — ya validado y no revocado. */
async function readSession(req) {
  const token = req.cookies && req.cookies[COOKIE_NAME];
  if (!token) return null;
  let payload;
  try {
    payload = jwt.verify(token, getSecret());
  } catch (e) {
    return null;
  }
  if (payload.role !== "admin" && payload.role !== "member") return null;
  if (!payload.gid || !payload.jti) return null;
  if (await isRevoked(payload.jti)) return null; // ya se cerró sesión con este token
  return { role: payload.role, groupId: payload.gid };
}

/* Logout revoca solo el jti de este token/dispositivo — no afecta a
   otros miembros del grupo que comparten el mismo rol. */
async function revokeCurrentToken(req) {
  const token = req.cookies && req.cookies[COOKIE_NAME];
  if (!token) return;
  try {
    const payload = jwt.verify(token, getSecret(), { ignoreExpiration: true });
    if (payload.jti) await revokeToken(payload.jti);
  } catch (e) {
    // token ilegible o ya vencido: no hay nada que revocar
  }
}

async function requireAuth(req, res, next) {
  try {
    const session = await readSession(req);
    if (!session) return res.status(401).json({ error: "No autenticado." });
    req.pandoraRole = session.role;
    req.pandoraGroupId = session.groupId;
    next();
  } catch (e) {
    next(e);
  }
}

function requireAdmin(req, res, next) {
  if (req.pandoraRole !== "admin") return res.status(403).json({ error: "Requiere rol administrador." });
  next();
}

/* Frenos de fuerza bruta en memoria, por IP. Se reinician si el server
   reinicia (y en el plan Free, Render puede dormir/reiniciar el proceso
   con más frecuencia) — es un freno, no una defensa perfecta. */
function makeLimiter(max, windowMs, message) {
  const attempts = new Map();
  return function (req, res, next) {
    const ip = req.ip || "unknown";
    const now = Date.now();
    let rec = attempts.get(ip);
    if (!rec || now > rec.resetAt) rec = { count: 0, resetAt: now + windowMs };
    if (rec.count >= max) {
      return res.status(429).json({ error: message });
    }
    rec.count++;
    attempts.set(ip, rec);
    next();
  };
}

const loginLimiter = makeLimiter(10, 15 * 60 * 1000, "Demasiados intentos. Probá de nuevo en unos minutos.");
const createGroupLimiter = makeLimiter(5, 60 * 60 * 1000, "Demasiados grupos creados desde acá. Probá de nuevo más tarde.");

module.exports = {
  COOKIE_NAME,
  resolveGroupAndRole,
  issueToken,
  readSession,
  revokeCurrentToken,
  requireAuth,
  requireAdmin,
  loginLimiter,
  createGroupLimiter
};
