"use strict";
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { isRevoked, revokeToken } = require("./db");

const COOKIE_NAME = "pandora_session";
const TOKEN_TTL = "30d";

function getSecret() {
  const s = process.env.SESSION_SECRET;
  if (!s) throw new Error("Falta SESSION_SECRET en las variables de entorno.");
  return s;
}

function timingSafeEqualStr(a, b) {
  const bufA = Buffer.from(String(a || ""));
  const bufB = Buffer.from(String(b || ""));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/* Two shared passphrases (admin / integrante) decide the role — simplest
   model that still means nobody gets in without a real secret, and that
   only the admin passphrase can add/edit/delete. Not per-person accounts;
   good enough for a family group testing the idea, not a substitute for
   per-user auth if this grows beyond the family. */
function roleForPassphrase(passphrase) {
  const adminPass = process.env.ADMIN_PASSPHRASE || "";
  const memberPass = process.env.MEMBER_PASSPHRASE || "";
  if (adminPass && timingSafeEqualStr(passphrase, adminPass)) return "admin";
  if (memberPass && timingSafeEqualStr(passphrase, memberPass)) return "member";
  return null;
}

function issueToken(role) {
  const jti = crypto.randomBytes(12).toString("hex");
  return jwt.sign({ role: role, jti: jti }, getSecret(), { expiresIn: TOKEN_TTL });
}

function readRole(req) {
  const token = req.cookies && req.cookies[COOKIE_NAME];
  if (!token) return null;
  try {
    const payload = jwt.verify(token, getSecret());
    if (payload.role !== "admin" && payload.role !== "member") return null;
    if (!payload.jti || isRevoked(payload.jti)) return null; // ya se cerró sesión con este token
    return payload.role;
  } catch (e) {
    return null;
  }
}

/* Logout revokes just the jti of the token being logged out — this
   device's session only, not every family member sharing the role. */
function revokeCurrentToken(req) {
  const token = req.cookies && req.cookies[COOKIE_NAME];
  if (!token) return;
  try {
    const payload = jwt.verify(token, getSecret(), { ignoreExpiration: true });
    if (payload.jti) revokeToken(payload.jti);
  } catch (e) {
    // token ilegible o ya vencido: no hay nada que revocar
  }
}

function requireAuth(req, res, next) {
  const role = readRole(req);
  if (!role) return res.status(401).json({ error: "No autenticado." });
  req.pandoraRole = role;
  next();
}

function requireAdmin(req, res, next) {
  if (req.pandoraRole !== "admin") return res.status(403).json({ error: "Requiere rol administrador." });
  next();
}

/* Tiny in-memory brute-force brake on /api/login: 10 intentos cada 15
   minutos por IP. Se reinicia si el servidor reinicia — es un freno, no
   una defensa perfecta, pero ya es infinitamente más que la API de MIFA
   tenía al principio (nada). */
const attempts = new Map();
function loginLimiter(req, res, next) {
  const ip = req.ip || "unknown";
  const now = Date.now();
  let rec = attempts.get(ip);
  if (!rec || now > rec.resetAt) rec = { count: 0, resetAt: now + 15 * 60 * 1000 };
  if (rec.count >= 10) {
    return res.status(429).json({ error: "Demasiados intentos. Probá de nuevo en unos minutos." });
  }
  rec.count++;
  attempts.set(ip, rec);
  next();
}

module.exports = { COOKIE_NAME, roleForPassphrase, issueToken, readRole, revokeCurrentToken, requireAuth, requireAdmin, loginLimiter };
