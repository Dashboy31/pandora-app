"use strict";
require("dotenv").config();

const path = require("path");
const express = require("express");
const cookieParser = require("cookie-parser");
const db = require("./db");
const { encrypt, decrypt, hashPassphrase } = require("./crypto");
const auth = require("./auth");

const REQUIRED_ENV = ["DATABASE_URL", "ENCRYPTION_KEY", "SESSION_SECRET"];
const missing = REQUIRED_ENV.filter(function (k) { return !process.env[k]; });
if (missing.length) {
  console.error("Faltan variables de entorno: " + missing.join(", "));
  console.error("Mirá .env.example para ver qué tiene que llevar cada una.");
  process.exit(1);
}

const app = express();
app.set("trust proxy", 1); // Render está detrás de un proxy TLS
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

/* Envuelve un handler async para que una excepción (o un reject) llegue
   al manejador de errores de Express en vez de colgar el request —
   Express 4 no hace esto solo para funciones async. */
function ah(fn) {
  return function (req, res, next) {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

function rowToPlatform(row, includeSecret) {
  const out = {
    id: row.id,
    name: row.name,
    user: row.account_user || "",
    asksCode: !!row.asks_code,
    verifyEmail: row.verify_email || "",
    notes: row.notes || ""
  };
  if (includeSecret) out.password = decrypt(row.password_enc);
  return out;
}

const COOKIE_OPTS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  maxAge: 30 * 24 * 60 * 60 * 1000
};

/* ---- grupos ---- */

app.post("/api/groups", auth.createGroupLimiter, ah(async function (req, res) {
  const b = req.body || {};
  const name = String(b.name || "").trim();
  const adminPass = String(b.adminPassphrase || "");
  const memberPass = String(b.memberPassphrase || "");
  if (!name) return res.status(400).json({ error: "Falta el nombre del grupo." });
  if (name.length > 60) return res.status(400).json({ error: "El nombre es muy largo." });
  if (adminPass.length < 4 || memberPass.length < 4) {
    return res.status(400).json({ error: "Las dos claves tienen que tener al menos 4 caracteres." });
  }
  if (adminPass === memberPass) {
    return res.status(400).json({ error: "La clave de administrador y la de integrante tienen que ser distintas." });
  }
  const adminHash = await hashPassphrase(adminPass);
  const memberHash = await hashPassphrase(memberPass);
  const group = await db.createGroup({ name: name, adminHash: adminHash, memberHash: memberHash });
  // Crear el grupo deja logueado como admin directamente, sin un paso más.
  const token = auth.issueToken(group.id, "admin");
  res.cookie(auth.COOKIE_NAME, token, COOKIE_OPTS);
  res.status(201).json({ role: "admin", groupName: group.name, groupCode: group.code });
}));

app.post("/api/login", auth.loginLimiter, ah(async function (req, res) {
  const code = (req.body && req.body.code) || "";
  const passphrase = (req.body && req.body.passphrase) || "";
  const resolved = await auth.resolveGroupAndRole(code, passphrase);
  if (!resolved) return res.status(401).json({ error: "Código o clave incorrectos." });
  const token = auth.issueToken(resolved.groupId, resolved.role);
  res.cookie(auth.COOKIE_NAME, token, COOKIE_OPTS);
  res.json({ role: resolved.role, groupName: resolved.groupName, groupCode: resolved.groupCode });
}));

app.post("/api/logout", ah(async function (req, res) {
  await auth.revokeCurrentToken(req);
  res.clearCookie(auth.COOKIE_NAME, { httpOnly: true, sameSite: "lax", secure: COOKIE_OPTS.secure });
  res.json({ ok: true });
}));

app.get("/api/session", ah(async function (req, res) {
  const session = await auth.readSession(req);
  if (!session) return res.json({ role: null });
  const group = await db.getGroupById(session.groupId);
  if (!group) return res.json({ role: null });
  res.json({ role: session.role, groupName: group.name, groupCode: group.code });
}));

/* ---- plataformas (todo escapado por grupo) ---- */

app.get("/api/platforms", auth.requireAuth, ah(async function (req, res) {
  const r = await db.pool.query(
    "SELECT * FROM platforms WHERE group_id = $1 ORDER BY created_at ASC",
    [req.pandoraGroupId]
  );
  res.json(r.rows.map(function (row) { return rowToPlatform(row, false); }));
}));

app.get("/api/platforms/:id", auth.requireAuth, ah(async function (req, res) {
  const r = await db.pool.query(
    "SELECT * FROM platforms WHERE id = $1 AND group_id = $2",
    [req.params.id, req.pandoraGroupId]
  );
  const row = r.rows[0];
  if (!row) return res.status(404).json({ error: "No encontrada." });
  res.json(rowToPlatform(row, true));
}));

app.post("/api/platforms", auth.requireAuth, auth.requireAdmin, ah(async function (req, res) {
  const b = req.body || {};
  const name = String(b.name || "").trim();
  if (!name) return res.status(400).json({ error: "Falta el nombre de la plataforma." });
  const id = db.newId();
  const row = {
    id: id,
    group_id: req.pandoraGroupId,
    name: name,
    account_user: String(b.user || "").trim(),
    password_enc: encrypt(b.password || ""),
    asks_code: !!b.asksCode,
    verify_email: String(b.verifyEmail || "").trim(),
    notes: String(b.notes || "").trim()
  };
  await db.pool.query(
    `INSERT INTO platforms (id, group_id, name, account_user, password_enc, asks_code, verify_email, notes)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [row.id, row.group_id, row.name, row.account_user, row.password_enc, row.asks_code, row.verify_email, row.notes]
  );
  res.status(201).json(rowToPlatform(row, true));
}));

app.put("/api/platforms/:id", auth.requireAuth, auth.requireAdmin, ah(async function (req, res) {
  const existing = await db.pool.query(
    "SELECT * FROM platforms WHERE id = $1 AND group_id = $2",
    [req.params.id, req.pandoraGroupId]
  );
  if (!existing.rows[0]) return res.status(404).json({ error: "No encontrada." });
  const b = req.body || {};
  const name = String(b.name || "").trim();
  if (!name) return res.status(400).json({ error: "Falta el nombre de la plataforma." });
  const row = {
    id: req.params.id,
    name: name,
    account_user: String(b.user || "").trim(),
    password_enc: encrypt(b.password || ""),
    asks_code: !!b.asksCode,
    verify_email: String(b.verifyEmail || "").trim(),
    notes: String(b.notes || "").trim()
  };
  await db.pool.query(
    `UPDATE platforms SET name=$1, account_user=$2, password_enc=$3, asks_code=$4,
     verify_email=$5, notes=$6, updated_at=now() WHERE id=$7 AND group_id=$8`,
    [row.name, row.account_user, row.password_enc, row.asks_code, row.verify_email, row.notes, row.id, req.pandoraGroupId]
  );
  const r = await db.pool.query("SELECT * FROM platforms WHERE id = $1 AND group_id = $2", [req.params.id, req.pandoraGroupId]);
  res.json(rowToPlatform(r.rows[0], true));
}));

app.delete("/api/platforms/:id", auth.requireAuth, auth.requireAdmin, ah(async function (req, res) {
  await db.pool.query("DELETE FROM platforms WHERE id = $1 AND group_id = $2", [req.params.id, req.pandoraGroupId]);
  res.json({ ok: true });
}));

app.get(/^\/(?!api\/).*/, function (req, res) {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// eslint-disable-next-line no-unused-vars
app.use(function (err, req, res, next) {
  console.error(err);
  res.status(500).json({ error: "Error interno del servidor." });
});

const PORT = process.env.PORT || 3000;
db.init()
  .then(function () {
    app.listen(PORT, function () {
      console.log("Pandora backend escuchando en el puerto " + PORT);
    });
  })
  .catch(function (e) {
    console.error("No se pudo inicializar la base de datos:", e);
    process.exit(1);
  });
