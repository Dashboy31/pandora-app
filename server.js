"use strict";
require("dotenv").config();

const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cookieParser = require("cookie-parser");
const { db, seedIfEmpty, newId } = require("./db");
const { encrypt, decrypt } = require("./crypto");
const auth = require("./auth");

const REQUIRED_ENV = ["ADMIN_PASSPHRASE", "MEMBER_PASSPHRASE", "ENCRYPTION_KEY", "SESSION_SECRET"];
const missing = REQUIRED_ENV.filter(function (k) { return !process.env[k]; });
if (missing.length) {
  console.error("Faltan variables de entorno: " + missing.join(", "));
  console.error("Mirá .env.example para ver qué tiene que llevar cada una.");
  process.exit(1);
}

seedIfEmpty();

const app = express();
app.set("trust proxy", 1); // Render está detrás de un proxy TLS
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

function rowToPlatform(row, includeSecret) {
  const out = {
    id: row.id,
    name: row.name,
    user: row.user || "",
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

app.post("/api/login", auth.loginLimiter, function (req, res) {
  const passphrase = (req.body && req.body.passphrase) || "";
  const role = auth.roleForPassphrase(passphrase);
  if (!role) return res.status(401).json({ error: "Clave incorrecta." });
  const token = auth.issueToken(role);
  res.cookie(auth.COOKIE_NAME, token, COOKIE_OPTS);
  res.json({ role: role });
});

app.post("/api/logout", function (req, res) {
  auth.revokeCurrentToken(req);
  res.clearCookie(auth.COOKIE_NAME, { httpOnly: true, sameSite: "lax", secure: COOKIE_OPTS.secure });
  res.json({ ok: true });
});

app.get("/api/session", function (req, res) {
  res.json({ role: auth.readRole(req) });
});

app.get("/api/platforms", auth.requireAuth, function (req, res) {
  const rows = db.prepare("SELECT * FROM platforms ORDER BY created_at ASC").all();
  res.json(rows.map(function (r) { return rowToPlatform(r, false); }));
});

app.get("/api/platforms/:id", auth.requireAuth, function (req, res) {
  const row = db.prepare("SELECT * FROM platforms WHERE id = ?").get(req.params.id);
  if (!row) return res.status(404).json({ error: "No encontrada." });
  res.json(rowToPlatform(row, true));
});

app.post("/api/platforms", auth.requireAuth, auth.requireAdmin, function (req, res) {
  const b = req.body || {};
  const name = String(b.name || "").trim();
  if (!name) return res.status(400).json({ error: "Falta el nombre de la plataforma." });
  const now = new Date().toISOString();
  const row = {
    id: newId(),
    name: name,
    user: String(b.user || "").trim(),
    password_enc: encrypt(b.password || ""),
    asks_code: b.asksCode ? 1 : 0,
    verify_email: String(b.verifyEmail || "").trim(),
    notes: String(b.notes || "").trim(),
    created_at: now,
    updated_at: now
  };
  db.prepare(`INSERT INTO platforms (id, name, user, password_enc, asks_code, verify_email, notes, created_at, updated_at)
    VALUES (@id, @name, @user, @password_enc, @asks_code, @verify_email, @notes, @created_at, @updated_at)`).run(row);
  res.status(201).json(rowToPlatform(row, true));
});

app.put("/api/platforms/:id", auth.requireAuth, auth.requireAdmin, function (req, res) {
  const existing = db.prepare("SELECT * FROM platforms WHERE id = ?").get(req.params.id);
  if (!existing) return res.status(404).json({ error: "No encontrada." });
  const b = req.body || {};
  const name = String(b.name || "").trim();
  if (!name) return res.status(400).json({ error: "Falta el nombre de la plataforma." });
  const now = new Date().toISOString();
  db.prepare(`UPDATE platforms SET name=@name, user=@user, password_enc=@password_enc, asks_code=@asks_code,
    verify_email=@verify_email, notes=@notes, updated_at=@updated_at WHERE id=@id`).run({
    id: req.params.id,
    name: name,
    user: String(b.user || "").trim(),
    password_enc: encrypt(b.password || ""),
    asks_code: b.asksCode ? 1 : 0,
    verify_email: String(b.verifyEmail || "").trim(),
    notes: String(b.notes || "").trim(),
    updated_at: now
  });
  const row = db.prepare("SELECT * FROM platforms WHERE id = ?").get(req.params.id);
  res.json(rowToPlatform(row, true));
});

app.delete("/api/platforms/:id", auth.requireAuth, auth.requireAdmin, function (req, res) {
  db.prepare("DELETE FROM platforms WHERE id = ?").run(req.params.id);
  res.json({ ok: true });
});

app.get(/^\/(?!api\/).*/, function (req, res) {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, function () {
  console.log("Pandora backend escuchando en el puerto " + PORT);
});
