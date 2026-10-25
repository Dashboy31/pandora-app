"use strict";
const Database = require("better-sqlite3");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { encrypt } = require("./crypto");

const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data", "pandora.db");
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS platforms (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    user TEXT,
    password_enc TEXT,
    asks_code INTEGER NOT NULL DEFAULT 0,
    verify_email TEXT,
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti TEXT PRIMARY KEY,
    revoked_at TEXT NOT NULL
  );
`);

/* Login tokens are stateless JWTs, so an explicit logout has nothing to
   delete server-side unless we track it: each token carries a random
   jti, and logging out records that jti here so the same token can never
   be used again, even if someone had copied the cookie before the
   logout. This revokes only THIS token/device — not every family member
   sharing the same role — which matches what "cerrar sesión" should mean
   day to day. Old entries are swept since a token can't outlive 30 days
   anyway. */
function isRevoked(jti) {
  return !!db.prepare("SELECT 1 FROM revoked_tokens WHERE jti = ?").get(jti);
}
function revokeToken(jti) {
  db.prepare("INSERT OR IGNORE INTO revoked_tokens (jti, revoked_at) VALUES (?, ?)").run(jti, new Date().toISOString());
  db.prepare("DELETE FROM revoked_tokens WHERE revoked_at < ?").run(
    new Date(Date.now() - 31 * 24 * 60 * 60 * 1000).toISOString()
  );
}

function newId() {
  return "p" + crypto.randomBytes(6).toString("hex");
}

function seedIfEmpty() {
  const row = db.prepare("SELECT COUNT(*) AS n FROM platforms").get();
  if (row.n > 0) return;
  const now = new Date().toISOString();
  const seed = [
    { name: "Netflix", user: "familia@ejemplo.com", password: "nf-ejemplo-2026", asksCode: 1, verifyEmail: "familia@ejemplo.com", notes: "Si pide un código, avisar al administrador para revisar el correo." },
    { name: "Spotify Familiar", user: "familia@ejemplo.com", password: "sp-ejemplo-2026", asksCode: 0, verifyEmail: "", notes: "Cada integrante arma su propia playlist, pero la cuenta es una sola." },
    { name: "Disney+", user: "familia@ejemplo.com", password: "dp-ejemplo-2026", asksCode: 1, verifyEmail: "otrocorreo@ejemplo.com", notes: "El perfil \"Peques\" tiene control parental activado." }
  ];
  const insert = db.prepare(`INSERT INTO platforms (id, name, user, password_enc, asks_code, verify_email, notes, created_at, updated_at)
    VALUES (@id, @name, @user, @password_enc, @asks_code, @verify_email, @notes, @created_at, @updated_at)`);
  seed.forEach(function (p) {
    insert.run({
      id: newId(),
      name: p.name,
      user: p.user,
      password_enc: encrypt(p.password),
      asks_code: p.asksCode,
      verify_email: p.verifyEmail,
      notes: p.notes,
      created_at: now,
      updated_at: now
    });
  });
}

module.exports = { db, seedIfEmpty, newId, isRevoked, revokeToken };
