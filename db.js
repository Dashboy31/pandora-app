"use strict";
const { Pool } = require("pg");
const crypto = require("crypto");

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error("Falta DATABASE_URL en las variables de entorno (cadena de conexión de Postgres).");
  process.exit(1);
}

/* Neon (y la mayoría de los Postgres gestionados) requieren TLS y usan
   certificados que Node no valida por default sin la CA correspondiente;
   rejectUnauthorized:false sigue cifrando la conexión, solo no verifica
   la cadena de certificados — razonable para esta escala. Se puede
   desactivar poniendo "?sslmode=disable" en DATABASE_URL (Postgres local
   sin TLS, por ejemplo para probar). */
const useSSL = !/sslmode=disable/i.test(connectionString);
const pool = new Pool({
  connectionString,
  ssl: useSSL ? { rejectUnauthorized: false } : false
});

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS groups (
      id TEXT PRIMARY KEY,
      code TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      admin_hash TEXT NOT NULL,
      member_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS platforms (
      id TEXT PRIMARY KEY,
      group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      account_user TEXT,
      password_enc TEXT,
      asks_code BOOLEAN NOT NULL DEFAULT false,
      verify_email TEXT,
      notes TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS idx_platforms_group ON platforms(group_id);
    CREATE TABLE IF NOT EXISTS revoked_tokens (
      jti TEXT PRIMARY KEY,
      revoked_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

/* Logout revoca solo el jti de ESE token — no cierra sesión a todo el
   grupo, que comparte rol pero no dispositivo. Se barren entradas viejas
   porque ningún token puede durar más de 30 días igual. */
async function isRevoked(jti) {
  const r = await pool.query("SELECT 1 FROM revoked_tokens WHERE jti = $1", [jti]);
  return r.rowCount > 0;
}
async function revokeToken(jti) {
  await pool.query("INSERT INTO revoked_tokens (jti, revoked_at) VALUES ($1, now()) ON CONFLICT DO NOTHING", [jti]);
  await pool.query("DELETE FROM revoked_tokens WHERE revoked_at < now() - interval '31 days'");
}

function newId(prefix) {
  return (prefix || "p") + crypto.randomBytes(6).toString("hex");
}

/* Código corto para compartir el grupo (vía link o de palabra). Alfabeto
   sin 0/O/1/I/L para que no se confunda al leerlo o escribirlo a mano. */
const CODE_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";
function randomCode(len) {
  const bytes = crypto.randomBytes(len);
  let out = "";
  for (let i = 0; i < len; i++) out += CODE_ALPHABET[bytes[i] % CODE_ALPHABET.length];
  return out;
}

async function createGroup({ name, adminHash, memberHash }) {
  const id = newId("g");
  for (let attempt = 0; attempt < 5; attempt++) {
    const code = randomCode(6);
    try {
      await pool.query(
        "INSERT INTO groups (id, code, name, admin_hash, member_hash) VALUES ($1, $2, $3, $4, $5)",
        [id, code, name, adminHash, memberHash]
      );
      return { id, code, name };
    } catch (e) {
      if (e && e.code === "23505") continue; // choque de código único: reintentar con otro
      throw e;
    }
  }
  throw new Error("No se pudo generar un código de grupo único, probá de nuevo.");
}

async function getGroupByCode(code) {
  const r = await pool.query("SELECT * FROM groups WHERE code = $1", [String(code || "").trim().toUpperCase()]);
  return r.rows[0] || null;
}

async function getGroupById(id) {
  const r = await pool.query("SELECT * FROM groups WHERE id = $1", [id]);
  return r.rows[0] || null;
}

module.exports = {
  pool,
  init,
  isRevoked,
  revokeToken,
  newId,
  createGroup,
  getGroupByCode,
  getGroupById
};
