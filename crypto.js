"use strict";
/* AES-256-GCM helpers for encrypting credentials at rest.
   ENCRYPTION_KEY must be a 32-byte key, base64-encoded, set only as a
   Render environment variable — never committed to the repo. Losing this
   key makes every stored password unrecoverable; rotating it requires
   re-encrypting the database. */
const crypto = require("crypto");
const { promisify } = require("util");
const scryptAsync = promisify(crypto.scrypt);

function getKey() {
  const raw = process.env.ENCRYPTION_KEY;
  if (!raw) throw new Error("Falta ENCRYPTION_KEY en las variables de entorno.");
  const key = Buffer.from(raw, "base64");
  if (key.length !== 32) {
    throw new Error("ENCRYPTION_KEY debe decodificar a 32 bytes (clave AES-256) en base64.");
  }
  return key;
}

function encrypt(plainText) {
  const key = getKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(String(plainText == null ? "" : plainText), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}

function decrypt(payload) {
  if (!payload) return "";
  const key = getKey();
  const raw = Buffer.from(payload, "base64");
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const enc = raw.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec.toString("utf8");
}

/* Group passphrases (admin/integrante) are now stored in a shared,
   multi-tenant database instead of single per-deploy env vars, so they
   get hashed instead of kept reversible — scrypt (built into Node, no
   native addon to compile, unlike bcrypt) with a random salt per hash,
   compared with a timing-safe equality check. */
async function hashPassphrase(passphrase) {
  const salt = crypto.randomBytes(16);
  const derived = await scryptAsync(String(passphrase == null ? "" : passphrase), salt, 64);
  return salt.toString("hex") + ":" + derived.toString("hex");
}

async function verifyPassphrase(passphrase, stored) {
  if (!stored) return false;
  const parts = String(stored).split(":");
  if (parts.length !== 2) return false;
  const [saltHex, hashHex] = parts;
  let salt, expected;
  try {
    salt = Buffer.from(saltHex, "hex");
    expected = Buffer.from(hashHex, "hex");
  } catch (e) {
    return false;
  }
  if (!salt.length || !expected.length) return false;
  const derived = await scryptAsync(String(passphrase == null ? "" : passphrase), salt, 64);
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

module.exports = { encrypt, decrypt, hashPassphrase, verifyPassphrase };
