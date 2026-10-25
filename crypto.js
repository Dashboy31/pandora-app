"use strict";
/* AES-256-GCM helpers for encrypting credentials at rest.
   ENCRYPTION_KEY must be a 32-byte key, base64-encoded, set only as a
   Render environment variable — never committed to the repo. Losing this
   key makes every stored password unrecoverable; rotating it requires
   re-encrypting the database. */
const crypto = require("crypto");

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

module.exports = { encrypt, decrypt };
