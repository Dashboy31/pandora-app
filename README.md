# Pandora — backend

Backend real de Pandora: credenciales del grupo guardadas en SQLite, cifradas
en reposo (AES-256-GCM), detrás de un login con dos claves compartidas
(administrador / integrante).

## Variables de entorno requeridas

Ver `.env.example`. Las cuatro son obligatorias — el servidor no arranca si
falta alguna: `ADMIN_PASSPHRASE`, `MEMBER_PASSPHRASE`, `ENCRYPTION_KEY`,
`SESSION_SECRET`.

## Correrlo localmente

```
npm install
cp .env.example .env   # y completá las claves
npm start
```

Abrí `http://localhost:3000`.

## Deploy

Pensado para Render, con `render.yaml` (Blueprint) y disco persistente en
`/data` para que la base de datos no se borre en cada deploy. Los pasos para
conectar el repo y cargar las variables de entorno están en la conversación
de Claude donde se armó este proyecto — no hay nada que correr a mano más
que eso.

## Modelo de seguridad (y sus límites)

- Las contraseñas de cada plataforma se cifran antes de guardarse en la base
  (AES-256-GCM) con una clave que vive solo en Render, nunca en el repo.
- Cada pedido a la API exige estar logueado; solo el rol administrador puede
  agregar, editar o borrar.
- Es un modelo de **dos claves compartidas**, no cuentas individuales: no
  diferencia qué integrante hizo cada cambio. Para eso (o para cifrado
  "zero-knowledge" con contraseña maestra por persona) hace falta otra vuelta
  de desarrollo.
