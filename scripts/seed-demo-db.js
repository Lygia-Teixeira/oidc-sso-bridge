// Cria um SQLite de DEMONSTRACAO simulando a base de usuarios da aplicacao
// legada. Usuarios ficticios (dominio example.com); senhas aleatorias
// geradas na hora e exibidas UMA vez no terminal.
//
// Uso: node scripts/seed-demo-db.js [caminho.db] [--force]
import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';

const args = process.argv.slice(2);
const force = args.includes('--force');
const target = resolve(args.find((a) => !a.startsWith('--')) ?? 'data/legacy-demo.db');

if (existsSync(target)) {
  if (!force) {
    console.error(`${target} ja existe. Use --force para recriar.`);
    process.exit(1);
  }
  rmSync(target);
}
mkdirSync(dirname(target), { recursive: true });

const db = new Database(target);
db.exec(`
  CREATE TABLE users (
    id                INTEGER PRIMARY KEY,
    email             TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash     TEXT    NOT NULL,
    display_name      TEXT,
    role              TEXT    NOT NULL DEFAULT 'member',
    is_active         INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    email_2fa_enabled INTEGER NOT NULL DEFAULT 0 CHECK (email_2fa_enabled IN (0, 1))
  );
`);

const demoUsers = [
  { email: 'ana@example.com', name: 'Ana Exemplo', role: 'admin', active: 1, otp: 1, note: 'com 2FA por e-mail' },
  { email: 'bruno@example.com', name: 'Bruno Exemplo', role: 'member', active: 1, otp: 0, note: 'sem 2FA' },
  { email: 'carla@example.com', name: 'Carla Exemplo', role: 'member', active: 0, otp: 0, note: 'conta desativada (deve ser recusada)' },
];

const insert = db.prepare(
  'INSERT INTO users (email, password_hash, display_name, role, is_active, email_2fa_enabled) VALUES (?, ?, ?, ?, ?, ?)',
);

console.log(`Banco de demonstracao criado em ${target}\n`);
for (const u of demoUsers) {
  const password = randomBytes(12).toString('base64url');
  const info = insert.run(u.email, bcrypt.hashSync(password, 12), u.name, u.role, u.active, u.otp);
  console.log(`  id=${info.lastInsertRowid}  ${u.email.padEnd(20)} senha: ${password}   (${u.note})`);
}
db.close();
console.log('\nSenhas exibidas apenas agora. Dados ficticios - nao reutilize em nenhum outro lugar.');
