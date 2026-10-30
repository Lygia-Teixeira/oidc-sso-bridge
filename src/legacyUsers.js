// Repositorio de usuarios da aplicacao legada.
//
// O arquivo SQLite e aberto em modo SOMENTE LEITURA: a ponte nunca altera
// a base de identidade da aplicacao de origem. Em container, monte o volume
// tambem como read-only (defesa em profundidade).
import Database from 'better-sqlite3';
import { config } from './config.js';

const db = new Database(config.legacyDbPath, { readonly: true, fileMustExist: true });
db.pragma('query_only = ON');

// Colunas selecionadas explicitamente - nada de SELECT *.
const COLUMNS = 'id, email, password_hash, display_name, role, is_active, email_2fa_enabled';
const byEmail = db.prepare(`SELECT ${COLUMNS} FROM users WHERE email = ? COLLATE NOCASE LIMIT 1`);
const byId = db.prepare(`SELECT ${COLUMNS} FROM users WHERE id = ? LIMIT 1`);

const EMAIL_MAX = 254;

function normalizeEmail(email) {
  if (typeof email !== 'string') return null;
  const trimmed = email.trim().toLowerCase();
  if (trimmed.length === 0 || trimmed.length > EMAIL_MAX || !trimmed.includes('@')) return null;
  return trimmed;
}

export function findUserByEmail(email) {
  const normalized = normalizeEmail(email);
  return normalized ? byEmail.get(normalized) ?? null : null;
}

export function findUserById(id) {
  const n = Number(id);
  return Number.isSafeInteger(n) && n > 0 ? byId.get(n) ?? null : null;
}

// Regra de elegibilidade aplicada nos DOIS fluxos (senha e tiquete):
// conta ativa e, se configurado, papel permitido.
export function isEligible(user) {
  if (!user || user.is_active !== 1) return false;
  if (config.allowedRoles.length > 0 && !config.allowedRoles.includes(user.role)) return false;
  return true;
}
