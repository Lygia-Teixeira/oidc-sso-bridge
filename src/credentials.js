// Verificacao de senha + bloqueio progressivo por conta.
import bcrypt from 'bcryptjs';

const PASSWORD_MAX_BYTES = 72; // limite do bcrypt; acima disso bytes seriam ignorados

// Hash "isca" para gastar o mesmo tempo quando o usuario nao existe,
// evitando enumeracao de contas por diferenca de tempo de resposta.
const DECOY_HASH = bcrypt.hashSync('decoy-password-for-constant-time', 12);

export async function checkPassword(user, password) {
  if (typeof password !== 'string' || password.length === 0) return false;
  if (Buffer.byteLength(password, 'utf8') > PASSWORD_MAX_BYTES) {
    await bcrypt.compare('x', DECOY_HASH);
    return false;
  }
  if (!user || typeof user.password_hash !== 'string') {
    await bcrypt.compare(password, DECOY_HASH);
    return false;
  }
  return bcrypt.compare(password, user.password_hash);
}

// Bloqueio por conta, em memoria. Complementa o rate limit por IP
// (ver routes/interaction.js): protege contra ataque distribuido a UMA
// conta. A ponte nao escreve no banco legado, por isso o estado fica aqui.
const MAX_FAILURES = 5;
const WINDOW_MS = 15 * 60 * 1000;
const LOCK_MS = 15 * 60 * 1000;
const failures = new Map(); // chave -> { count, firstAt, lockedUntil }

function key(email) {
  return String(email || '').trim().toLowerCase();
}

export function lockRemainingMs(email) {
  const entry = failures.get(key(email));
  if (!entry?.lockedUntil) return 0;
  return Math.max(0, entry.lockedUntil - Date.now());
}

export function recordFailure(email) {
  const k = key(email);
  const now = Date.now();
  let entry = failures.get(k);
  if (!entry || now - entry.firstAt > WINDOW_MS) entry = { count: 0, firstAt: now, lockedUntil: 0 };
  entry.count += 1;
  if (entry.count >= MAX_FAILURES) entry.lockedUntil = now + LOCK_MS;
  failures.set(k, entry);
}

export function clearFailures(email) {
  failures.delete(key(email));
}

setInterval(() => {
  const now = Date.now();
  for (const [k, entry] of failures) {
    if (now - entry.firstAt > WINDOW_MS && now > entry.lockedUntil) failures.delete(k);
  }
}, 60 * 1000).unref();
