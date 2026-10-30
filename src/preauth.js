// Ponte entre "tiquete aceito em /launch" e "interacao OIDC iniciada pelo RP".
//
// O tiquete e CONSUMIDO ja em /launch; o navegador recebe apenas um handle
// aleatorio e opaco (cookie httpOnly) que aponta para um registro em
// memoria. O handle vale por 90s e uma unica vez.
import { randomBytes } from 'node:crypto';

const TTL_MS = 90 * 1000;
const handles = new Map(); // handle -> { userId, expiresAt }

export const PREAUTH_COOKIE = 'bridge_preauth';
export const PREAUTH_TTL_MS = TTL_MS;

export function createPreauth(userId) {
  const handle = randomBytes(32).toString('base64url');
  handles.set(handle, { userId, expiresAt: Date.now() + TTL_MS });
  return handle;
}

/** Retorna o userId e invalida o handle (uso unico), ou null. */
export function takePreauth(handle) {
  if (typeof handle !== 'string' || handle.length > 64) return null;
  const entry = handles.get(handle);
  handles.delete(handle);
  if (!entry || entry.expiresAt <= Date.now()) return null;
  return entry.userId;
}

setInterval(() => {
  const now = Date.now();
  for (const [h, e] of handles) if (e.expiresAt <= now) handles.delete(h);
}, 30 * 1000).unref();
