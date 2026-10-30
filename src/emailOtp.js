// Segundo fator por codigo enviado ao e-mail.
//
// - codigo de 6 digitos gerado com CSPRNG (crypto.randomInt)
// - guardado apenas como HMAC (nunca o codigo em claro na memoria)
// - amarrado a interacao OIDC + usuario
// - expira em 5 minutos e aceita no maximo 5 tentativas
// - comparacao em tempo constante
import { createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { sendMail } from './mailer.js';

const TTL_MS = 5 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const pepper = randomBytes(32); // por processo; reiniciar invalida codigos pendentes
const challenges = new Map(); // interactionUid -> { digest, userId, expiresAt, attempts }

function digest(uid, code) {
  return createHmac('sha256', pepper).update(`${uid}:${code}`).digest();
}

export function hasPendingChallenge(uid) {
  const c = challenges.get(uid);
  return Boolean(c && c.expiresAt > Date.now());
}

export async function issueChallenge(uid, user) {
  const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
  challenges.set(uid, { digest: digest(uid, code), userId: user.id, expiresAt: Date.now() + TTL_MS, attempts: 0 });
  await sendMail({
    to: user.email,
    subject: 'Seu codigo de verificacao',
    text: `Codigo de verificacao: ${code}\n\nValido por 5 minutos. Se nao foi voce, ignore esta mensagem.`,
  });
}

/** @returns {{ ok: true, userId: number } | { ok: false, reason: string, final: boolean }} */
export function verifyChallenge(uid, submitted) {
  const c = challenges.get(uid);
  if (!c || c.expiresAt <= Date.now()) {
    challenges.delete(uid);
    return { ok: false, reason: 'expired', final: true };
  }
  c.attempts += 1;
  const code = String(submitted ?? '').trim();
  const valid = /^\d{6}$/.test(code) && timingSafeEqual(c.digest, digest(uid, code));
  if (valid) {
    challenges.delete(uid);
    return { ok: true, userId: c.userId };
  }
  if (c.attempts >= MAX_ATTEMPTS) {
    challenges.delete(uid);
    return { ok: false, reason: 'too_many_attempts', final: true };
  }
  return { ok: false, reason: 'invalid_code', final: false };
}

setInterval(() => {
  const now = Date.now();
  for (const [uid, c] of challenges) if (c.expiresAt <= now) challenges.delete(uid);
}, 60 * 1000).unref();
