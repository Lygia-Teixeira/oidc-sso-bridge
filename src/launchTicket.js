// "Launch ticket": prova curta, assinada e de uso unico de que o usuario
// acabou de se autenticar NA APLICACAO LEGADA (que ja aplicou senha e 2FA
// dela). Permite abrir o Relying Party sem redigitar a senha.
//
// Formato (compacto, sem dependencia de biblioteca JWT):
//   lt1.<base64url(JSON payload)>.<base64url(HMAC-SHA256(chave, "lt1." + payload))>
//
// Payload: { sub, aud, iat, exp, jti }
//   - sub: id do usuario na base legada (sem e-mail: nada de PII no tiquete)
//   - aud: deve ser exatamente o audience desta ponte
//   - exp - iat <= teto configurado (60s por padrao, maximo absoluto 120s)
//   - jti: aleatorio >= 128 bits; registrado ao consumir para bloquear replay
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const PREFIX = 'lt1';
const CLOCK_SKEW_S = 5;
const MAX_TICKET_LENGTH = 1024;

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function mac(secret, signingInput) {
  return createHmac('sha256', secret).update(signingInput).digest();
}

// Usado pela aplicacao legada (ou pelo script de demonstracao) para emitir.
export function signLaunchTicket({ secret, sub, audience, ttlSeconds = 60 }) {
  const now = Math.floor(Date.now() / 1000);
  const payload = { sub: String(sub), aud: audience, iat: now, exp: now + ttlSeconds, jti: b64url(randomBytes(16)) };
  const body = b64url(JSON.stringify(payload));
  const signingInput = `${PREFIX}.${body}`;
  return `${signingInput}.${b64url(mac(secret, signingInput))}`;
}

// Registro de jti ja consumidos. Cada entrada vive ate o exp do tiquete
// (+ tolerancia); depois disso o proprio exp ja impede o reuso.
// Observacao: em memoria = valido para UMA instancia. Com varias replicas,
// troque por um armazenamento compartilhado com SET NX + TTL (ex.: Redis).
const consumed = new Map(); // jti -> expiresAtMs

setInterval(() => {
  const now = Date.now();
  for (const [jti, until] of consumed) if (until <= now) consumed.delete(jti);
}, 30 * 1000).unref();

export class LaunchTicketError extends Error {
  constructor(reason) {
    super(reason);
    this.reason = reason;
  }
}

/** Verifica E consome o tiquete (uso unico). Retorna { sub }. */
export function consumeLaunchTicket(ticket, { secret, audience, maxTtlSeconds }) {
  if (typeof ticket !== 'string' || ticket.length > MAX_TICKET_LENGTH) throw new LaunchTicketError('malformed');
  const parts = ticket.split('.');
  if (parts.length !== 3 || parts[0] !== PREFIX) throw new LaunchTicketError('malformed');

  // 1) Assinatura primeiro, em tempo constante, antes de interpretar o JSON.
  const expected = mac(secret, `${parts[0]}.${parts[1]}`);
  const given = Buffer.from(parts[2], 'base64url');
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
    throw new LaunchTicketError('bad_signature');
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    throw new LaunchTicketError('malformed');
  }

  // 2) Claims.
  const now = Math.floor(Date.now() / 1000);
  const { sub, aud, iat, exp, jti } = payload ?? {};
  if (aud !== audience) throw new LaunchTicketError('bad_audience');
  if (!Number.isInteger(iat) || !Number.isInteger(exp)) throw new LaunchTicketError('malformed');
  if (exp - iat > maxTtlSeconds || exp <= iat) throw new LaunchTicketError('ttl_too_long');
  if (iat > now + CLOCK_SKEW_S) throw new LaunchTicketError('not_yet_valid');
  if (exp < now - CLOCK_SKEW_S) throw new LaunchTicketError('expired');
  if (typeof jti !== 'string' || jti.length < 22) throw new LaunchTicketError('malformed');
  if (typeof sub !== 'string' || !/^\d{1,15}$/.test(sub)) throw new LaunchTicketError('malformed');

  // 3) Replay.
  if (consumed.has(jti)) throw new LaunchTicketError('replayed');
  consumed.set(jti, (exp + CLOCK_SKEW_S) * 1000);

  return { sub };
}
