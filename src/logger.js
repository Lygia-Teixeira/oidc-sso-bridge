// Log de auditoria em JSON (uma linha por evento), com lista BRANCA de campos.
// Qualquer campo fora da lista e descartado - assim senha, codigo de 2FA,
// tiquete, cookie ou e-mail nunca chegam ao log por descuido.
import { createHash } from 'node:crypto';

const ALLOWED_FIELDS = new Set(['event', 'outcome', 'reason', 'userId', 'clientId', 'ip', 'interaction', 'msg']);

// Identificadores de interacao sao opacos, mas encurtamos/hasheamos para
// correlacionar eventos sem permitir reaproveitar o valor.
export function fingerprint(value) {
  if (!value) return undefined;
  return createHash('sha256').update(String(value)).digest('hex').slice(0, 12);
}

function write(level, fields) {
  const entry = { ts: new Date().toISOString(), level };
  for (const [key, value] of Object.entries(fields)) {
    if (ALLOWED_FIELDS.has(key) && value !== undefined) entry[key] = value;
  }
  const line = JSON.stringify(entry);
  if (level === 'error' || level === 'warn') console.error(line);
  else console.log(line);
}

export const log = {
  info: (fields) => write('info', fields),
  warn: (fields) => write('warn', fields),
  error: (fields) => write('error', fields),
};
