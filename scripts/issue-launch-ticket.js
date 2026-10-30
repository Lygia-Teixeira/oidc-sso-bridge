// Simula a APLICACAO LEGADA emitindo um launch ticket para o usuario
// autenticado. Em producao isso fica no backend da aplicacao legada, atras
// da sessao autenticada dela, e usa a mesma LAUNCH_TICKET_SECRET.
//
// Uso: node scripts/issue-launch-ticket.js <userId>
// Saida: uma pagina HTML minima que faz POST do tiquete para /launch.
import { writeFileSync } from 'node:fs';
import { signLaunchTicket } from '../src/launchTicket.js';

try {
  process.loadEnvFile();
} catch {
  /* sem .env */
}

const userId = process.argv[2];
if (!/^\d+$/.test(userId ?? '')) {
  console.error('Uso: node scripts/issue-launch-ticket.js <userId>');
  process.exit(1);
}
const secret = process.env.LAUNCH_TICKET_SECRET;
const issuer = process.env.OIDC_ISSUER;
if (!secret || secret.includes('CHANGE_ME') || !issuer) {
  console.error('Defina LAUNCH_TICKET_SECRET e OIDC_ISSUER no .env.');
  process.exit(1);
}

const ticket = signLaunchTicket({
  secret,
  sub: userId,
  audience: process.env.LAUNCH_TICKET_AUDIENCE || 'oidc-sso-bridge',
  ttlSeconds: 60,
});

// O que a aplicacao legada renderizaria: um formulario que envia o tiquete
// por POST (fora da URL) para a ponte.
const html = `<!doctype html><meta charset="utf-8"><title>Abrir</title>
<form method="post" action="${new URL('/launch', issuer)}">
  <input type="hidden" name="ticket" value="${ticket}">
  <button type="submit">Abrir o cofre (tiquete valido por 60s)</button>
</form>`;
writeFileSync('launch-demo.html', html);
console.log('Gerado launch-demo.html (abra no navegador em ate 60s). Arquivo descartavel, nao versionar.');
