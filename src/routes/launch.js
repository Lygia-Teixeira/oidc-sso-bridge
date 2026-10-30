// Entrada do fluxo "um clique" vindo da aplicacao legada.
//
// A aplicacao legada (onde o usuario JA esta autenticado) emite um launch
// ticket e o envia por POST (formulario) para /launch. Usamos POST para o
// tiquete nao aparecer em URL, historico, Referer nem log de proxy.
//
// Aqui o tiquete e verificado E consumido imediatamente. O navegador
// recebe so um handle opaco (cookie httpOnly, 90s, uso unico) e e
// redirecionado para a URL FIXA do Relying Party que inicia o OIDC.
import express from 'express';
import { rateLimit } from 'express-rate-limit';
import { config } from '../config.js';
import { consumeLaunchTicket, LaunchTicketError } from '../launchTicket.js';
import { findUserById, isEligible } from '../legacyUsers.js';
import { createPreauth, PREAUTH_COOKIE, PREAUTH_TTL_MS } from '../preauth.js';
import { messageView } from '../views.js';
import { clientIp } from '../http.js';
import { log } from '../logger.js';

export function launchRouter() {
  const router = express.Router();
  const form = express.urlencoded({ extended: false, limit: '2kb', parameterLimit: 5 });
  const limiter = rateLimit({ windowMs: 60 * 1000, limit: 30, standardHeaders: 'draft-8', legacyHeaders: false });

  router.post('/launch', limiter, form, (req, res) => {
    const reject = (reason) => {
      log.warn({ event: 'launch_ticket', outcome: 'rejected', reason, ip: clientIp(req) });
      return res
        .status(401)
        .send(messageView('Link expirado', 'Volte para a aplicacao de origem e tente novamente.'));
    };

    let sub;
    try {
      ({ sub } = consumeLaunchTicket(req.body.ticket, config.launch));
    } catch (err) {
      return reject(err instanceof LaunchTicketError ? err.reason : 'error');
    }

    const user = findUserById(sub);
    if (!isEligible(user)) return reject('not_eligible');

    res.cookie(PREAUTH_COOKIE, createPreauth(user.id), {
      httpOnly: true,
      secure: config.isProduction || req.secure,
      sameSite: 'lax', // precisa acompanhar a navegacao top-level vinda do RP
      path: '/interaction',
      maxAge: PREAUTH_TTL_MS,
    });
    log.info({ event: 'launch_ticket', outcome: 'accepted', userId: user.id, ip: clientIp(req) });
    // Destino vem SO da configuracao (nunca da requisicao): sem open redirect.
    return res.redirect(303, config.launch.rpLoginUrl);
  });

  return router;
}
