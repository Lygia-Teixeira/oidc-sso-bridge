// Telas e acoes da interacao OIDC (login por senha, 2o fator, atalho via tiquete).
import express from 'express';
import { rateLimit } from 'express-rate-limit';
import { config } from '../config.js';
import { findUserByEmail, findUserById, isEligible } from '../legacyUsers.js';
import { checkPassword, clearFailures, lockRemainingMs, recordFailure } from '../credentials.js';
import { hasPendingChallenge, issueChallenge, verifyChallenge } from '../emailOtp.js';
import { PREAUTH_COOKIE, takePreauth } from '../preauth.js';
import { readCookie, clientIp } from '../http.js';
import { signInView, otpView, messageView } from '../views.js';
import { log, fingerprint } from '../logger.js';

const GENERIC_FAILURE = 'E-mail ou senha incorretos.';

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Rate limit por IP nas acoes que recebem segredo. O bloqueio por conta
// (credentials.js) cobre o caso de muitos IPs atacando a mesma conta.
function limiter(limit) {
  return rateLimit({
    windowMs: 15 * 60 * 1000,
    limit,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: (req, res) => {
      log.warn({ event: 'rate_limited', ip: clientIp(req) });
      res.status(429).send(messageView('Muitas tentativas', 'Aguarde alguns minutos antes de tentar novamente.'));
    },
  });
}

export function interactionRouter(provider) {
  const router = express.Router();
  const form = express.urlencoded({ extended: false, limit: '4kb', parameterLimit: 10 });

  // Carrega a interacao a partir do cookie assinado do oidc-provider e
  // confere que o uid da URL e o MESMO da interacao em curso neste navegador.
  async function loadLoginInteraction(req, res) {
    const details = await provider.interactionDetails(req, res);
    if (details.uid !== req.params.uid || details.prompt.name !== 'login') {
      const err = new Error('interaction mismatch');
      err.status = 400;
      throw err;
    }
    return details;
  }

  async function finishLogin(req, res, userId, amr) {
    await provider.interactionFinished(
      req,
      res,
      { login: { accountId: String(userId), amr } },
      { mergeWithLastSubmission: false },
    );
  }

  router.get(
    '/interaction/:uid',
    wrap(async (req, res) => {
      const details = await provider.interactionDetails(req, res);
      const { uid, prompt, params } = details;

      if (uid !== req.params.uid) return res.status(400).send(messageView('Erro', 'Interacao invalida.'));

      if (prompt.name !== 'login') {
        // Com loadExistingGrant (oidc.js) o consentimento e automatico para o
        // RP registrado; qualquer outro prompt e inesperado.
        log.warn({ event: 'unexpected_prompt', reason: prompt.name, interaction: fingerprint(uid) });
        return res.status(400).send(messageView('Erro', 'Solicitacao nao suportada.'));
      }

      // Atalho "um clique": handle de pre-autenticacao criado em /launch.
      if (config.launch.enabled) {
        const handle = readCookie(req, PREAUTH_COOKIE);
        if (handle) {
          res.clearCookie(PREAUTH_COOKIE, { path: '/interaction' });
          const userId = takePreauth(handle);
          const user = userId ? findUserById(userId) : null;
          if (isEligible(user)) {
            log.info({ event: 'login', outcome: 'success', reason: 'launch_ticket', userId: user.id, clientId: params.client_id, interaction: fingerprint(uid) });
            return finishLogin(req, res, user.id, ['ext']);
          }
          // Handle expirado/invalido: segue para o formulario normal, sem alarde.
          log.info({ event: 'launch_preauth', outcome: 'ignored', interaction: fingerprint(uid) });
        }
      }

      if (hasPendingChallenge(uid)) return res.send(otpView({ uid }));
      return res.send(signInView({ uid, clientName: params.client_id }));
    }),
  );

  router.post(
    '/interaction/:uid/password',
    limiter(20),
    form,
    wrap(async (req, res) => {
      const { uid, params } = await loadLoginInteraction(req, res);
      const email = typeof req.body.email === 'string' ? req.body.email : '';
      const password = typeof req.body.password === 'string' ? req.body.password : '';
      const ip = clientIp(req);
      const render = (error, status = 200) => res.status(status).send(signInView({ uid, clientName: params.client_id, error }));

      if (lockRemainingMs(email) > 0) {
        log.warn({ event: 'login', outcome: 'blocked', reason: 'account_lock', ip, interaction: fingerprint(uid) });
        // Mesma mensagem generica: nao confirmar que a conta existe.
        return render('Muitas tentativas. Tente novamente mais tarde.', 429);
      }

      const user = findUserByEmail(email);
      const passwordOk = await checkPassword(user, password); // sempre roda bcrypt (tempo constante)

      if (!user || !passwordOk) {
        recordFailure(email);
        log.warn({ event: 'login', outcome: 'failure', reason: 'bad_credentials', ip, interaction: fingerprint(uid) });
        return render(GENERIC_FAILURE);
      }

      if (!isEligible(user)) {
        log.warn({ event: 'login', outcome: 'denied', reason: 'not_eligible', userId: user.id, ip });
        return render('Esta conta nao tem acesso a este servico.');
      }

      clearFailures(email);

      if (config.requireEmailOtp || user.email_2fa_enabled === 1) {
        try {
          await issueChallenge(uid, user);
        } catch {
          log.error({ event: 'otp_send', outcome: 'failure', userId: user.id });
          return render('Nao foi possivel enviar o codigo de verificacao. Tente novamente.', 503);
        }
        log.info({ event: 'otp_sent', userId: user.id, interaction: fingerprint(uid) });
        return res.send(otpView({ uid }));
      }

      log.info({ event: 'login', outcome: 'success', reason: 'password', userId: user.id, clientId: params.client_id, ip });
      return finishLogin(req, res, user.id, ['pwd']);
    }),
  );

  router.post(
    '/interaction/:uid/otp',
    limiter(30),
    form,
    wrap(async (req, res) => {
      const { uid, params } = await loadLoginInteraction(req, res);
      const result = verifyChallenge(uid, req.body.otp);

      if (!result.ok) {
        log.warn({ event: 'otp', outcome: 'failure', reason: result.reason, ip: clientIp(req), interaction: fingerprint(uid) });
        if (result.final) {
          return res.send(
            signInView({ uid, clientName: params.client_id, error: 'Codigo expirado ou tentativas esgotadas. Entre novamente.' }),
          );
        }
        return res.send(otpView({ uid, error: 'Codigo invalido.' }));
      }

      // Revalida a conta: pode ter sido desativada entre a senha e o codigo.
      const user = findUserById(result.userId);
      if (!isEligible(user)) return res.send(signInView({ uid, clientName: params.client_id, error: 'Esta conta nao tem acesso a este servico.' }));

      log.info({ event: 'login', outcome: 'success', reason: 'password+otp', userId: user.id, clientId: params.client_id });
      return finishLogin(req, res, user.id, ['pwd', 'otp']);
    }),
  );

  return router;
}
