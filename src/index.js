import express from 'express';
import { config } from './config.js';
import { buildProvider } from './oidc.js';
import { interactionRouter } from './routes/interaction.js';
import { launchRouter } from './routes/launch.js';
import { securityHeaders } from './http.js';
import { messageView } from './views.js';
import { log } from './logger.js';

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', config.trustProxyHops);

const provider = buildProvider();
const rpOrigins = config.client.redirectUris.map((u) => new URL(u).origin);

app.get('/healthz', (_req, res) => res.type('text/plain').send('ok'));

app.use(['/interaction', '/launch'], securityHeaders(rpOrigins));
app.use(interactionRouter(provider));
if (config.launch.enabled) app.use(launchRouter());

// Todo o resto (/.well-known/openid-configuration, /auth, /token, /jwks, ...)
app.use(provider.callback());

// Handler de erro: resposta generica, detalhe so no log (sem dados sensiveis).
app.use((err, req, res, _next) => {
  const status = Number.isInteger(err.status) && err.status >= 400 && err.status < 500 ? err.status : 500;
  log[status >= 500 ? 'error' : 'warn']({ event: 'http_error', reason: err.name, msg: status >= 500 ? err.message : undefined });
  res.status(status).send(messageView('Erro', status >= 500 ? 'Erro interno.' : 'Requisicao invalida ou sessao expirada. Reinicie o login pelo aplicativo.'));
});

app.listen(config.port, () => {
  log.info({ event: 'startup', msg: `listening on :${config.port}, issuer ${config.issuer}, launch=${config.launch.enabled}` });
});
