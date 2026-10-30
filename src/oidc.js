// Configuracao do Authorization Server (oidc-provider).
import Provider, { interactionPolicy } from 'oidc-provider';
import { config } from './config.js';
import { findUserById, isEligible } from './legacyUsers.js';
import { escapeHtml } from './views.js';
import { log } from './logger.js';

const OIDC_SCOPES = ['openid', 'email', 'profile'];

// ---------------------------------------------------------------------------
// Politica de interacao: SEMPRE exigir login.
//
// O comportamento padrao de um OP e reaproveitar a sessao existente no
// navegador ("SSO silencioso"). Para um cofre de senhas acessado de
// estacoes compartilhadas isso e indesejavel: a segunda pessoa no mesmo
// navegador herdaria a identidade da primeira. Esta checagem extra so deixa
// passar quando o login acabou de ser concluido NESTA mesma interacao.
// ---------------------------------------------------------------------------
const policy = interactionPolicy.base();
policy.get('login').checks.add(
  new interactionPolicy.Check('fresh_login_required', 'a fresh authentication is required for every authorization request', (ctx) =>
    ctx.oidc.result?.login ? interactionPolicy.Check.NO_NEED_TO_PROMPT : interactionPolicy.Check.REQUEST_PROMPT,
  ),
  0,
);

// ---------------------------------------------------------------------------
// Consentimento: o RP registrado e first-party (configurado pelo proprio
// operador), entao o grant e criado automaticamente - mas SOMENTE com os
// escopos OIDC suportados e efetivamente solicitados. Nenhum outro client
// pode ser registrado dinamicamente (registration desativado por padrao).
// ---------------------------------------------------------------------------
async function loadExistingGrant(ctx) {
  const { oidc } = ctx;
  const accountId = oidc.session.accountId;
  const clientId = oidc.client.clientId;

  const existingId = oidc.result?.consent?.grantId || oidc.session.grantIdFor(clientId);
  if (existingId) {
    const existing = await oidc.provider.Grant.find(existingId);
    if (existing && existing.accountId === accountId && existing.clientId === clientId) return existing;
  }

  if (clientId !== config.client.clientId) return undefined;

  const requested = [...oidc.requestParamOIDCScopes].filter((s) => OIDC_SCOPES.includes(s));
  const grant = new oidc.provider.Grant({ accountId, clientId });
  grant.addOIDCScope(requested.join(' '));
  await grant.save();
  return grant;
}

async function findAccount(_ctx, sub) {
  const user = findUserById(sub);
  // Conta desativada DEPOIS do login tambem nao recebe tokens.
  if (!isEligible(user)) return undefined;
  return {
    accountId: String(user.id),
    async claims() {
      return {
        sub: String(user.id),
        email: user.email,
        // A base legada e a fonte de verdade do e-mail corporativo.
        email_verified: true,
        name: user.display_name || user.email,
      };
    },
  };
}

async function renderError(ctx, out) {
  // Nunca expor stack/detalhes internos ao navegador.
  log.warn({ event: 'oidc_error', reason: out?.error, clientId: ctx.oidc?.client?.clientId });
  ctx.type = 'html';
  ctx.set('Cache-Control', 'no-store');
  const description = config.isProduction ? 'Nao foi possivel concluir a autenticacao.' : out?.error_description;
  ctx.body = `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>Erro</title></head>
<body><h1>Erro de autenticacao</h1><p>${escapeHtml(out?.error)}</p><p>${escapeHtml(description)}</p></body></html>`;
}

export function buildProvider() {
  const { client } = config;

  const provider = new Provider(config.issuer, {
    clients: [
      {
        client_id: client.clientId,
        client_secret: client.clientSecret,
        redirect_uris: client.redirectUris,
        post_logout_redirect_uris: client.postLogoutRedirectUris,
        response_types: ['code'],
        grant_types: ['authorization_code'],
        token_endpoint_auth_method: 'client_secret_basic',
      },
    ],
    responseTypes: ['code'],
    // PKCE (S256) obrigatorio por padrao. Desligue apenas se o RP nao
    // suportar - o Vaultwarden com SSO suporta (SSO_PKCE=true).
    pkce: { required: () => config.pkceRequired },
    // redirect_uri sempre explicito e comparado por igualdade exata.
    allowOmittingSingleRegisteredRedirectUri: false,
    scopes: OIDC_SCOPES,
    claims: {
      openid: ['sub'],
      email: ['email', 'email_verified'],
      profile: ['name'],
    },
    // Varios RPs simples (incluindo o Vaultwarden) leem e-mail/nome direto
    // do ID Token em vez de chamar o userinfo. Desligar a conformidade
    // estrita faz os claims concedidos irem tambem no ID Token.
    conformIdTokenClaims: false,
    findAccount,
    loadExistingGrant,
    interactions: {
      policy,
      url: (_ctx, interaction) => `/interaction/${interaction.uid}`,
    },
    cookies: {
      keys: config.cookieKeys,
    },
    ...(config.jwks ? { jwks: config.jwks } : {}),
    // O RP troca o code pelo token no backend: nada de CORS para navegadores.
    clientBasedCORS: () => false,
    features: {
      devInteractions: { enabled: false },
      rpInitiatedLogout: { enabled: true },
    },
    ttl: {
      AuthorizationCode: 60,
      AccessToken: 10 * 60,
      IdToken: 10 * 60,
      Interaction: 10 * 60,
      Grant: 60 * 60,
      Session: 60 * 60,
    },
    renderError,
  });

  // Atras de proxy TLS, confiar em X-Forwarded-* para gerar URLs https
  // e marcar cookies como Secure.
  provider.proxy = config.trustProxyHops > 0;

  provider.on('server_error', (_ctx, err) => log.error({ event: 'oidc_server_error', msg: err?.message }));
  provider.on('grant.success', (ctx) =>
    log.info({ event: 'token_issued', outcome: 'success', clientId: ctx.oidc?.client?.clientId, userId: ctx.oidc?.account?.accountId }),
  );

  return provider;
}
