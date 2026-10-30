// Carrega e valida TODA a configuracao a partir de variaveis de ambiente.
// Nenhum segredo tem valor padrao no codigo: se faltar, o processo nao sobe.
import { readFileSync } from 'node:fs';

try {
  // Node >= 22: le o .env sem dependencia extra. Ausencia do arquivo e ok
  // (em container as variaveis chegam pelo ambiente).
  process.loadEnvFile();
} catch {
  /* sem .env local */
}

const PLACEHOLDER = 'CHANGE_ME';
const env = process.env;
const isProduction = env.NODE_ENV === 'production';

function required(name) {
  const value = env[name];
  if (!value || value.trim() === '') {
    throw new Error(`Variavel de ambiente obrigatoria ausente: ${name}`);
  }
  return value.trim();
}

function list(name) {
  return (env[name] || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function assertSecret(label, value, minLength = 32) {
  if (value.includes(PLACEHOLDER)) {
    throw new Error(`${label} ainda contem o placeholder ${PLACEHOLDER}. Gere valores com "npm run keys".`);
  }
  if (value.length < minLength) {
    throw new Error(`${label} precisa ter pelo menos ${minLength} caracteres.`);
  }
  return value;
}

function bool(name, fallback) {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(raw.toLowerCase());
}

function int(name, fallback) {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n)) throw new Error(`${name} precisa ser um numero inteiro.`);
  return n;
}

// Em producao toda URL do fluxo precisa ser HTTPS. Em desenvolvimento,
// http e aceito (tipicamente localhost).
function assertUrl(label, value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} nao e uma URL valida.`);
  }
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && !isProduction)) {
    throw new Error(`${label} precisa usar https em producao.`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${label} nao pode conter credenciais embutidas.`);
  }
  return parsed;
}

const issuer = assertUrl('OIDC_ISSUER', required('OIDC_ISSUER'));
if (issuer.search || issuer.hash) throw new Error('OIDC_ISSUER nao pode ter query string nem fragmento.');

// O oidc-provider compara redirect_uri por igualdade EXATA com o que foi
// registrado. Aqui so garantimos que o que esta sendo registrado e sano.
function redirectList(name, { mandatory }) {
  const values = mandatory ? required(name).split(',').map((s) => s.trim()).filter(Boolean) : list(name);
  return values.map((raw) => {
    const u = assertUrl(name, raw);
    if (u.hash) throw new Error(`${name} nao pode conter fragmento (#).`);
    return u.toString();
  });
}

function loadJwks() {
  const path = env.JWKS_PATH;
  if (!path) {
    if (isProduction) throw new Error('JWKS_PATH e obrigatorio em producao (rode "npm run keys").');
    return undefined; // oidc-provider gera chave efemera em dev (com aviso no log)
  }
  const jwks = JSON.parse(readFileSync(path, 'utf8'));
  if (!Array.isArray(jwks.keys) || jwks.keys.length === 0) throw new Error('JWKS sem chaves.');
  if (jwks.keys.some((k) => !k.d)) throw new Error('JWKS precisa conter as chaves privadas de assinatura.');
  return jwks;
}

const cookieKeys = list('COOKIE_KEYS').map((k, i) => assertSecret(`COOKIE_KEYS[${i}]`, k));
if (cookieKeys.length === 0) throw new Error('COOKIE_KEYS precisa de pelo menos uma chave.');

const launchEnabled = bool('LAUNCH_ENABLED', false);

const mailTransport = env.MAIL_TRANSPORT || 'smtp';
if (!['smtp', 'console'].includes(mailTransport)) throw new Error('MAIL_TRANSPORT deve ser smtp ou console.');
if (mailTransport === 'console' && isProduction) {
  throw new Error('MAIL_TRANSPORT=console e apenas para desenvolvimento.');
}

export const config = Object.freeze({
  isProduction,
  port: int('PORT', 3000),
  // Numero de proxies reversos confiaveis na frente do servico (0 = nenhum).
  trustProxyHops: int('TRUST_PROXY_HOPS', 0),
  issuer: issuer.toString().replace(/\/$/, ''),
  cookieKeys,
  jwks: loadJwks(),
  legacyDbPath: required('LEGACY_DB_PATH'),
  allowedRoles: list('ALLOWED_ROLES'),
  client: Object.freeze({
    clientId: required('RP_CLIENT_ID'),
    clientSecret: assertSecret('RP_CLIENT_SECRET', required('RP_CLIENT_SECRET')),
    redirectUris: redirectList('RP_REDIRECT_URIS', { mandatory: true }),
    postLogoutRedirectUris: redirectList('RP_POST_LOGOUT_REDIRECT_URIS', { mandatory: false }),
  }),
  pkceRequired: bool('PKCE_REQUIRED', true),
  // true = exige codigo por e-mail de TODOS; false = so de quem ativou na base legada.
  requireEmailOtp: bool('REQUIRE_EMAIL_OTP', false),
  launch: Object.freeze({
    enabled: launchEnabled,
    // Chave HMAC compartilhada SOMENTE com a aplicacao legada.
    secret: launchEnabled ? assertSecret('LAUNCH_TICKET_SECRET', required('LAUNCH_TICKET_SECRET')) : null,
    // Teto rigido: mesmo que a aplicacao legada emita algo mais longo, nao aceitamos.
    maxTtlSeconds: Math.min(Math.max(int('LAUNCH_TICKET_MAX_TTL', 60), 10), 120),
    audience: env.LAUNCH_TICKET_AUDIENCE || 'oidc-sso-bridge',
    // Destino FIXO depois de aceitar o tiquete: a tela do Relying Party que
    // inicia o fluxo OIDC. Nunca vem de parametro da requisicao (sem open redirect).
    rpLoginUrl: launchEnabled ? assertUrl('RP_LOGIN_URL', required('RP_LOGIN_URL')).toString() : null,
  }),
  mail: Object.freeze({
    transport: mailTransport,
    host: env.SMTP_HOST,
    port: int('SMTP_PORT', 587),
    user: env.SMTP_USER,
    pass: env.SMTP_PASS,
    from: env.MAIL_FROM || 'no-reply@example.com',
  }),
});
