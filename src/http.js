// Utilitarios HTTP pequenos para nao depender de cookie-parser/helmet.

// Cabecalhos defensivos para as paginas HTML desta ponte.
// `formTargets`: origens dos redirect_uris registrados. Alguns navegadores
// aplicam `form-action` tambem a cadeia de redirecionamentos apos o POST do
// formulario, que termina no callback do Relying Party.
export function securityHeaders(formTargets = []) {
  const formAction = ["'self'", ...new Set(formTargets)].join(' ');
  const headers = {
    'Content-Security-Policy': `default-src 'none'; style-src 'unsafe-inline'; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
    'Cross-Origin-Opener-Policy': 'same-origin',
  };
  return (_req, res, next) => {
    res.set(headers);
    next();
  };
}

export function readCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) {
      try {
        return decodeURIComponent(part.slice(idx + 1).trim());
      } catch {
        return undefined;
      }
    }
  }
  return undefined;
}

export function clientIp(req) {
  // Com "trust proxy" configurado, o Express ja resolve o IP real.
  return req.ip;
}
