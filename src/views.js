// Paginas minimas (sem template engine). TODO conteudo dinamico passa por escapeHtml.

export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"'`=/]/g, (c) => `&#${c.charCodeAt(0)};`);
}

const STYLE = `
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; background: Canvas; color: CanvasText; }
  main { width: min(360px, calc(100vw - 32px)); padding: 24px; border: 1px solid GrayText; border-radius: 10px; }
  h1 { font-size: 1.15rem; margin: 0 0 8px; }
  p.hint { font-size: .85rem; opacity: .75; margin: 0 0 12px; }
  label { display: block; font-size: .85rem; margin-top: 12px; }
  input { width: 100%; box-sizing: border-box; padding: 8px; margin-top: 4px; font: inherit; }
  button { width: 100%; margin-top: 18px; padding: 10px; font: inherit; cursor: pointer; }
  .error { margin-top: 12px; font-size: .85rem; color: #c0392b; }
`;

function layout(title, body) {
  return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(title)}</title>
<style>${STYLE}</style>
</head>
<body><main>${body}</main></body>
</html>`;
}

function errorBlock(error) {
  return error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : '';
}

export function signInView({ uid, clientName, error }) {
  const action = `/interaction/${encodeURIComponent(uid)}/password`;
  return layout(
    'Entrar',
    `<h1>Entrar</h1>
<p class="hint">Acesso a <strong>${escapeHtml(clientName)}</strong> com a sua conta corporativa.</p>
<form method="post" action="${escapeHtml(action)}" autocomplete="on">
  <label>E-mail<input type="email" name="email" maxlength="254" required autofocus autocomplete="username"></label>
  <label>Senha<input type="password" name="password" maxlength="128" required autocomplete="current-password"></label>
  <button type="submit">Continuar</button>
  ${errorBlock(error)}
</form>`,
  );
}

export function otpView({ uid, error }) {
  const action = `/interaction/${encodeURIComponent(uid)}/otp`;
  return layout(
    'Verificacao',
    `<h1>Confirme que e voce</h1>
<p class="hint">Enviamos um codigo de 6 digitos para o e-mail cadastrado. Ele expira em 5 minutos.</p>
<form method="post" action="${escapeHtml(action)}" autocomplete="off">
  <label>Codigo<input type="text" name="otp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autofocus autocomplete="one-time-code"></label>
  <button type="submit">Verificar</button>
  ${errorBlock(error)}
</form>`,
  );
}

export function messageView(title, message) {
  return layout(title, `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>`);
}
