# Política de segurança

Este repositório é uma **implementação de referência** para estudo e portfólio.
Não há versões com suporte nem garantia de correções.

## Como reportar

Se encontrar uma vulnerabilidade, **não abra uma issue pública**. Use o recurso
*Report a vulnerability* (GitHub Security Advisories) deste repositório,
descrevendo o impacto, os passos para reproduzir e a versão/commit afetado.

## Escopo

- Código em `src/` e `scripts/`.
- Fora de escopo: o Relying Party (Vaultwarden), a aplicação legada e
  configurações de implantação de terceiros.

## Boas práticas para quem reutilizar

- Gere todos os segredos com `npm run keys`; nunca versione `.env`, `keys/` ou bancos `*.db`.
- Rode com `NODE_ENV=production`, atrás de proxy reverso HTTPS, com `TRUST_PROXY_HOPS` correto.
- Monte a base legada como volume somente leitura.
- Para mais de uma instância, substitua o estado em memória por armazenamento compartilhado (ver README, "Limitações").
- Rotacione `COOKIE_KEYS` mantendo a chave anterior na segunda posição durante a transição.
