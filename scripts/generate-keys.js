// Gera o material criptografico necessario para rodar a ponte:
//  - keys/jwks.json: chave privada RSA (RS256) para assinar ID Tokens
//  - valores aleatorios para COOKIE_KEYS, RP_CLIENT_SECRET e LAUNCH_TICKET_SECRET
//
// Os segredos sao impressos no terminal para voce colar no .env (ou no
// gerenciador de segredos). Nada e enviado para lugar nenhum.
//
// Uso: node scripts/generate-keys.js [--force]
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';

const out = 'keys/jwks.json';
if (existsSync(out) && !process.argv.includes('--force')) {
  console.error(`${out} ja existe. Use --force para substituir (tokens emitidos com a chave antiga deixarao de validar).`);
  process.exit(1);
}

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 3072 });
const jwk = { ...privateKey.export({ format: 'jwk' }), kid: randomUUID(), alg: 'RS256', use: 'sig' };

mkdirSync('keys', { recursive: true });
writeFileSync(out, JSON.stringify({ keys: [jwk] }, null, 2), { mode: 0o600 });

const rand = () => randomBytes(32).toString('base64url');
console.log(`JWKS privado gravado em ${out} (permissao 600; NAO versionar).\n`);
console.log('Cole no .env:\n');
console.log(`JWKS_PATH=./${out}`);
console.log(`COOKIE_KEYS=${rand()},${rand()}`);
console.log(`RP_CLIENT_SECRET=${rand()}`);
console.log(`LAUNCH_TICKET_SECRET=${rand()}`);
