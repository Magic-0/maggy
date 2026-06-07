---
name: security
description: OWASP security patterns, secrets management, security testing
when-to-use: When writing code that handles auth, user input, API keys, or when security review is requested
user-invocable: true
allowed-tools: [Read, Glob, Grep, Bash]
effort: high
---

# Security Skill


Security best practices and automated security testing for all projects.

---

## Core Principle

**Security is not optional.** Every project must pass security checks before merge. Assume all input is malicious, all secrets will leak if committed, and all dependencies have vulnerabilities.

---

## Required Security Setup

### 1. Gitignore (Non-Negotiable)

Every project must have these in `.gitignore`:

```gitignore
# Environment files - NEVER commit
.env
.env.*
!.env.example

# Secrets
*.pem
*.key
*.p12
*.pfx
credentials.json
secrets.json
*-credentials.json
service-account*.json

# IDE and OS
.idea/
.vscode/settings.json
.DS_Store
Thumbs.db

# Dependencies
node_modules/
__pycache__/
*.pyc
.venv/
venv/

# Build outputs
dist/
build/
*.egg-info/

# Logs that might contain sensitive data
*.log
logs/
```

### 2. Environment Variables

**Create `.env.example`** with all required vars (no values):
```bash
# .env.example - Copy to .env and fill in values

# Server-side only (NEVER prefix with VITE_ or NEXT_PUBLIC_)
DATABASE_URL=
ANTHROPIC_API_KEY=
SUPABASE_SERVICE_ROLE_KEY=

# Client-side safe (public, non-sensitive)
VITE_SUPABASE_URL=
VITE_SUPABASE_ANON_KEY=
```

### Frontend Environment Variables (Critical!)

**NEVER put secrets in client-exposed env vars:**

| Framework | Client-Exposed Prefix | Server-Only |
|-----------|----------------------|-------------|
| Vite | `VITE_*` | No prefix |
| Next.js | `NEXT_PUBLIC_*` | No prefix |
| Create React App | `REACT_APP_*` | N/A (no server) |

```typescript
// WRONG - Secret exposed to browser bundle!
const apiKey = import.meta.env.VITE_ANTHROPIC_API_KEY;

// CORRECT - Only public values client-side
const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;

// CORRECT - Secrets stay server-side only
// In API route or server function:
const apiKey = process.env.ANTHROPIC_API_KEY;
```

**Vercel Environment Variables:**
- In Vercel dashboard, secrets without `VITE_` prefix are server-only
- Only `VITE_*` vars are bundled into client code
- Always verify in browser devtools → Sources → your bundle that secrets aren't exposed

**Validate environment at startup:**
```typescript
// config/env.ts
import { z } from 'zod';

const envSchema = z.object({
  DATABASE_URL: z.string().url(),
  ANTHROPIC_API_KEY: z.string().min(1),
  NODE_ENV: z.enum(['development', 'production', 'test']),
});

export const env = envSchema.parse(process.env);
```

```python
# config/env.py
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    database_url: str
    anthropic_api_key: str
    environment: str = "development"

    class Config:
        env_file = ".env"

settings = Settings()
```

---

## Security Tests

### Pre-Commit Security Checks

Add to pre-commit hooks:

**For all projects:**
```yaml
# .pre-commit-config.yaml (add to existing)
repos:
  # Detect secrets
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']

  # Check for security issues in dependencies
  - repo: local
    hooks:
      - id: security-check
        name: security-check
        entry: ./scripts/security-check.sh
        language: script
        pass_filenames: false
```

**TypeScript/JavaScript:**
```json
// package.json scripts
{
  "scripts": {
    "security:audit": "npm audit --audit-level=high",
    "security:secrets": "npx secretlint '**/*'",
    "security:deps": "npx better-npm-audit audit"
  }
}
```

**Python:**
```bash
# Add to dev dependencies
pip install safety bandit

# Commands
safety check           # Check dependencies for vulnerabilities
bandit -r src/        # Static security analysis
```

### Security Check Script

Create `scripts/security-check.sh`:

```bash
#!/bin/bash
set -e

echo "Running security checks..."

# Check for secrets in staged files
echo "Checking for secrets..."
if command -v detect-secrets &> /dev/null; then
  detect-secrets scan --baseline .secrets.baseline
fi

# Check .env is not staged
if git diff --cached --name-only | grep -E '^\.env$|^\.env\.' | grep -v '\.example$'; then
  echo "ERROR: .env file is staged for commit!"
  exit 1
fi

# Check for common secret patterns in staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)
if echo "$STAGED_FILES" | xargs grep -l -E '(password|secret|api_key|apikey|token|private_key)\s*[:=]\s*["\047][^"\047]+["\047]' 2>/dev/null; then
  echo "ERROR: Possible secrets found in staged files!"
  exit 1
fi

# Language-specific checks
if [ -f "package.json" ]; then
  echo "Checking npm dependencies..."
  npm audit --audit-level=high || echo "Warning: npm audit found issues"
fi

if [ -f "pyproject.toml" ] || [ -f "requirements.txt" ]; then
  echo "Checking Python dependencies..."
  if command -v safety &> /dev/null; then
    safety check || echo "Warning: safety found issues"
  fi
fi

echo "Security checks passed!"
```

```bash
chmod +x scripts/security-check.sh
```

---

## GitHub Actions Security Workflow

Create `.github/workflows/security.yml`:

```yaml
name: Security

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    # Run weekly on Monday at 9am UTC
    - cron: '0 9 * * 1'

jobs:
  secrets-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Detect secrets
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.pull_request.base.sha }}
          head: ${{ github.event.pull_request.head.sha }}

  dependency-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Node.js projects
      - name: Setup Node
        if: hashFiles('package.json') != ''
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        if: hashFiles('package.json') != ''
        run: npm ci

      - name: NPM Audit
        if: hashFiles('package.json') != ''
        run: npm audit --audit-level=high

      # Python projects
      - name: Setup Python
        if: hashFiles('pyproject.toml') != '' || hashFiles('requirements.txt') != ''
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install safety
        if: hashFiles('pyproject.toml') != '' || hashFiles('requirements.txt') != ''
        run: pip install safety

      - name: Safety check
        if: hashFiles('pyproject.toml') != '' || hashFiles('requirements.txt') != ''
        run: safety check

  codeql:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ hashFiles('package.json') != '' && 'javascript-typescript' || 'python' }}

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
```

---

## Input Validation (OWASP Top 10)

### 1. SQL Injection Prevention

**Never use string concatenation:**
```typescript
// BAD - SQL injection vulnerable
const user = await db.query(`SELECT * FROM users WHERE id = ${userId}`);

// GOOD - Parameterized query
const user = await db.query('SELECT * FROM users WHERE id = $1', [userId]);

// GOOD - Using ORM (Kysely, Prisma, Drizzle)
const user = await db.selectFrom('users').where('id', '=', userId).execute();
```

```python
# BAD - SQL injection vulnerable
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# GOOD - Parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# GOOD - Using ORM (SQLAlchemy)
user = session.query(User).filter(User.id == user_id).first()
```

### 2. XSS Prevention

```typescript
// Always sanitize user input before rendering
import DOMPurify from 'dompurify';

// BAD - XSS vulnerable
element.innerHTML = userInput;

// GOOD - Sanitized
element.innerHTML = DOMPurify.sanitize(userInput);

// BEST - Use framework's built-in escaping (React does this by default)
return <div>{userInput}</div>;  // Safe in React

// DANGER - Bypasses React's protection
return <div dangerouslySetInnerHTML={{ __html: userInput }} />;  // Avoid!
```

### 3. Input Validation at Boundaries

```typescript
// Validate ALL external input with Zod
import { z } from 'zod';

const CreateUserSchema = z.object({
  email: z.string().email().max(255),
  name: z.string().min(1).max(100).regex(/^[a-zA-Z\s]+$/),
  age: z.number().int().min(0).max(150),
});

// In route handler
app.post('/users', async (req, res) => {
  const result = CreateUserSchema.safeParse(req.body);
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }
  // result.data is now typed and validated
});
```

### 4. Path Traversal Prevention

```typescript
import path from 'path';

// BAD - Path traversal vulnerable
const filePath = `./uploads/${req.params.filename}`;

// GOOD - Validate and sanitize path
const filename = path.basename(req.params.filename);  // Strips ../
const filePath = path.join('./uploads', filename);

// Verify it's still within allowed directory
if (!filePath.startsWith(path.resolve('./uploads'))) {
  throw new Error('Invalid path');
}
```

---

## Authentication & Authorization

### Secure Cookies (httpOnly Sessions)

Pour toute session utilisateur, toujours utiliser des cookies `httpOnly` — jamais de token dans `localStorage` (vulnérable XSS).

```typescript
// Pattern cookie de session — Next.js App Router
response.cookies.set("session", token, {
  httpOnly: true,           // Inaccessible depuis JS client
  sameSite: "lax",          // Protection CSRF (lax = ok pour navigations GET, bloque POST cross-site)
  secure:   process.env.NODE_ENV === "production",  // HTTPS only en prod
  path:     "/",
  maxAge:   7 * 24 * 60 * 60,  // 7 jours en secondes
})
```

**Règles :**
- `httpOnly: true` toujours — sans exception
- `sameSite: "strict"` si pas de navigation cross-site ; `"lax"` sinon
- `secure: true` en production (jamais en dev local HTTP)
- `maxAge` explicite — pas de cookie session sans expiration définie

---

### Isolation des contextes d'identité (modes & multi-tenant)

**Principe fondamental** : deux contextes d'identité actifs ne doivent jamais coexister de façon ambiguë. Quand deux cookies ou flags de contexte sont présents simultanément (mode démo + session réelle, tenant A + tenant B…), les guards lisent des sources différentes et s'accordent des permissions contradictoires — la faille émerge dans l'écart.

---

#### Modes (démo / preview / guest)

Un cookie de mode (`demo`, `preview`, `guest`…) et un cookie de session réelle ne doivent **jamais coexister**. La coexistence crée une ambiguïté dangereuse : les guards de lecture retournent des fixtures démo, mais les guards d'écriture voient `hasValidSession → true` → les actions du mode écrivent en DB réelle (notifications parasites, données corrompues…).

**4 règles non négociables :**

1. **Entrée en mode → révoquer la session réelle** : la route d'entrée (`/api/auth/demo`…) lit le cookie session, le révoque en DB, et l'efface dans la réponse AVANT de poser le cookie de mode.

2. **Login → effacer le cookie de mode** : `issueSessionResponse` (et tout chemin d'émission de session, y compris 2FA) doit appeler `clearModeCookie(response)`. Garantit que même si l'étape 1 a échoué, le login normalise l'état.

3. **Routes d'écriture → mode guard AVANT session guard** : sur tout handler `POST/PATCH/DELETE`, vérifier `isDemoRequest(req)` en premier. Si mode → retourner sans toucher la DB. Ne jamais laisser `hasValidSession` seul décider pour les writes en présence d'un cookie de mode.

4. **Logout du mode = route PUBLIC** : la route de logout doit bypasser le middleware de session (`PUBLIC_PATHS` ou équivalent). Sans ça, un POST de logout depuis le mode (sans vraie session) est bloqué par le proxy, le cookie de mode ne peut jamais être effacé.

```typescript
// ✅ CORRECT — mode entry: revoke real session first
export async function POST(req: Request) {
  const response = NextResponse.json({ ok: true })
  const token = readSessionToken(req)
  if (token) {
    try { await revokeSessionByToken(token) } catch {}
    response.cookies.set(SESSION_COOKIE_NAME, "", { maxAge: 0, path: "/" })
  }
  return setModeCookie(response)
}

// ✅ CORRECT — login: clear mode cookie on session issuance
async function issueSessionResponse(...): Promise<NextResponse> {
  // ... set real session cookie ...
  return clearModeCookie(response)  // ← always, last line
}

// ✅ CORRECT — write route: mode guard before session guard
export async function POST(req: Request) {
  if (isDemoRequest(req)) return NextResponse.json({ ok: true })  // ← first check
  if (!(await hasValidSession(req))) return unauthorized()
  // ... DB write only if real session confirmed ...
}
```

**Anti-patterns modes :**
- ❌ Poser un cookie de mode sans effacer le cookie session existant
- ❌ Vérifier `hasValidSession` AVANT `isDemoRequest` sur les routes d'écriture
- ❌ Logout du mode gardé par le proxy (route non-publique → POST bloqué depuis le mode)
- ❌ `issueSessionResponse` qui ne purge pas les cookies de mode actifs

---

#### Multi-tenant

En architecture multi-tenant, le `tenant_id` courant est une **dimension d'autorisation** aussi critique que la session elle-même. Un `tenant_id` mal isolé permet à un utilisateur légitime d'accéder aux données d'un autre tenant sans jamais contourner l'authentification.

**4 règles non négociables :**

1. **Tenant context dans la session (DB), jamais dans un cookie séparé** : un cookie `tenant_id` non-httpOnly est falsifiable côté client. Lier le tenant à la session en base — la session *est* le contexte tenant, pas un cookie annexe.

2. **Changement de tenant → nouvelle session** : révoquer la session tenant-A, émettre une nouvelle session scoped tenant-B. Ne jamais juste modifier un cookie `current_tenant` : la session resterait valide pour le mauvais contexte.

3. **Toutes les queries DB scopées sur le tenant de la session** : ne jamais prendre `tenantId` du body ou des params URL pour scoper les requêtes. Toujours le lire depuis la session en DB, côté serveur.

4. **Impersonation admin = mode à part entière** : si un admin peut "agir comme" un tenant, appliquer les mêmes 4 règles que le mode démo (révoquer sa propre session, cookie d'impersonation dédié, write guard en premier, logout public).

```typescript
// ✅ CORRECT — tenant_id always from session, never from body
export async function POST(req: Request) {
  const session = await requireSession(req)   // { userId, tenantId }
  if (!session) return unauthorized()
  const { name } = await parseBody(req, schema)
  await db`INSERT INTO projects (name, tenant_id) VALUES (${name}, ${session.tenantId})`
}

// ✅ CORRECT — scope mutations to session tenant
export async function DELETE(req: Request, { params }: Ctx) {
  const session = await requireSession(req)
  if (!session) return unauthorized()
  const { id } = await params
  const deleted = await db`
    DELETE FROM projects WHERE id = ${id} AND tenant_id = ${session.tenantId}
  `
  if (deleted.count === 0) return notFound()   // nonexistent OR wrong tenant
  return NextResponse.json({ ok: true })
}

// ✅ CORRECT — tenant switch: revoke old session, issue new one scoped to target
export async function POST(req: Request) {
  const session = await requireSession(req)
  if (!session) return unauthorized()
  const { targetTenantId } = await parseBody(req, switchSchema)
  const membership = await db`
    SELECT 1 FROM tenant_members WHERE user_id = ${session.userId} AND tenant_id = ${targetTenantId}
  `
  if (!membership.length) return forbidden()
  await revokeSession(session.token)
  return issueSessionResponse({ userId: session.userId, tenantId: targetTenantId })
}

// ❌ WRONG — tenant_id from body (attacker can inject any tenant)
export async function POST(req: Request) {
  const { name, tenantId } = await req.json()
  await db`INSERT INTO projects (name, tenant_id) VALUES (${name}, ${tenantId})`
}

// ❌ WRONG — DELETE without tenant scope (cross-tenant deletion possible)
export async function DELETE(req: Request, { params }: Ctx) {
  const session = await requireSession(req)
  if (!session) return unauthorized()
  await db`DELETE FROM projects WHERE id = ${(await params).id}`  // any tenant!
}
```

**Anti-patterns multi-tenant :**
- ❌ `tenant_id` dans un cookie séparé, surtout non-httpOnly (falsifiable côté client)
- ❌ Changer de tenant en modifiant juste un cookie `current_tenant` sans révoquer la session
- ❌ Lire `tenantId` du body/params URL pour scoper les queries (injection de tenant)
- ❌ `WHERE id = ?` sans `AND tenant_id = ?` sur les mutations (cross-tenant write/delete)
- ❌ Impersonation admin sans isolation de contexte (admin écrit avec ses propres droits sur le tenant cible)

---

### Two-Factor Authentication (TOTP RFC 6238)

Pattern pour 2FA basé sur authenticator (Google Authenticator, 1Password, Authy).

#### Flow en 2 étapes avec cookie pending

```
POST /api/auth/login    → vérifie email+password
  ├─ 2FA désactivé     → cookie session définitive
  └─ 2FA activé        → cookie pending JWT (TTL court ~5 min)
        ↓
POST /api/auth/login/2fa → vérifie code TOTP
  ├─ code valide       → cookie session définitive + suppression cookie pending
  └─ code invalide     → 401 (rate limité)
```

```typescript
// lib/auth-pending.ts — cookie temporaire JWT entre les 2 étapes
import { SignJWT, jwtVerify } from "jose"

const PENDING_TTL_S = 5 * 60  // 5 minutes max pour saisir le code TOTP

export async function signPendingAuth(userId: string): Promise<string> {
  return new SignJWT({ userId })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(`${PENDING_TTL_S}s`)
    .sign(getEncryptionKey())  // clé 32 bytes depuis env var
}

// Poser le cookie pending
response.cookies.set("auth_pending", jwt, {
  httpOnly: true, sameSite: "lax",
  secure: process.env.NODE_ENV === "production",
  path: "/", maxAge: PENDING_TTL_S,
})

// Destruction après validation 2FA
response.cookies.set("auth_pending", "", { maxAge: 0, path: "/" })
```

#### Setup TOTP (otplib)

```typescript
import { generateSecret, generateURI, verifySync } from "otplib"
import { toDataURL } from "qrcode"

// Générer un secret base32 (160 bits)
const secret = generateSecret()

// URI pour QR code (standard otpauth://)
const uri = generateURI({ issuer: "MonApp", label: userEmail, secret })
const qrDataUrl = await toDataURL(uri, { errorCorrectionLevel: "M", scale: 6 })

// Vérifier un code (±30s de tolérance pour dérives d'horloge)
function verifyTotpCode(secret: string, code: string): boolean {
  const clean = code.replace(/\s/g, "")
  if (!/^\d{6}$/.test(clean)) return false
  try {
    return verifySync({ secret, token: clean, epochTolerance: 30 })?.valid === true
  } catch { return false }
}
```

#### Backup codes one-shot

```typescript
// 10 codes × 8 chars base32, consommables une seule fois
function generateBackupCodes(): string[] {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  return Array.from({ length: 10 }, () => {
    const arr = new Uint8Array(8)
    crypto.getRandomValues(arr)
    return Array.from(arr).map(b => alphabet[b % alphabet.length]).join("")
  })
}

// Vérification + consommation (one-shot — retire le code de la liste)
async function consumeBackupCode(userId: string, code: string): Promise<boolean> {
  const row = await loadTotpRow(userId)
  let matched = false
  const remaining = row.backup_codes_enc.filter(enc => {
    if (!matched && decrypt(enc) === code) { matched = true; return false }
    return true
  })
  if (matched) await db`UPDATE user_totp SET backup_codes_enc = ${remaining} WHERE user_id = ${userId}`
  return matched
}
```

---

### Chiffrement AES-256-GCM pour secrets en DB

Ne jamais stocker un secret (TOTP, clé API...) en clair en base. Utiliser AES-256-GCM (chiffrement **authentifié** — détecte toute falsification).

```typescript
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto"

// Format de sortie : iv_hex:tag_hex:ciphertext_hex
// Clé : 32 bytes (64 hex chars) depuis ENCRYPTION_KEY env var

export function encryptSecret(plaintext: string): string {
  const key = getKeyFromEnv()               // Buffer 32 bytes
  const iv  = randomBytes(12)               // 96 bits — recommandé GCM
  const cipher = createCipheriv("aes-256-gcm", key, iv)
  const ct  = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()])
  const tag = cipher.getAuthTag()           // 128 bits — intégrité
  return `${iv.toString("hex")}:${tag.toString("hex")}:${ct.toString("hex")}`
}

export function decryptSecret(encoded: string): string {
  const [ivHex, tagHex, ctHex] = encoded.split(":")
  const key     = getKeyFromEnv()
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(ivHex, "hex"))
  decipher.setAuthTag(Buffer.from(tagHex, "hex"))  // throw si MAC invalide
  return Buffer.concat([
    decipher.update(Buffer.from(ctHex, "hex")),
    decipher.final(),
  ]).toString("utf8")
}

function getKeyFromEnv(): Buffer {
  const hex = process.env.ENCRYPTION_KEY?.trim() ?? ""
  if (hex.length !== 64 || !/^[0-9a-fA-F]+$/.test(hex))
    throw new Error("ENCRYPTION_KEY invalide — doit être 64 hex chars (32 bytes)")
  return Buffer.from(hex, "hex")
}
// Générer une clé : node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

**Règles :**
- IV aléatoire différent à chaque chiffrement (jamais réutilisé)
- `getAuthTag()` après `final()` — obligatoire pour l'authenticité
- Rotation de clé = re-chiffrement de toutes les données existantes

---

### Anti-Enumeration & Timing Attack

```typescript
// Ne PAS court-circuiter le hash si l'utilisateur n'existe pas
// (sinon la différence de timing révèle si l'email existe)
const user = await findUserByEmail(email)
const hashToCheck = user?.password_hash
  ?? "$2b$12$0000000000000000000000000000000000000000000000000000XX"
const passwordOk = await bcrypt.compare(password, hashToCheck)

if (!user || !passwordOk) {
  // Message générique — pas "email inconnu" ni "mauvais mot de passe"
  return res.status(401).json({ error: "Identifiants incorrects" })
}
```

**Règles :**
- Message d'erreur **toujours identique** (pas de distinction email/password invalide)
- Auth par **email uniquement** — évite l'énumération via usernames courts (`admin`, `root`…)
- Hash factice du même coût que bcrypt pour équilibrer le timing

---

### Password Strength Validation

Au-delà du hash, valider la complexité avant d'accepter un mot de passe :

```typescript
function validatePasswordStrength(password: string): string | null {
  if (password.length < 16)            return "Minimum 16 caractères requis."
  if (!/[a-z]/.test(password))        return "Au moins une lettre minuscule."
  if (!/[A-Z]/.test(password))        return "Au moins une lettre majuscule."
  if (!/\d/.test(password))           return "Au moins un chiffre."
  if (!/[^a-zA-Z\d]/.test(password)) return "Au moins un caractère spécial."
  return null
}
// Appeler AVANT hashPassword, côté serveur (pas uniquement côté client)
```

---

### Tokens de reset one-shot (SHA-256)

Ne jamais stocker un token de reset en clair — le hacher avant persistance :

```typescript
import crypto from "crypto"

// Génération (côté serveur, envoyé par email)
const rawToken = crypto.randomBytes(32).toString("hex")

// Stockage (seulement le hash, jamais le raw)
const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex")
await db`INSERT INTO reset_tokens (token_hash, user_id, expires_at, used)
         VALUES (${tokenHash}, ${userId}, NOW() + INTERVAL '1 hour', false)`

// Vérification
const hash = crypto.createHash("sha256").update(req.token).digest("hex")
const row  = await db`SELECT * FROM reset_tokens
                      WHERE token_hash = ${hash} AND used = false AND expires_at > NOW()`
```

---

### Bearer Token pour routes internes (Cron / Worker)

Protéger les routes non-utilisateur (cron jobs, workers) par un secret partagé :

```typescript
// lib/auth-bearer.ts
export function authorizedBearer(req: Request, secretEnv: "CRON_SECRET" | "WORKER_SECRET"): boolean {
  const secret = process.env[secretEnv]
  if (!secret) return false
  return req.headers.get("authorization") === `Bearer ${secret}`
}

// Usage dans une route
export async function POST(req: Request) {
  if (!authorizedBearer(req, "CRON_SECRET"))
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  // ...
}
```

**Règles :**
- Secrets à entropie maximale (64+ hex chars = 32 bytes random)
- Ne jamais logger ou exposer ces secrets côté client
- Stocker dans les env vars serveur (jamais `NEXT_PUBLIC_*`)

---

### Rate Limiting (Next.js / Vercel Serverless)

```typescript
// lib/rate-limit.ts — sliding window in-memory
// ⚠️ Non partagé entre instances Lambda. Pour usage critique → Upstash Ratelimit + Vercel KV

interface Bucket { count: number; resetAt: number }
const buckets = new Map<string, Bucket>()
const MAX_KEYS = 5000  // cap mémoire

export function rateLimit(req: Request, scope: string, max: number, windowMs: number): NextResponse | null {
  const ip  = req.headers.get("x-forwarded-for")?.split(",")[0].trim() ?? "local"
  const key = `${scope}:${ip}`
  const now = Date.now()

  // Eviction des buckets expirés si cap atteint
  if (buckets.size >= MAX_KEYS)
    for (const [k, b] of buckets) if (b.resetAt < now) buckets.delete(k)

  const b = buckets.get(key)
  if (!b || b.resetAt < now) { buckets.set(key, { count: 1, resetAt: now + windowMs }); return null }
  if (b.count >= max) {
    const retryAfter = Math.ceil((b.resetAt - now) / 1000)
    return NextResponse.json(
      { error: "Trop de tentatives — réessayez plus tard" },
      { status: 429, headers: { "Retry-After": String(retryAfter) } },
    )
  }
  b.count++
  return null
}

// Limites recommandées par endpoint
// login          : 5 req / 15 min
// login/2fa      : 5 req / 15 min
// forgot-password: 3 req / 60 min
// reset-password : 5 req / 60 min
```

---

### JWT Best Practices

```typescript
import jwt from 'jsonwebtoken';

// Token generation
function generateToken(userId: string): string {
  return jwt.sign(
    { sub: userId },
    process.env.JWT_SECRET!,
    {
      expiresIn: '15m',      // Short-lived access tokens
      algorithm: 'HS256',
    }
  );
}

// Token verification
function verifyToken(token: string): { sub: string } {
  return jwt.verify(token, process.env.JWT_SECRET!, {
    algorithms: ['HS256'],   // Explicitly specify allowed algorithms
  }) as { sub: string };
}
```

### Password Hashing

```typescript
import bcrypt from 'bcrypt';

const SALT_ROUNDS = 12;  // Minimum 10, recommended 12+

async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}
```

```python
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)
```

### Rate Limiting

```typescript
import rateLimit from 'express-rate-limit';

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,                   // 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
});

// Apply to auth routes
app.use('/api/auth', rateLimit({
  windowMs: 60 * 1000,  // 1 minute
  max: 5,                // 5 attempts per minute
  message: 'Too many login attempts, please try again later',
}));
```

---

## Security Headers

```typescript
import helmet from 'helmet';

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
  },
}));
```

---

## Security Testing Checklist

Run before every release:

```markdown
## Security Checklist

### Secrets & Environment
- [ ] No secrets in code (run detect-secrets)
- [ ] .env files in .gitignore
- [ ] .env.example exists with all required vars
- [ ] Environment validated at startup

### Dependencies
- [ ] npm audit / safety check passes
- [ ] No known vulnerabilities in dependencies
- [ ] Dependencies up to date (Dependabot enabled)

### Input Validation
- [ ] All API inputs validated with schema (Zod/Pydantic)
- [ ] File uploads restricted by type and size
- [ ] Path traversal prevented

### Authentication
- [ ] Passwords hashed with bcrypt (12+ rounds)
- [ ] Password strength validated server-side (16+ chars, maj+min+chiffre+spécial)
- [ ] JWTs use short expiration
- [ ] Rate limiting on auth endpoints (5/15min login, 3/60min forgot-password)
- [ ] Session tokens rotated on login (crypto.randomBytes)
- [ ] Cookies : httpOnly + sameSite + secure (prod) + maxAge explicite
- [ ] Isolation des modes : entrée en mode → session révoquée ; login → cookie de mode effacé
- [ ] Routes d'écriture : mode guard (`isDemoRequest`…) vérifié AVANT `hasValidSession`
- [ ] Logout du mode dans `PUBLIC_PATHS` (atteignable sans vraie session)
- [ ] Multi-tenant : `tenant_id` lié à la session en DB (jamais cookie séparé)
- [ ] Multi-tenant : toutes les queries scopées sur le tenant de la session (pas du body)
- [ ] Multi-tenant : `WHERE id = ? AND tenant_id = ?` sur toutes les mutations
- [ ] Multi-tenant : changement de tenant → nouvelle session (pas juste un cookie swappé)
- [ ] Auth par email uniquement (pas username) — anti-enumeration
- [ ] Message d'erreur générique "Identifiants incorrects" (pas email/password distinct)
- [ ] Timing attack mitigé : hash factice si user inconnu
- [ ] Reset tokens : hash SHA-256 avant stockage, one-shot + TTL court
- [ ] 2FA TOTP si disponible : cookie pending JWT (5 min) entre les 2 étapes
- [ ] Secrets TOTP chiffrés AES-256-GCM en DB (jamais en clair)
- [ ] Backup codes 2FA : one-shot, chiffrés en DB, consommés à l'usage
- [ ] Routes internes (cron/worker) protégées par Bearer token haute entropie

### Database
- [ ] Parameterized queries only
- [ ] Least privilege database user
- [ ] Connection strings not logged

### Headers & CORS
- [ ] Security headers enabled (helmet)
- [ ] CORS restricted to known origins
- [ ] HTTPS only in production

### Logging
- [ ] No secrets in logs
- [ ] No PII in logs (or properly masked)
- [ ] Failed auth attempts logged
```

---

## Security Anti-Patterns

- ❌ Secrets in `VITE_*`, `NEXT_PUBLIC_*`, or `REACT_APP_*` env vars (client-exposed!)
- ❌ Secrets in code or config files committed to git
- ❌ .env files without .gitignore entry
- ❌ String concatenation for SQL queries
- ❌ `dangerouslySetInnerHTML` without sanitization
- ❌ `eval()` or `new Function()` with user input
- ❌ Passwords stored as plain text or weak hash (MD5, SHA1)
- ❌ JWTs with no expiration or very long expiration
- ❌ No rate limiting on authentication endpoints
- ❌ Logging sensitive data (passwords, tokens, PII)
- ❌ Using `*` for CORS origins in production
- ❌ Ignoring npm audit / safety check warnings
- ❌ Running as root / admin in production
- ❌ Hardcoded credentials for any environment
- ❌ Disabling SSL/TLS verification
- ❌ Cookies sans `httpOnly` (exposés au JS client — vol XSS)
- ❌ Cookies sans `sameSite` (CSRF possible)
- ❌ Token de session dans `localStorage` ou `sessionStorage`
- ❌ Stocker un secret TOTP ou backup code en clair en DB
- ❌ Court-circuiter le hash si l'utilisateur n'existe pas (timing oracle)
- ❌ Message "email inconnu" ou "mauvais mot de passe" distinct (enumeration)
- ❌ Auth par username court (`admin`, `root`) — préférer email
- ❌ Token de reset stocké en clair — toujours SHA-256 avant persistance
- ❌ Bearer secret < 32 bytes d'entropie (utiliser `crypto.randomBytes(32).toString("hex")`)
- ❌ Rate limit uniquement côté client (doit être côté serveur, par IP)
- ❌ Cookie de mode posé sans révoquer la session réelle (coexistence → writes en DB réelle depuis le mode)
- ❌ `hasValidSession` vérifié avant `isDemoRequest` sur les routes d'écriture (session valide + cookie démo → fuite)
- ❌ Route de logout du mode non-publique (proxy bloque le POST → cookie de mode jamais effaçable)
- ❌ `issueSessionResponse` sans `clearModeCookie` (ancien cookie de mode survit au login normal)
- ❌ `tenant_id` dans un cookie séparé, surtout non-httpOnly (falsifiable côté client)
- ❌ Changement de tenant par swap de cookie sans révoquer la session (session A toujours valide sur tenant B)
- ❌ `tenantId` lu du body/params pour scoper les queries (injection de tenant arbitraire)
- ❌ `WHERE id = ?` sans `AND tenant_id = ?` sur les mutations (cross-tenant write/delete silencieux)
- ❌ Impersonation admin sans contexte isolé (admin agit avec ses propres droits sur le tenant cible)
