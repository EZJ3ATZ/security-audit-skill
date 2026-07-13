# Autenticação: OAuth2 / OIDC / JWT / SAML / sessão

Autenticação (quem é) é a fronteira mais atacada. Aqui o erro raramente é o algoritmo — é a **validação que faltou**: um token aceito sem conferir assinatura, um escopo largo demais, uma sessão que não expira. Comece confirmando que todo token/asserção é **verificado no servidor** antes de qualquer decisão.

## JWT — os furos clássicos

**Grep:** `jwt.decode`, `jwt.encode`, `verify=False`, `algorithms=`, `verify_signature`, `HS256`, `RS256`, `decode_complete`, `get_unverified`

- **`verify=False` / `options={"verify_signature": False}`** → token aceito sem checar assinatura = forja livre. Nunca em produção.
- **`algorithms` não fixado** → ataque `alg: none` ou confusão RS256→HS256 (assina com a chave pública como se fosse segredo HMAC). Sempre passe `algorithms=["RS256"]` explícito e recuse o resto.
- **Não validar `exp` / `nbf` / `aud` / `iss`** → token expirado ou de outro público reaproveitado. Confira expiração, audience e issuer.
- **Segredo HS256 fraco/hardcoded** → força-bruta do segredo, forja de qualquer token. Segredo forte, do ambiente.
- **Dado sensível no payload** → JWT é base64, não é cifrado. Nada de senha/PII/segredo no claim.

**Ruim:**
```python
data = jwt.decode(token, options={"verify_signature": False})   # aceita qualquer coisa
data = jwt.decode(token, key, algorithms=["HS256", "RS256"])     # confusão de alg
```
**Correção:**
```python
data = jwt.decode(token, key, algorithms=["RS256"],
                  audience=EXPECTED_AUD, issuer=EXPECTED_ISS)
```

## OAuth2 / OIDC

Fluxo de terceiro (Microsoft Graph, Google). O perigo está nos parâmetros de fluxo e no que você faz com o token depois.

**Grep:** `state=`, `redirect_uri`, `code`, `access_token`, `refresh_token`, `client_secret`, `scope`, `authorize`, `token_endpoint`

- **Sem `state` (ou não validado no callback)** → CSRF no login / account takeover. Gere `state` aleatório, guarde na sessão, confira na volta. PKCE (`code_verifier`/`code_challenge`) em client público.
- **`redirect_uri` não fixo/whitelisted** → roubo de código de autorização. O provider deve ter a lista exata; nunca monte o redirect a partir de input.
- **Escopo largo demais** → o app pede mais do que precisa. Graph app-only tenant-wide (`Mail.Read` em toda a org) é o exemplo: poderoso e perigoso. Confirme que o escopo é o mínimo e que a **caixa consultada deriva da sessão do usuário, não do request** (senão vira leitura indevida / SSRF de identidade).
- **`client_secret` no front / no bundle / no log** → vazamento total. Só no servidor, em env var.
- **Token guardado inseguro** → refresh token em log, em tabela sem restrição, em localStorage. Trate como segredo.
- **App-only sem autorização por recurso** → o token do app pode tudo; a autorização de *qual dado este usuário vê* tem que ser feita pelo seu código, não pelo Graph. Ver flask-python.md §authz.

## SAML

**Grep:** `SAMLResponse`, `assertion`, `signature`, `xmlsec`, `validate_signature`, `InResponseTo`, `Audience`, `NotOnOrAfter`

- **Assinatura não validada / validada na resposta mas não na asserção** → forja de asserção. Valide a assinatura da **asserção** que carrega a identidade.
- **XML Signature Wrapping (XSW)** → atacante injeta uma asserção não assinada ao lado da assinada; parser pega a errada. Use lib madura e confira que a asserção validada é a que você consome.
- **Sem checar `Audience`, `NotOnOrAfter`, `InResponseTo`** → replay / asserção de outro SP. Valide todos.
- **XXE no parser de XML** → leitura de arquivo / SSRF. Desligue entidades externas (`resolve_entities=False`, `no_network=True`).

## Sessão (cookie)

**Grep:** `session[`, `SECRET_KEY`, `Set-Cookie`, `permanent`, `session.permanent`, `SESSION_COOKIE`, `logout`, `session.clear`

- **`SECRET_KEY` fixo/previsível** → forja de sessão assinada do Flask. Aleatório, do ambiente, **não** commitado. Se vazar, rotacione (invalida sessões).
- **Cookie sem `HttpOnly; Secure; SameSite`** → roubo via XSS / envio em CSRF / trânsito em claro. Configure `SESSION_COOKIE_HTTPONLY=True`, `SECURE=True`, `SAMESITE="Lax"`.
- **Sessão não expira / não invalida no logout** → sessão eterna reaproveitável. Defina expiração; `session.clear()` no logout.
- **Sem rotação de id de sessão após login** → session fixation. Regenere a sessão ao autenticar.
- **Papel/privilégio guardado no cookie sem re-checar** → se o cliente influencia, é escalonamento. Decisão de authz sempre revalidada no servidor a cada request (o guard `before_request` do ERP faz isso — confirme que cobre tudo).

## Senha e reset

- **Hash fraco** (MD5/SHA1/sem salt) → cracking. Use `bcrypt`/`argon2`/`scrypt`.
- **Reset por token previsível/sem expiração/reutilizável** → takeover. Token aleatório longo, uso único, expira rápido, invalidado após uso.
- **Login sem lockout/rate limit** → brute force. Ver owasp-web.md e flask-python.md §rate limiting. Não revele "usuário existe" vs "senha errada" (enumeração).
- **Cadastro pendente / esqueci-senha** já existem no ERP (auditoria 05/07 desatualizada nesse ponto) — revalide o fluxo de token mesmo assim.

## Criptografia aplicada — os erros que dão CVE

Cripto raramente quebra pelo algoritmo; quebra pelo **uso errado**. Procure:

**Validação de TLS desabilitada (CWE-295) — MITM.** O mais grave e comum em código de integração.
**Grep:** `verify=False`, `_create_unverified_context`, `CERT_NONE`, `InsecureRequestWarning`, `rejectUnauthorized: false`, `check_hostname = False`, `disable_warnings`
- `requests.get(url, verify=False)` ou `ssl._create_default_https_context = ssl._create_unverified_context` → o cliente aceita **qualquer** certificado; um MITM lê/altera o tráfego (incl. token no header). ⚠ O `seu script de deploy` do usuário faz exatamente isso — é achado, não conveniência. Correção: remover o bypass; se há erro de CA corporativa, apontar `verify=/caminho/ca.pem`, nunca desligar.

**Comparação não constante de segredo (CWE-208) — timing attack.**
**Grep:** `==` / `!=` comparando token/HMAC/assinatura/senha-hash, `hmac.new(...).hexdigest() ==`
- Comparar segredo com `==` vaza o comprimento do prefixo correto por tempo. Use `hmac.compare_digest(a, b)` (Python) / `crypto.timingSafeEqual` (Node).

**RNG inseguro para valor de segurança (CWE-338).**
**Grep:** `random.random`, `random.randint`, `random.choice`, `Math.random`, `uuid1(`
- Token/reset/session id/salt gerado com `random` (Mersenne Twister, previsível) → forjável. Use `secrets` (Python) / `crypto.randomBytes` (Node). `uuid4` ok para id; para segredo, `secrets.token_urlsafe`.

**Hash/cifra fraca ou mal usada.**
**Grep:** `md5`, `sha1`, `DES`, `RC4`, `ECB`, `hashlib.sha256(senha` (hash rápido p/ senha, sem salt/KDF), `Random IV` reutilizado, `AES.new(...MODE_ECB`
- Senha: só `bcrypt`/`argon2`/`scrypt` (KDF lento). SHA-256 puro em senha = crackável. MD5/SHA1 para integridade de segurança = quebrados.
- Cifra: ECB vaza padrão; IV/nonce **nunca** reusado com a mesma chave (GCM/CTR); prefira AEAD (AES-GCM, ChaCha20-Poly1305).

**Cripto caseira (CWE-327).** Qualquer XOR/rolagem própria "para ofuscar", ou protocolo montado à mão. Regra: não invente cripto; use lib madura.

## Contexto dos apps

Já dito onde importa, não repito: caixa do Graph **deriva da sessão, não do request** (§OAuth acima + flask-python.md §SSRF); JWT do Supabase **verificado no servidor** e usuário derivado dele, não de id vindo do corpo (supabase-rls.md §3). Fatos datados dos apps → `contexto-local.md`.
