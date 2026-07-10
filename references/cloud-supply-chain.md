# Cloud / CI-CD / Docker / secrets / supply chain

O código pode estar limpo e o app cair mesmo assim: por um segredo commitado, uma dependência maliciosa, um container rodando como root, um pipeline que executa código de PR de terceiro. Aqui a fronteira de confiança é o **ambiente e a cadeia de build**, não a requisição.

## Secrets — o furo nº 1 em cloud

**Grep:** `SECRET`, `PASSWORD`, `API_KEY`, `TOKEN`, `ghp_`, `github_pat`, `sk-`, `xoxb-`, `Bearer `, `client_secret`, `service_role`, `-----BEGIN`, `.env`, `credentials`

- **Segredo hardcoded no código / no repo** → qualquer um com acesso ao repo (ou ao bundle público) tem a chave. Mover para env var. Se já foi commitado, **rotacione** — apagar do HEAD não basta, fica no histórico.
- **`.env` / `.pem` / `*.key` commitado** → confira `.gitignore` e o histórico (`git log --all --full-history -- .env`). O o script de deploy faz push por API — garanta que ele nunca empacote um arquivo de chave, tokens ou `.env` na lista de arquivos.
- **Segredo em log** → token/header/`request` completo logado em produção. Vaza para quem lê log (Railway, Sentry).
- **Escopo do token maior que o necessário** → o PAT do GitHub do o script de deploy só precisa de `contents:write` naquele repo. Um token `repo`+`admin` amplo é dano em massa se vazar. Escopo mínimo, expiração curta.

## Variáveis de ambiente e config de plataforma (Railway)

- Secrets como env var no Railway: bom. Confira que **não** são reimpressos em endpoint de debug/health, nem expostos ao front (só `NEXT_PUBLIC_`/`VITE_` vão para o bundle — nada sensível com esse prefixo).
- **CORS `*`** com credenciais → qualquer origem chama sua API autenticada. Restrinja à origem do app.
- **Endpoint de debug em produção** (`/controle/graph/debug_*`) → confirme que exige admin e não vaza tokens/estrutura interna. Debug útil não pode ser porta aberta.
- **Banco exposto** → Postgres do Railway acessível publicamente sem necessidade. Restrinja rede; senha forte.

## Docker / containers

**Grep (Dockerfile / compose):** `FROM`, `USER`, `--privileged`, `ADD`, `COPY . `, `latest`, `ARG`, `ENV.*SECRET`, `chmod 777`, `docker.sock`

- **Roda como root** (sem `USER` não-root) → escape de container = root no host. Adicione um usuário sem privilégio.
- **Segredo em `ARG`/`ENV` do build** → fica na imagem/camadas, `docker history` revela. Use secret mount ou injete em runtime.
- **`FROM ...:latest`** → build não reproduzível, puxa versão comprometida sem querer. Pin por tag/digest.
- **`COPY . .` sem `.dockerignore`** → `.env`, `.git`, chaves entram na imagem. Tenha `.dockerignore`.
- **`--privileged` / montar `docker.sock`** → equivale a root no host. Só com justificativa forte.
- **Imagem base com CVE** → escaneie (`trivy`, `docker scout`).

## Kubernetes — só se o projeto usar (os apps do usuário NÃO usam; estão em Railway)

Pule esta seção salvo se houver `*.yaml` de k8s / Helm no repo. Se houver: Secret do k8s é **base64, não cifrado** (encryption-at-rest + RBAC restrito); Pod sem `securityContext` roda root; sem NetworkPolicy tudo fala com tudo; `hostPath`/`hostNetwork`/`privileged` desnecessário = escape. Menor privilégio em tudo.

## CI/CD — pipeline como superfície de ataque

**Grep (workflows):** `pull_request_target`, `${{ github.event`, `run:`, `secrets.`, `actions/checkout`, `@main`, `@master`, `curl | sh`, `permissions:`

- **`pull_request_target` + checkout do código do PR** → PR de fork roda com secrets do repo = exfiltração de segredo por qualquer um que abra PR. Padrão perigoso; use `pull_request` para código não confiável.
- **Interpolação de `github.event.*` (título/branch/PR) direto em `run:`** → command injection no runner. Passe por env var, não interpole no shell.
- **Action de terceiro por tag móvel (`@v3`/`@main`)** → dono da action muda e roda no seu pipeline. Pin por SHA de commit.
- **`permissions` do `GITHUB_TOKEN` não restrito** → default largo. Defina `permissions:` mínimo por job.
- **Secret ecoado em step** → aparece no log do build (que pode ser público). Nunca `echo $SECRET`.

## Supply chain — dependências

**Grep / comandos:** `npm audit`, `pip list --outdated`, `requirements.txt`, `package.json`, `package-lock.json`, `poetry.lock`

- **Dependência com CVE conhecido** → `npm audit`, `pip-audit`. Priorize o que está no caminho de execução com input não confiável.
- **Sem lockfile / lockfile não commitado** → build pega versão diferente, sujeito a takeover de pacote. Commite o lock.
- **Typosquatting / pacote suspeito** → nome parecido com um popular, publicado há pouco, mantenedor único. Confira antes de adicionar.
- **Dependência puxada de fonte não oficial** (URL git, index alternativo) → confira a procedência.

## Contexto dos apps

Detalhes datados (PAT do o script de deploy, escopo, o que já mordeu antes) → `contexto-local.md` (opcional — ver README). Princípio atemporal que fica aqui: **deploy automático no push de uma branch = o push É o deploy em produção**; não há gate de review, então quem escreve na branch escreve em produção — trate o pipeline como superfície de ataque de primeira classe. Supabase `service_role` (ignora RLS) nunca no front/bundle/log → supabase-rls.md.
