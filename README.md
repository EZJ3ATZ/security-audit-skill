# security-audit — skill de auditoria de segurança para Claude Code

Uma [skill](https://docs.anthropic.com/en/docs/claude-code/skills) de Claude Code que faz
**auditoria de segurança com mentalidade de invasor** e **root cause analysis de bugs
difíceis** sobre código que você está autorizado a analisar. Whitebox por padrão;
blackbox/DAST sob demanda.

Não é *só* um scanner. Ela **roda o ferramental determinístico** (secret-scan, SAST,
auditoria de dependência) como triagem e **raciocina por cima** — é o segundo especialista
criterioso que acha o que a revisão convencional deixa passar: o controle *ausente*, o erro
de lógica de negócio, a race condition, a cadeia de achados pequenos que juntos viram um
caminho crítico.

## Comece pelo link (link-first)

O primeiro passo é dar a ela **a URL do sistema a auditar** — a auditoria começa pelo sistema
**vivo**, não por um trecho de código solto. Um atacante real não abre o seu repositório; ele
abre o seu site. Dado um link, a skill roda de ponta a ponta: mapeia a superfície pela URL
(Fase 1), confirma no código se você fornecer o repo (Fase 2), e entrega o relatório por
severidade. Sem URL, ela cai direto no whitebox — não trava.

## O diferencial: protocolo invasor-primeiro (duas fases)

O jeito nº 1 de uma revisão vazar furo é **ler o código primeiro** e absorver a moldura do
autor — aí você deixa de ver o controle que *deveria existir e não existe*. Contra isso, a
skill separa hipótese de confirmação:

1. **Fase 1 — Invasor (sem código).** A partir da descrição / arquitetura / papéis / URL,
   monta o dossiê de ataque (joias da coroa, objetivos, fronteiras de confiança, STRIDE) e
   produz uma **lista priorizada de hipóteses** — *"se eu atacasse, tentaria X; o controle Y
   deveria barrar"* — tudo marcado "A verificar". Então **para** e espera o código.
2. **Fase 2 — Investigador (código liberado).** Para cada hipótese, prova ou derruba por
   rastreio do dado até o sink. **Regra anti-ancoragem: julgue o código contra a hipótese,
   não a hipótese contra o código** — controle esperado ausente é achado, mesmo que o código
   "pareça organizado".

Isso reproduz o fluxo `pense como invasor → me mostre o código → investigue` — o que separa
red team de code review comum.

## Como usa

- **Whitebox (padrão):** lê o código-fonte, rastreia o dado da fonte não confiável ao sink.
- **Ferramental cabeado:** `py tools/scan.py <alvo> [--include-deps]` orquestra
  **detect-secrets** (segredos), **bandit** (SAST Python) e **pip-audit** (CVE de deps), e
  roda gitleaks/semgrep/npm audit se presentes. A saída é **triagem, não veredito** — a skill
  confirma cada candidato por rastreio (secret-scan e deps pegam o que o raciocínio não pega;
  o SAST costuma ter falso-positivo, então cada hit passa pelo portão).
- **Blackbox / DAST (opt-in):** bate no app publicado de fora (headers, flags de cookie,
  endpoint alcançável, auth de fato aplicada) — quando você pede ou passa uma URL.
- **Portão de validação:** todo achado ≥Médio passa por 6 perguntas (alcançável? sem
  mitigação no caminho? cenário concreto? contraprova falhou? severidade contextual? fato ou
  hipótese?) antes de virar relatório. Falhou uma → rebaixa. É a diferença entre relatório e ruído.
- **Chaining:** achados nunca são ilhas — a skill monta a cadeia (Baixo + Médio → Alto).
- **Cobertura honesta:** toda auditoria declara o que varreu e o que ficou de fora. Um
  falso-negativo escondido é pior que um falso-positivo.

## O que ela agrega (honesto)

Contra um modelo forte — que já acha muito bug sozinho — o ganho **não é "achar mais" num
trecho pequeno**: em fixtures controladas, skill e baseline empatam (o modelo forte gabarita
as duas). Isso é esperado e a skill não esconde. O valor está em três lugares que o modelo
**não entrega de graça**:

- **Rigor e forma:** relatório estruturado, rastreio fonte→sink verificável, **disciplina de
  falso-positivo** (nos testes: 0 decoy reportado como vulnerabilidade), cobertura declarada.
- **Runtime / config / infra:** headers de segurança, flags de cookie, TLS mal configurado —
  coisas que **não moram nas rotas** e escapam ao code review de código-fonte.
- **Ferramental determinístico:** secret-scan / SAST / deps que pegam segredo commitado,
  dependência com CVE e sink clássico — o que um raciocínio num ponto no tempo não pega.

Onde ela comprovadamente rende mais é no **sistema real de múltiplos arquivos** (não no trecho
isolado): num teste real achou mais que o baseline sem skill. **Ressalva honesta:** as
medições são de N pequeno — sinal forte, ainda não prova estatística.

## Cobertura

Referências carregadas sob demanda (só a stack em jogo, para não gastar contexto):

| Domínio | Arquivo |
|---|---|
| Flask / Python / Postgres | `references/flask-python.md` |
| Supabase / RLS / edge functions | `references/supabase-rls.md` |
| React / TanStack / front | `references/react-frontend.md` |
| API / OWASP API Top 10 (BOLA/BFLA/BOPLA) | `references/api-security.md` |
| OAuth2 / OIDC / JWT / SAML / sessão / cripto | `references/auth-tokens.md` |
| Cloud / CI-CD / Docker / secrets / supply chain | `references/cloud-supply-chain.md` |
| IA / LLM / prompt injection | `references/llm-security.md` |
| Threat modeling, CVSS/CWE/CAPEC, lógica de negócio, race conditions, RCA | `references/threat-modeling.md` |
| OWASP Web Top 10 + severidade + template de achado | `references/owasp-web.md` |
| Blackbox / DAST | `references/blackbox-dast.md` |

Padrões: OWASP Web Top 10 (2021), OWASP API Top 10 (2023), OWASP LLM Top 10 (2025),
CWE v4.x, CVSS v3.1. Inclui notas de CVEs recentes por stack (ex.: CVE-2025-48757 RLS
off-by-default no Supabase/Lovable; CVE-2024-34069 Werkzeug debugger; CVE-2025-29927 bypass
de middleware do Next.js).

## Instalação

Copie a pasta para o diretório de skills do Claude Code:

```bash
git clone https://github.com/<seu-usuario>/security-audit-skill.git
cp -r security-audit-skill ~/.claude/skills/security-audit
```

Ferramental opcional (recomendado — habilita `tools/scan.py`):

```bash
py -m pip install detect-secrets bandit pip-audit
```

Depois, no Claude Code: `/security-audit` — ou passe a **URL do sistema** e peça "audite a
segurança disto", "tem furo aqui?", "threat model", "revisar antes do deploy".

## Contexto local (opcional, recomendado)

A skill fica mais afiada sabendo onde os furos já apareceram *nos seus* apps. Copie
`references/contexto-local.example.md` para `references/contexto-local.md` e preencha. Se
contiver detalhe sensível (URLs de produção, vulnerabilidades ainda abertas), **mantenha-o
fora do controle de versão** — este repo público não o inclui de propósito.

## Escopo e ética

Escopo por **autorização, não autoria**: os seus apps e sistemas da sua organização que você
tem permissão para testar. Objetivo **defensivo** — achar, provar e corrigir para o dono.
Não use para atacar infra de terceiro sem relação; isso é crime, não auditoria.

## Um exemplo do tipo de furo que ela pega (genérico)

Uma "confused deputy": uma função de servidor que lê dados com credencial privilegiada
(service role, ignora RLS) e **confia no `tenant_id`/`id` que veio do navegador**. Parece
segura porque filtra por `tenant_id` — mas como o `tenant_id` é do atacante e a RLS foi
ignorada, o filtro não protege nada: qualquer usuário logado lê o recurso de qualquer tenant.
A skill pega isso porque a Fase 1 hipotetiza "authz por recurso tem que existir no servidor"
e a Fase 2 verifica se o pré-check usa o token do *usuário* (RLS ativa) antes do read
privilegiado — não apenas se "tem um filtro".

---

*Skill escrita em português. Método atemporal; as notas de CVE são datadas e devem ser
revisadas periodicamente.*
