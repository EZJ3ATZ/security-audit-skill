# security-audit — skill de auditoria de segurança para Claude Code

Uma [skill](https://docs.anthropic.com/en/docs/claude-code/skills) de Claude Code que faz
**auditoria de segurança com mentalidade de invasor** e **root cause analysis de bugs
difíceis** sobre código que você está autorizado a analisar. Whitebox por padrão;
blackbox/DAST sob demanda.

Não é um scanner. É um **segundo especialista criterioso** — o revisor que acha o que a
revisão convencional deixa passar: o controle *ausente*, o erro de lógica de negócio, a
race condition, a cadeia de achados pequenos que juntos viram um caminho crítico.

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
- **Blackbox / DAST (opt-in):** bate no app publicado de fora (headers, flags de cookie,
  endpoint alcançável, auth de fato aplicada) — só quando você pede ou passa uma URL.
- **Portão de validação:** todo achado ≥Médio passa por 6 perguntas (alcançável? sem
  mitigação no caminho? cenário concreto? contraprova falhou? severidade contextual? fato ou
  hipótese?) antes de virar relatório. Falhou uma → rebaixa. É a diferença entre relatório e ruído.
- **Chaining:** achados nunca são ilhas — a skill monta a cadeia (Baixo + Médio → Alto).
- **Cobertura honesta:** toda auditoria declara o que varreu e o que ficou de fora. Um
  falso-negativo escondido é pior que um falso-positivo.

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

Depois, no Claude Code: `/security-audit` — ou peça "audite a segurança disto", "tem furo
aqui?", "threat model", "revisar antes do deploy".

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
