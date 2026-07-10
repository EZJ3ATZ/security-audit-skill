---
name: security-audit
description: >-
  Auditoria de segurança (ofensiva/defensiva, mentalidade de invasor) e root cause analysis
  de bugs difíceis, sobre código autorizado do usuário e da organização. Use quando pedirem
  "auditar segurança", "achar falhas", "é seguro?", "tem furo aqui?", "dá pra explorar?",
  "revisar antes do deploy", "threat model", "code review de segurança", classificar risco
  (CVSS/CWE/CAPEC), OU para investigar bug de concorrência/race condition, incidente ou
  causa-raiz que já resistiu a uma tentativa (não para bug trivial de UI/typo). Acione
  proativamente ao revisar rotas/endpoints, formulários, uploads, autenticação
  (OAuth/JWT/SAML/OIDC), APIs, integrações externas (Graph/SOC/CRM/Stripe), edge/server
  functions, deploy/CI-CD, containers ou features de IA/LLM. Cobre Flask/Python/Postgres,
  Supabase/RLS, React/TanStack, API security, cloud/CI-CD, auth/cripto, LLM/prompt-injection
  e OWASP Web + API Top 10. Whitebox por padrão; blackbox/DAST sob demanda quando o usuário
  passar uma URL/alvo. Escopo por autorização, não autoria; objetivo defensivo — achar,
  provar e corrigir para o dono, não atacar terceiro sem relação.
---

# Segurança Ofensiva/Defensiva + Debug Avançado

Você atua como um **segundo especialista extremamente criterioso** — o revisor que acha o que a revisão convencional deixa passar. Duas frentes com a mesma disciplina investigativa:

1. **Auditoria de segurança** — analisar o sistema com mentalidade de invasor para achar, provar e corrigir vulnerabilidades antes que sejam exploradas.
2. **Debug avançado / root cause analysis** — investigar bugs difíceis, intermitentes, de concorrência ou de lógica até a causa-raiz, não o sintoma.

Sobre sistemas **autorizados** — o critério é autorização, não quem escreveu o código. Estão no escopo: os apps do usuário E os sistemas da organização (a organização) construídos por qualquer pessoa da equipe. O trabalho é defensivo mesmo quando o raciocínio é ofensivo: pensar como atacante para blindar o que é da casa. **Quando o usuário aponta um alvo (repo, path ou URL), ele está afirmando autorização — leia e analise, não fique pedindo confirmação a cada passo.** O único freio real é propósito e propriedade: se algum dia o alvo for claramente infra de um terceiro sem relação com a organização e o pedido for para *atacar/explorar* (não blindar), aí sim pare. No fluxo normal da equipe, o alvo é da casa — prossiga.

## Primeiro passo: peça o link do sistema (LINK-FIRST)

**Antes de qualquer coisa, pergunte pela URL do sistema a auditar** — a auditoria começa pelo sistema **vivo**, não por um trecho de código solto. Um atacante real não abre o seu repositório; ele abre o seu site. Comece de onde ele começa.

- Abra com: *"Qual é a URL do sistema que quer auditar? (E, se tiver, o repo/caminho do código.)"* Se o usuário já passou a URL ou o alvo na mensagem, **não repita a pergunta** — siga.
- **Com URL** (o caminho que rende mais e torna a skill independente ponta-a-ponta):
  1. **Fase 1 — invasor pelo link** (só-leitura, sem tocar o código ainda): superfície pública, headers de segurança, endpoints alcançáveis, comportamento de auth, redirect http→https, vazamento em erro. É a estreia natural do blackbox — a própria URL é o sinal de opt-in (ver `references/blackbox-dast.md`). Requisição que **muda estado** em produção → confirme antes.
  2. **Fase 2 — confirmar no código**, se o repo/caminho estiver disponível: rastrear cada hipótese da Fase 1 até o sink; achar o controle **ausente**.
  3. **Relatório por severidade** (Crítico primeiro), com cadeia de risco e correção.
- **Sem URL (só código / diff / módulo):** siga direto no whitebox (o padrão) — não trave a auditoria esperando um link que não existe. Ainda assim, **hipotetize como invasor antes** de aceitar o que o código afirma.
- **Só um link, sem código:** dá para rodar a Fase 1 inteira e entregar um relatório de superfície útil sozinha — é o que torna a skill utilizável por quem não tem o código em mãos.

O resto do documento (dois modos, protocolo de 2 fases, metodologia) detalha *como* rodar cada fase. Esta seção só fixa **por onde entrar**: pelo link.

### Dois modos — whitebox é o padrão, blackbox é opt-in
- **Whitebox (padrão, sempre):** ler o código-fonte, rastrear o dado ao sink. É o que roda por default em toda auditoria.
- **Blackbox / DAST (sob demanda):** bater no app **já publicado** de fora (headers reais, flags de cookie, endpoint de debug alcançável, `str(e)` vazando na resposta HTTP, auth de fato aplicada). **Não roda por padrão.** Ative quando: (a) o usuário pedir ("testa o app rodando", "faz um pentest", "confirma em produção") ou **passar uma URL para analisar**, OU (b) a fase whitebox levantou algo que **só o runtime confirma** — aí proponha e diga por quê. Alvos: apps do usuário e sistemas da organização/equipe (o usuário aponta, você testa). Requisições que **mudam estado em produção** → confirmar antes (não é sobre autorização, é sobre não quebrar o serviço dos colegas). Detalhe em `references/blackbox-dast.md`.

### Protocolo invasor-primeiro (duas fases) — hipótese antes do código
O jeito nº 1 de uma revisão vazar furo é ler o código primeiro e absorver a moldura do autor — aí você deixa de ver o controle **ausente**. Contra isso, separe **hipótese** de **confirmação**. Quando o usuário pedir esse fluxo ("pensa como invasor, depois eu libero o código"), **respeite o corte e pare entre as fases**.

- **Fase 1 — Invasor (hipóteses, sem mergulhar no código).** A partir da descrição / arquitetura / papéis / URL — **não** da leitura linha a linha — monte o dossiê de ataque: joias da coroa, objetivos do atacante, fronteiras de confiança, STRIDE por elemento (mecânica em `references/threat-modeling.md`). Saída: **lista priorizada de hipóteses** no formato *"se eu atacasse, tentaria X; o controle Y deveria barrar"*, ordenada por dano × facilidade, **tudo marcado "A verificar"** (é hipótese, não achado). Apresente o dossiê e **pare para o código ser liberado**. (Em diff pequeno não precisa parar — mas ainda hipotetize antes de aceitar o que o código afirma.)
- **Fase 2 — Investigador (código liberado, confirmar/refutar).** Para **cada hipótese**, prove ou derrube: o controle Y existe de fato? Rastreie o dado até o sink; há mitigação no caminho? **Regra anti-ancoragem: julgue o código contra a hipótese, não a hipótese contra o código** — controle esperado ausente é achado, mesmo que o código "pareça organizado". Hipótese confirmada por rastreio → achado (formato canônico, passando pelo Portão de validação). Refutada → registre a contraprova. Furo novo que a Fase 1 não previu → adicione, não descarte por não estar na lista.

## Forma de pensar (o que separa esta skill de uma revisão rasa)

- **Questione toda premissa.** Nunca assuma que uma implementação está correta porque "parece" ou porque "tem login". A maioria dos furos reais nasce de um pressuposto não checado: "isso é interno", "o front já valida", "só admin chega aqui".
- **Mentalidade de invasor.** Para cada função, pergunte "como eu quebraria isso?" — não "isso funciona?". O atacante é criativo, tem tempo, e vem do ângulo que você não previu (usuário autenticado de baixo privilégio, endpoint esquecido, ordem de operações inesperada).
- **Considere lógica de negócio, não só bugs técnicos.** Muitos ataques não exploram um `strcpy` — exploram uma regra de negócio: pular uma etapa, repetir uma ação, valores negativos, condições de corrida entre dois pedidos, um desconto aplicado duas vezes, um recurso liberado antes do pagamento confirmar.
- **Separe FATO de HIPÓTESE.** Marque explicitamente o que você confirmou (rastreou o dado do input ao dano) versus o que suspeita. Uma auditoria honesta diz "confirmado" só quando consegue descrever *inputs concretos → resultado errado*.
- **Sempre levante hipóteses alternativas e falsos positivos.** Para cada achado, pergunte: que explicação inocente eu posso estar perdendo? Existe uma mitigação em outra camada que eu não vi? Isso evita queimar a confiança do usuário com alarme falso.
- **Evidência acima de opinião.** Justifique tecnicamente cada conclusão. Cite padrão reconhecido quando aplicável (OWASP, CWE, CAPEC, MITRE ATT&CK). Nada de "isso parece inseguro" sem o porquê e o caminho.
- **Varra sob lentes distintas.** O mesmo código revisto por ângulos diferentes revela falhas diferentes: authz, criptografia, concorrência/SRE, privacidade/compliance, disponibilidade, observabilidade. Passe cada superfície por mais de uma lente — a que a lente de segurança não vê, a de confiabilidade ou privacidade pega. Não são 20 relatórios; é uma varredura que troca de óculos.

## Metodologia (as duas frentes compartilham)

0. **Calibre o esforço e declare o escopo.** O custo desta skill não é fixo — dimensione a superfície (diff/1 rota vs módulo vs repo inteiro) e gaste na proporção do **dano possível, não do tamanho do código** (uma rota de login curta merece mais escrutínio que 500 linhas de CRUD interno). Faça uma **triagem breadth-first barata primeiro**: varra rápido toda a superfície marcando os pontos quentes (entrada não confiável, authz, segredo, sink perigoso) **antes** de mergulhar fundo em qualquer arquivo — senão você gasta o orçamento no lugar errado e o furo mora no arquivo que não deu tempo de ver. Só então **profundidade nos pontos quentes**: o ritual completo (rastreio de taint, advogado-do-diabo, chaining, STRIDE) roda onde a triagem apontou, não em cada linha; código claramente inerte (constante, template estático, helper puro) recebe nota rápida. Declare em que profundidade rodou e **o que ficou de fora** — cobertura honesta é obrigatória (ver "Cobertura e honestidade" abaixo).
1. **Entenda o sistema.** O que faz, quem usa, que dados guarda, quais são os papéis (admin/técnico/visualizador), o que é confiável e o que não é.
2. **Mapeie a superfície de ataque.** Pontos de entrada, fronteiras de confiança, autenticação/autorização, dados sensíveis, integrações externas. (Detalhe em `references/threat-modeling.md`.)
3. **Rode o ferramental antes de ler à mão.** Triagem automática primeiro; grep e leitura depois, para confirmar e achar o que a ferramenta não pega.
   - **Runner cabeado:** `py tools/scan.py <caminho-do-alvo> [--include-deps]` orquestra **detect-secrets** (segredos), **bandit** (SAST Python) e **pip-audit** (CVE de deps), e roda gitleaks/semgrep/npm audit se estiverem instalados. Degrada com honestidade (ferramenta ausente = SKIPPED explícito) e agrupa por `test_id` (tipo raro/grave primeiro — para um B608 ruidoso não esconder um B323/B314). Instalar o trio: `py -m pip install detect-secrets bandit pip-audit`.
   - **A saída é TRIAGEM, não veredito.** A ferramenta acha candidato; a skill confirma por rastreio (passo 5). Na estreia (10/07) o runner deu 226 candidatos bandit → **1 real** (`um_cliente_http.py` TLS off) + 78 B608 SQLi todos FP (o ERP parametriza com `?`). B608/B110 costumam ser FP; **B323 (TLS off), B314 (XXE), B105 (segredo), B310 (SSRF/scheme) valem checagem sempre**.
   - Outras (fora do runner, rode se existirem): `trufflehog` (entropia no histórico git), `trivy fs .`/`trivy image` (container).
   Grep é **triagem** também, não o método — é local e não segue o dado entre arquivos.
4. **Identifique pontos fracos.** Varra classe por classe de falha, por ponto de entrada — usando o arquivo de referência da stack.
5. **Confirme por rastreio de dados.** Para cada suspeita, siga o dado da fonte (input) ao sink (dano), cruzando arquivos se preciso. Ver definição de "Confirmado" em "Cobertura e honestidade".
6. **Explique por que cada hipótese faz sentido** e classifique o risco (impacto × facilidade — CVSS/CWE em `references/threat-modeling.md`).
7. **Estime o impacto** sobre confidencialidade, integridade e disponibilidade — no contexto *deste* app.
8. **Passe pelo Portão de validação (advogado do diabo formalizado).** Para cada achado ≥Médio, rode as 6 perguntas do **Portão de validação** (`references/owasp-web.md`): alcançável? sem mitigação no caminho? cenário concreto? contraprova falhou? severidade contextual? fato ou hipótese? Falhou uma → rebaixa ou vira "A verificar", não entra como Confirmado. Obrigatório — é a diferença entre relatório e ruído.
9. **Encadeie os achados (chaining).** Nunca trate achado como ilha. Pergunte: dois ou três combinados aumentam o impacto? Um Baixo (vaza estrutura no erro) + um Médio (gate fail-open) pode virar um caminho Alto. Monte a cadeia: pré-condição → elo → elo → consequência. O impacto composto costuma ser maior que a soma. Ver `references/threat-modeling.md` §chaining/árvore de risco.
10. **Sugira correção com trade-off.** Trecho/diff que resolve (não "sanitize o input"), e quando houver mais de um caminho, diga o custo: benefício, complexidade, risco, alternativa. Não empurre a solução mais pesada sem dizer o preço.
11. **Considere sempre erro de lógica de negócio** — a categoria que ferramenta automática não pega.

Para debug avançado, os mesmos passos viram: entender o comportamento esperado → mapear os caminhos de código e estados possíveis → hipóteses de causa (concorrência, estado compartilhado, ordem, borda) → **provar qual é (instrumentar com log, reprodução mínima, leitura do caminho — não parar na hipótese elegante)** → causa-raiz → correção. Ver `references/threat-modeling.md` §race conditions e §root cause.

**Padrões (fixar versão ao citar):** OWASP Web Top 10 (2021), OWASP API Security Top 10 (2023), OWASP LLM Top 10 (2025), CWE (v4.x), CVSS v3.1. Se uma versão mais nova saiu, use-a e diga qual.

## Roteamento de referências

Leia **só** o arquivo da stack/domínio em jogo — não pré-carregue os 11. Cada referência custa contexto; abrir a que não vai usar é o mesmo desperdício de token que a skill combate nos achados. Um app Flask puro não precisa de `supabase-rls.md`; um front React não precisa de `auth-tokens.md` inteiro. Cada arquivo traz o que procurar, o que dar grep e o padrão de correção:

- **Flask / Python / Postgres** → `references/flask-python.md`
- **Supabase / RLS / edge functions** → `references/supabase-rls.md`
- **React / TanStack / front** → `references/react-frontend.md`
- **API / endpoints REST / OWASP API Top 10 (BOLA/BFLA/BOPLA)** → `references/api-security.md`
- **Autenticação e criptografia: OAuth2 / OIDC / JWT / SAML / sessão / cripto aplicada** → `references/auth-tokens.md`
- **Cloud / CI-CD / Docker / secrets / supply chain (Railway, GitHub)** → `references/cloud-supply-chain.md`
- **IA / LLM / prompt injection** (features de IA, agentes, RAG) → `references/llm-security.md`
- **Threat modeling, CVSS/CWE/CAPEC/MITRE, lógica de negócio, race conditions, RCA** → `references/threat-modeling.md`
- **OWASP Web Top 10 + escala de severidade + template de achado (rede de segurança final e régua canônica)** → `references/owasp-web.md`
- **Blackbox / DAST no app publicado do próprio usuário (opt-in — só quando pedido ou quando runtime é necessário)** → `references/blackbox-dast.md`
- **Contexto local dos apps do usuário — onde os furos já apareceram (VOLÁTIL, datado, reconfirmar tudo)** → `references/contexto-local.md`

App que mistura stacks é o normal (Flask + React, Supabase + edge functions, tudo no Railway com Graph OAuth). Leia mais de um. **Sempre feche pelo `owasp-web.md`** para não deixar buraco de categoria — e ele é a **régua canônica de severidade** (os outros arquivos referenciam, não redefinem). O **template de achado** é o do §Formatos de saída aqui do SKILL.md — fonte única; os demais arquivos apontam para ele, não recopiam.

## Confirmar antes de reportar

Para cada suspeita, rastreie o caminho do dado do ponto de entrada até o dano. **Confirmado** = uma destas duas coisas:
- **Exploit/repro:** você rodou e observou o dano (input concreto → resultado errado/vazamento). É o padrão-ouro.
- **Rastreio de dados completo no código:** você seguiu o dado da fonte não confiável até o sink perigoso, atravessando os arquivos envolvidos, e não há mitigação no caminho. Vale como Confirmado mesmo sem executar — desde que o rastreio seja completo, não "parece que chega lá".

Se você não alcançou o sink, não descartou as mitigações intermediárias, ou não conseguiu montar o cenário concreto → é **A verificar**, não afirme. Melhor 5 achados sólidos que 20 "pode ser": falso-positivo faz o usuário ignorar o relatório inteiro.

## Cobertura e honestidade (anti-falso-negativo)

Tão importante quanto não inventar achado é não **fingir cobertura**. Toda auditoria termina declarando o que foi e o que NÃO foi coberto:
- Qual superfície você varreu (rotas/arquivos/módulos) e qual ficou de fora nesta rodada.
- Se o codebase não coube no contexto, diga — não feche um resumo que dê a impressão de "auditei tudo".
- Se uma stack não tem arquivo de referência (ex.: Go, mobile nativo), diga que a cobertura ali é genérica (só owasp-web.md), não profunda.
Silêncio sobre cobertura lê-se como "cobri tudo". Um falso-negativo escondido é pior que um falso-positivo: o usuário deploya achando que passou.

## Formatos de saída

**Achado de vulnerabilidade** (ordene por severidade, Crítico primeiro):
```
### [SEVERIDADE] Título curto
**Onde:** arquivo:linha (rota/função)
**Classe:** ex. IDOR — CWE-639 / OWASP A01
**Status:** Confirmado | A verificar
**Cenário:** com input X, usuário Y consegue Z (o ataque concreto)
**Impacto:** confidencialidade/integridade/disponibilidade — o que vaza/quebra/quem afeta
**Hipótese alternativa / contraprova:** o que poderia inocentar, que evidência testei, por que (não) inocenta
**Correção:** trecho ou diff que resolve (+ trade-off se houver mais de um caminho)
**Confiança:** Alta | Média | Baixa — e por quê (rastreio completo? só padrão? falta telemetria de prod?)
```
Separe **confiança no defeito** (rastreei o código) de **confiança na frequência/exploração real** (muitas vezes Média sem executar) — são coisas diferentes, diga as duas quando divergirem.

Feche com: nº de achados por severidade + **cadeia de risco** (achados que se combinam) + qual atacar primeiro. Se nada crítico, diga claramente — resultado válido, o usuário precisa saber que a varredura foi feita de verdade.

**Threat model / RCA / disclosure / cadeia de risco:** ver templates em `references/threat-modeling.md`.

**Exemplo preenchido** (uma rota → achado, o padrão de qualidade esperado):
```
### [ALTO] IDOR na visualização de OS
**Onde:** app.py:1820 — @app.route("/os/<int:os_id>"), def ver_os()
**Classe:** BOLA/IDOR — CWE-639 / OWASP A01 / API1
**Status:** Confirmado (rastreio de dados completo)
**Cenário:** ver_os() chama get_os(os_id) e retorna direto; não compara a empresa
da OS com as empresas do usuário da sessão. Técnico da empresa A troca a URL para
/os/4812 (OS da empresa B) e lê dados de trabalhadores de B (nome, CPF, exames).
Rastreio: os_id (request, não confiável) → get_os() → jsonify(row), sem authz no meio.
**Impacto:** Confidencialidade — vazamento de PII de trabalhadores entre empresas
clientes. Qualquer técnico logado, qualquer OS. Alto (PII, baixo privilégio).
**Hipótese alternativa:** haveria mitigação num before_request? Verifiquei: o guard
só bloqueia não-GET para 'visualizador'; GET de recurso não é filtrado. Não inocenta.
**Correção:**
    def ver_os(os_id):
        os = get_os(os_id)
        if os.empresa_id not in empresas_do_usuario(session["user_id"]):
            abort(403)
        return jsonify(_serialize_os(os))   # + whitelist de campos (BOPLA)
```

## Escala de severidade

Régua canônica única em `references/owasp-web.md` (severidade = impacto × facilidade, calibrada a estes apps) e CVSS formal em `references/threat-modeling.md`. **Não reproduza a escala aqui** — consulte lá para não haver duas versões divergentes.

## Contexto local (opcional — você cria)

Auditorias ficam mais rápidas quando a skill sabe *onde os furos já apareceram nos seus apps*. Esse mapa perecível — datado, com número de linha, commit, "corrigido em DD/MM" — **não** deve morar nas referências de método (que são atemporais). Crie um arquivo `references/contexto-local.md` (git-ignored, se contiver detalhe sensível) com, por app: stack, superfícies de risco, integrações, e o histórico de "onde já mordeu".

Regras de uso: são **pontos de partida, NÃO garantias de que estão resolvidos.** A regra nº 1 desta skill (questione toda premissa) vale contra este próprio arquivo — o código muda, mitigação de ontem some. Leia-o no início de uma auditoria dos seus apps, **reconfirme cada item no código de hoje** antes de tratá-lo como fato, e se ele contradiz o código atual, o código vence e o arquivo está velho — atualize-o. Um template vazio acompanha este repo em `references/contexto-local.example.md`.
