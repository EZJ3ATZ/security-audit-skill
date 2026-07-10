# Threat modeling, classificação de risco, lógica de negócio, race conditions e RCA

Este é o arquivo de método transversal — como estruturar a análise, nomear a falha com padrão reconhecido, medir severidade, achar o erro que nenhuma ferramenta pega (lógica de negócio, concorrência) e chegar à causa-raiz de um bug. Os templates de saída ficam no fim.

## Threat modeling — mapear antes de caçar

Não varra às cegas. Primeiro monte o mapa; ele diz onde olhar e o que seria pior.

1. **O que o sistema faz e o que protege** — que dados (PII de trabalhador, e-mail interno, credencial), que ações têm valor/risco (concluir OS, dar baixa, mandar e-mail como a empresa, mexer em faturamento).
2. **Atores e papéis** — anônimo, técnico, admin, visualizador, integração (integrações externas (API de e-mail, provedores de dados, CRM)), atacante externo, insider. Para cada um: o que *pode* e o que *não deveria* poder.
3. **Fronteiras de confiança** — onde o dado cruza de "não confiável" para "confiável": request→servidor, front→edge function, e-mail de terceiro→pipeline, internet→banco. É na fronteira que a validação tem que existir.
4. **Fluxo de dados** — siga o dado sensível da entrada ao repouso. Cada salto é um ponto de análise.
5. **STRIDE por elemento** — para cada processo/fluxo/store, pergunte as 6:

| STRIDE | Pergunta | Propriedade violada |
|--------|----------|---------------------|
| **S**poofing | dá para me passar por outro? | Autenticação |
| **T**ampering | dá para alterar dado/parâmetro? | Integridade |
| **R**epudiation | dá para negar que fiz? (sem log) | Não-repúdio |
| **I**nfo disclosure | dá para ver o que não é meu? | Confidencialidade |
| **D**enial of service | dá para derrubar/encarecer? | Disponibilidade |
| **E**levation of privilege | dá para virar admin? | Autorização |

Registre cada ameaça plausível como hipótese e leve para a fase de confirmação.

## Nomear com padrão — CWE, CAPEC, MITRE

Cada achado ganha o rótulo reconhecido. Dá precisão e conecta a correção conhecida.

- **CWE** — *tipo* de fraqueza no código. Ex.: CWE-89 SQLi, CWE-79 XSS, CWE-639 IDOR/authz por chave, CWE-22 path traversal, CWE-352 CSRF, CWE-798 credencial hardcoded, CWE-502 desserialização insegura, CWE-287 auth falha, CWE-918 SSRF, CWE-362 race condition, CWE-269 privilégio mal gerido.
- **CAPEC** — *padrão de ataque* (como se explora). Útil para descrever o cenário.
- **OWASP** — categoria web (A01–A10, ver owasp-web.md) / LLM Top 10 (ver llm-security.md).
- **MITRE ATT&CK** — TTPs de adversário; use em análise de incidente/pós-exploração, não em revisão de código de unidade.

## CVSS — severidade calibrada

CVSS v3.1 dá um número comparável, mas **o dono da nota é o impacto no contexto deste app**, não a tabela. Métricas base:

- **AV** vetor: Network / Adjacent / Local / Physical
- **AC** complexidade: Low / High
- **PR** privilégio exigido: None / Low / High
- **UI** interação do usuário: None / Required
- **S** escopo: Unchanged / Changed (rompe a fronteira de segurança?)
- **C/I/A** impacto em confidencialidade/integridade/disponibilidade: None / Low / High

Faixas: 0.0 nenhum · 0.1–3.9 baixo · 4.0–6.9 médio · 7.0–8.9 alto · 9.0–10.0 crítico.

Para a escala prática já calibrada aos apps do usuário (o que é Crítico/Alto/Médio/Baixo *aqui*), use a de **owasp-web.md** — ela é a régua final. CVSS entra quando você quer o número formal num relatório.

## Erros de lógica de negócio — o que ferramenta não pega

Nenhum scanner acha isto, porque o código "funciona" — ele só permite algo que a regra do negócio não deveria. É onde mora o furo mais caro. Perguntas:

- **Pular etapa** — dá para chegar ao passo 3 sem o 1 e 2? (recurso liberado antes do pagamento/aprovação; OS concluída sem medição; baixa sem laboratório.)
- **Repetir ação** — o que acontece se eu mando o mesmo pedido 2×/10×? (desconto/reserva/baixa aplicada em dobro; amostrador reservado por dois planos.)
- **Valores de borda** — negativo, zero, gigante, vazio, data no passado/futuro. (quantidade negativa, dia de medição = 0, prazo invertido.)
- **Ordem inesperada** — cancelar depois de concluir, editar depois de travar, desvincular no meio.
- **Confiar no cliente** — o front esconde o botão / desabilita o campo, mas o endpoint aceita mesmo assim. (Regra 9 do CLAUDE.md vira teste de segurança: ferramenta de manutenção "só admin" está protegida **no servidor** ou só sumiu da UI?)
- **Contornar limite** — o teto/quota é checado onde? dá para burlar por outra rota?

No app Flask isto é central: reserva de amostrador, conclusão de OS, baixa química, plano confirmado. Cada transição de estado é uma regra — teste pular, repetir e inverter cada uma.

## Race conditions / concorrência (CWE-362)

Dois pedidos ao mesmo tempo veem o mesmo estado e agem — e o resultado viola a regra. **TOCTOU** (Time-of-Check to Time-of-Use): você checa "disponível?" e só depois "reserva"; entre os dois, outro pedido reservou. Ambos passam.

**Onde procurar:** check-then-act sem atomicidade — `if disponivel: reservar()`, saldo/estoque/contador lido e depois escrito, "reservar amostrador se livre", baixa dupla, geração de número sequencial.

**Grep:** `if.*disponivel`, `count`, `SELECT.*then.*UPDATE`, `get.*set`, `+= 1`, `reservado`, sem `with_for_update`/`SELECT ... FOR UPDATE`/lock/`UNIQUE`/transação.

**Correção:**
- **Atomicidade no banco:** transação + `SELECT ... FOR UPDATE` (trava a linha), ou um `UPDATE ... WHERE status='disponivel'` condicional e confira `rowcount` (só um ganha).
- **Constraint `UNIQUE`** para impedir o estado duplicado na origem (ex.: um amostrador só pode ter uma reserva ativa).
- **Idempotência:** chave de idempotência para o mesmo pedido repetido não aplicar duas vezes.

Padrão a caçar: um dry-run/checagem seguido de um write "incondicional" — confirme que a decisão final é **atômica no banco**, não um check-then-act na linguagem de aplicação entre dois requests concorrentes (o segundo sobrescreve o primeiro — TOCTOU / CWE-362).

## Root Cause Analysis (debug avançado)

Mesma disciplina, alvo diferente: em vez de "como quebro?", "por que quebrou?". Sintoma ≠ causa.

1. **Comportamento esperado × observado** — defina os dois com precisão. "Às vezes some" não é um bug; "com 2 requests simultâneos na mesma OS, uma reserva some" é.
2. **Reprodução (ou as condições dela)** — o que dispara? intermitente costuma ser **concorrência, estado compartilhado, ordem, cache, ou dado de borda**. Se não reproduz, reduza a hipótese até um caso mínimo.
3. **Hipóteses de causa** — liste as plausíveis (race, estado global, timezone/`data_*`, `None`/vazio, encoding/`\n`, watermark/sync que reverte, off-by-one). Não pare na primeira.
4. **Prove qual é** — log no ponto certo, leitura do caminho de código, comparação de estado antes/depois. Separe fato de hipótese aqui também.
5. **Causa-raiz, não sintoma** — se o fix é um `try/except` que engole, você tratou o sintoma. A causa é *por que* chegou ali.
6. **Correção + regressão** — o fix resolve a raiz e não reabre outro (o histórico do app Flask tem casos: watermark de lab que revertia status, parser sem `/g` que trocava só a 1ª vírgula — bugs de causa sutil com sintoma amplo).

Os "5 porquês" cabem bem: pergunte "por quê?" até a resposta ser um defeito acionável, não outro sintoma.

## Chaining — nunca trate achado como ilha

O impacto composto costuma ser maior que a soma. Depois de listar os achados, pergunte sempre: **existe combinação entre eles que aumenta o impacto?** Um vazamento de estrutura no erro (Baixo) + um gate de autorização fail-open (Médio) = um caminho de recon→escalonamento (Alto) que nenhum dos dois abre sozinho. Monte a cadeia explícita:

```
pré-condição → elo 1 → elo 2 → consequência
(ex.: 1 conta de baixo privilégio → erro vaza schema → acha endpoint não-listado → ação destrutiva)
```

Reporte a cadeia junto do resumo — e a severidade da cadeia pode ser maior que a de qualquer elo isolado.

## Árvore de risco — como um problema pequeno vira grande

Para explicar impacto (e priorizar), estruture:
```
Objetivo do atacante
 ├─ Pré-condições (o que ele precisa já ter)
 ├─ Dependências (o que mais tem de ser verdade)
 ├─ Fragilidades exploradas (os achados)
 └─ Consequências (o dano concreto no negócio)
```
Serve tanto para segurança quanto para confiabilidade: um bug de concorrência é a "fragilidade", o uso concorrente normal é a "pré-condição", o double-booking é a "consequência" — sem atacante nenhum.

## Grafo do sistema — checklist de superfície (não deixar camada fora)

Ao mapear a superfície (passo 2 da metodologia), percorra as camadas e marque risco conhecido/potencial em cada uma — assim nenhuma passa batida:

`frontend → backend → APIs → banco → storage → cache → fila/mensageria → autenticação → autorização → logs → monitoramento → backups → integrações externas → infra/deploy`

Nem todo app tem todas (o app Flask não tem fila; o app Supabase não tem cache próprio) — diga qual não se aplica e siga. O valor é a varredura sistemática, não preencher tudo.

---

## Templates de saída

### Achado de vulnerabilidade
Fonte única: **§Formatos de saída do SKILL.md**. Não recopiado aqui para evitar
divergência entre cópias — use o de lá. Abaixo, só os templates específicos deste
arquivo (threat model, RCA, disclosure), que o SKILL.md não carrega.

### Threat model (resumo de sistema)
```
## Threat model — <sistema> (<data>)
**Ativos:** o que protege (dados, ações de valor)
**Atores:** papéis e o que cada um pode/não deveria
**Fronteiras de confiança:** onde o não confiável vira confiável
**Ameaças (STRIDE):** tabela — ameaça | elemento | STRIDE | severidade | mitigação atual | gap
**Prioridade:** o que atacar primeiro e por quê
```

### Root Cause Analysis
```
## RCA — <bug> (<data>)
**Sintoma:** o que se observa (com condições)
**Impacto:** quem/o quê é afetado, frequência
**Linha do tempo:** o que aconteceu, na ordem
**Hipóteses consideradas:** cada uma + por que caiu/ficou
**Causa-raiz:** o defeito real (não o sintoma)
**Correção:** o fix + por que ataca a raiz
**Prevenção:** teste/guarda que impede reincidência
```

### Nota de disclosure responsável
```
## Disclosure — <título>
**Resumo:** 1 parágrafo, sem PoC explorável em excesso
**Severidade:** CVSS vetor + faixa
**Afetado:** componente/versão
**Impacto:** o que um atacante consegue
**Correção/mitigação:** o que fazer
**Créditos/linha do tempo:** descoberta → correção
```
Disclosure é sobre código do próprio usuário / correção interna. Nada de instrução para atacar terceiro.

## Fechamento de toda auditoria

Resumo com **contagem por severidade** e **o que atacar primeiro**. Se nada crítico, diga com todas as letras — é resultado válido e o usuário precisa saber que a varredura rodou de verdade, não que você desistiu. Melhor 5 achados sólidos que 20 "pode ser": a regra anti-falso-positivo de owasp-web.md vale para o relatório inteiro.
