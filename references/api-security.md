# API security — OWASP API Security Top 10 (2023)

APIs falham diferente de páginas web. O atacante não usa a UI — fala direto com o endpoint, com qualquer corpo, em qualquer ordem, na velocidade que quiser. As três primeiras da lista (BOLA, Broken Auth, BOPLA) são a maioria dos incidentes reais. O CRM do usuário é **API-first** — este arquivo é prioritário nele.

## API1 — BOLA (Broken Object Level Authorization) = IDOR

A campeã. Endpoint recebe um id de objeto e devolve/altera o objeto **sem checar se o chamador é dono dele**. É o mesmo que IDOR (ver flask-python.md §authz), mas na API é a regra, não a exceção — todo endpoint com `/<id>` é suspeito.

**Grep:** `/<int:`, `/:id`, `params.id`, `req.params`, `req.query`, `where id =`, `.eq('id'`, `findById`, `get_or_404`
**Teste concreto:** logado como usuário A, troque o id no request para o de B. Voltou dado de B? BOLA confirmado.
**Correção:** toda leitura/escrita por id valida posse — `WHERE id = ? AND owner = <do token>`, ou RLS que amarre `auth.uid()`. O dono sai do token/sessão, nunca do request.

## API2 — Broken Authentication

Auth do endpoint fraca ou ausente. Ver auth-tokens.md (JWT, sessão, brute force). Específico de API:
- Endpoint que aceita request sem token e ainda responde dado sensível.
- Token em query string (`?token=`) → vaza em log/histórico/referer.
- Sem rate limit em login/refresh → brute force e credential stuffing à vontade.

**Grep:** `Authorization`, `verify`, `getUser`, `@login_required` (ausente onde deveria), `?token=`, `api_key` em query.

## API3 — BOPLA (Broken Object Property Level Authorization)

Duas faces:
- **Mass assignment:** o endpoint aceita propriedades que o usuário não deveria setar (`role`, `is_admin`, `empresa_id`, `reservado_por_plano`, `data_resultado`). Ver flask-python.md §mass assignment. **Grep:** `**request.json`, `.update(request`, `{...req.body}`, `Object.assign`, `spread` do body no update.
- **Excessive data exposure:** o endpoint devolve o objeto **inteiro** e o front "esconde" campos sensíveis. O atacante lê no network tab. **Grep:** `SELECT *`, `.select('*')`, `return jsonify(row)`, serializer sem whitelist de campos.
**Correção:** whitelist explícita nos dois sentidos — campos que entram (aceitos no write) e campos que saem (serializados no read). Nunca `SELECT *` para o cliente; nunca `**body` no update.

## API4 — Unrestricted Resource Consumption

Sem limite de custo → DoS e denial-of-wallet. Endpoint que gera DOCX, roda sync, chama LLM, ou faz query pesada sem rate limit / paginação / timeout. Também: upload sem limite de tamanho.
**Grep:** ausência de `limit`/`LIMIT`/paginação em list endpoints; `sync`, `export`, geração de relatório sem throttle.
**Correção:** rate limit por usuário, paginação obrigatória, teto de tamanho, timeout.

## API5 — Broken Function Level Authorization (BFLA)

O usuário chama uma **função** que não é do papel dele — o endpoint de admin que a UI só mostra pro admin, mas o back não checa role. Diferente de BOLA (que é sobre o *objeto*): BFLA é sobre a *ação/rota*.
**Teste:** logado como técnico, chame a rota de admin direto (`POST /demandas/re-extrair`, baixa em lote, `/empresas/<id>/excluir-fantasma`). Executou? BFLA.
**Correção:** checagem de role **no servidor** em toda rota privilegiada. Esconder na UI não conta (regra nº 9 do CLAUDE.md vira teste de segurança).

## API6 — Unrestricted Access to Sensitive Business Flows

Fluxo de negócio legítimo abusado por automação: repetir sem limite uma ação que deveria ser rara (reservar todos os amostradores, disparar N e-mails, criar OS em massa). Ver threat-modeling.md §lógica de negócio.
**Correção:** detectar/limitar uso automatizado do fluxo (rate, captcha em ponto sensível, checagem de padrão).

## API7 — SSRF

Endpoint que faz request de saída com URL/host influenciado pelo usuário. Ver flask-python.md §SSRF. Crítico com Graph/SOC/CRM e metadata de cloud.

## API8 — Security Misconfiguration

CORS `*`, verbo HTTP não tratado, header de segurança ausente, stack trace na resposta, endpoint de debug aberto. Ver owasp-web.md §misconfiguration e cloud-supply-chain.md.

## API9 — Improper Inventory Management (shadow / zombie APIs)

Endpoint esquecido, versão antiga (`/v1/` ainda no ar), rota de debug em produção, host de staging exposto. O que você esqueceu que existe é o que não está protegido.
**No ERP:** os `/controle/graph/debug_*`, `sync_mini`, `sync_error` — são debug; estão fechados para admin em produção? Documentados? Um endpoint não inventariado não é auditado — e o atacante encontra por fuzzing.
**Grep:** rotas com `debug`, `test`, `_old`, `v1`/`v2`, `internal`, `admin` sem guard.

## API10 — Unsafe Consumption of APIs

Você confia cegamente na resposta de uma API de terceiro (Graph, SOC, CRM, laboratório). Se a resposta dela for maliciosa/malformada (ou o terceiro for comprometido), o dado entra no seu sistema sem validação → injection de segunda ordem, dado envenenado.
**Correção:** valide/sanitize a resposta de terceiro como se fosse input do usuário — especialmente antes de gravar no banco ou alimentar LLM. Ver llm-security.md (texto de e-mail via Graph é input não confiável).

## Prioridade ao auditar a API do usuário (CRM API-first / app de CS)

1. **BOLA (API1)** em todo endpoint com id — troque o id e veja se vaza.
2. **BFLA (API5)** em toda rota de admin/manutenção — chame como usuário comum.
3. **BOPLA (API3)** — mass assignment no write, `SELECT *` no read.
4. **Auth (API2)** — endpoint sensível sem token responde?
5. **Inventory (API9)** — endpoints de debug/versão antiga fechados?
