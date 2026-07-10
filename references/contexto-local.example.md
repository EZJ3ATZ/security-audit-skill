# Contexto local dos seus apps — TEMPLATE (VOLÁTIL)

> ⚠️ **Este arquivo apodrece de propósito.** Cada item é uma *pergunta a confirmar no
> código de hoje*, não um fato. A regra nº 1 da skill (questione toda premissa) vale
> contra ele. Se algo aqui contradiz o código atual, o código vence — atualize a data.
>
> Copie para `contexto-local.md` e preencha com os SEUS sistemas. Se contiver detalhe
> sensível (URLs de produção, nomes internos, vulnerabilidades ainda abertas),
> **mantenha `contexto-local.md` fora do controle de versão** (`.gitignore`).

Última revisão: **AAAA-MM-DD**

## <Nome do app 1> (stack, ex.: Flask + Postgres)
- **O que protege:** <PII, credenciais, ações de valor>
- **Superfícies de risco:** <rotas de auth, uploads, endpoints admin, integrações>
- **Onde já mordeu (datado):** <ex.: IDOR em /recurso/<id> — corrigido em DD/MM, reconfirmar>
- **Integrações externas:** <APIs de e-mail, provedores de dados, CRM, pagamentos — escopo e onde vivem os segredos>

## <Nome do app 2> (stack, ex.: Supabase + React)
- **RLS:** toda tabela tem `ENABLE ROW LEVEL SECURITY` + policy real (não `USING(true)`)?
- **Edge/server functions:** cada uma valida o JWT do chamador e autoriza por recurso no servidor?
- **`service_role`:** nunca no front/bundle/log?
- **Onde já mordeu (datado):** <...>

## Deploy / CI-CD
- <ex.: push no `main` = deploy em produção sem gate de review — tratar o pipeline como superfície de ataque>
- <escopo dos tokens de deploy, `.env`/segredos fora do push>
