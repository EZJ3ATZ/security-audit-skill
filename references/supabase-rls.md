# Supabase / RLS / edge functions — classes de falha

O modelo do Supabase é diferente de um back tradicional: o cliente fala **direto** com o Postgres via a chave anon, e a única coisa entre um atacante e a tabela inteira é o **RLS (Row Level Security)**. Isso muda onde ficam os furos. As duas fontes de dor: (1) RLS mal configurado, (2) código de servidor (edge/server functions, RPC) que confia no frontend.

## 1. RLS: está ligado e realmente protege?

**Toda tabela exposta ao cliente precisa de RLS habilitado E políticas corretas.** RLS desligado numa tabela acessível pela anon key = qualquer um lê/escreve tudo.

Verifique (via migrations, SQL, ou dashboard):
- `ALTER TABLE ... ENABLE ROW LEVEL SECURITY;` existe para cada tabela? Tabela sem isso e com grant para `anon`/`authenticated` está aberta.
- As políticas (`CREATE POLICY`) realmente restringem? Uma política `USING (true)` "liga" o RLS mas não protege nada — libera geral.
- Política de `SELECT` cobre, mas e `INSERT`/`UPDATE`/`DELETE`? Cada comando precisa da sua. Faltando um → escrita/remoção livre.
- A política amarra a linha ao usuário certo? Padrão: `USING (auth.uid() = user_id)` ou via tabela de membership. Se compara com coluna que o próprio cliente pode setar, não vale.

**Grep no repo:** `ENABLE ROW LEVEL SECURITY`, `CREATE POLICY`, `USING (`, `WITH CHECK (`, `auth.uid()`, `GRANT`, `to anon`, `to authenticated`

**Mas o git mente sobre RLS.** O grep acima só vê o que está versionado — e policy/grant mudam no dashboard sem virar migration. O estado REAL de produção pode divergir do repo (RLS ligada numa migration e depois desligada à mão, grant para `anon` criado no console, policy `USING (true)` de debug esquecida). Essa **deriva** é a única classe que a leitura do código não pega — e onde um modelo forte não ajuda, porque não é uma questão de raciocínio, é de fato de produção ausente do contexto. Rode o probe contra o banco real:
- `py tools/schema_drift.py --dsn postgres://... --expect expect.json` (só-leitura): lista tabelas com RLS off, grants para `anon`, policies com `USING/WITH CHECK = true`, e faz o diff contra o que você declarou que o código assume (`rls_required`, `no_anon_grants`, `no_permissive_policies`, whitelist de colunas por tabela). Sem `--expect` = inventário + heurística; com = diff código×realidade.
- É o par de banco do `scan.py` (que cobre o working tree). Degrada honesto: SQLite → pula a camada RLS (não tem); sem driver psycopg → SKIPPED explícito.
- Foi ponto cego real no app de CS (RLS/policy fora do git). Confirme cada achado no dashboard/SQL antes de reportar — o probe é triagem.
Cruze: para cada `create table`, existe `enable row level security` + políticas para os 4 comandos?

## 2. Chaves: anon vs service_role

- **anon key** pode aparecer no frontend (é o desenho do Supabase) — desde que o RLS proteja. Se o RLS estiver frouxo, a anon key vira chave-mestra.
- **service_role key BYPASSA todo o RLS.** Ela **nunca** pode estar no frontend, no bundle, em `VITE_`/`NEXT_PUBLIC_`, num repo público, ou num log. Se vazar, é game over: acesso total ao banco.

**Grep:** `service_role`, `SUPABASE_SERVICE`, `SERVICE_ROLE_KEY`, `eyJ` (prefixo de JWT — chave exposta), `VITE_SUPABASE`, `NEXT_PUBLIC_SUPABASE`
Confirme: service_role só em variável de ambiente de servidor (edge function, back), nunca chega ao cliente.

## 3. Edge / server functions — auth no servidor (o furo conhecido do app de CS)

Este é o ponto que já mordeu antes: **função de servidor que executa ação privilegiada sem checar quem chamou.** RLS do banco pode estar perfeito, mas se uma edge function usa service_role (bypassa RLS) e não valida o chamador, qualquer um invoca e ela faz o trabalho sujo — ler e-mails internos, mandar e-mail "como a empresa", puxar dados de outra conta.

Para **cada** edge function / RPC / server action, cheque:
- **Autentica o chamador?** Lê e valida o JWT do usuário (`Authorization` header) no início da função? Ou aceita qualquer request?
- **Autoriza?** Depois de saber quem é, confirma que essa pessoa pode fazer *essa* ação sobre *esse* recurso? Não basta "tem token".
- **Confia em algo do body que deveria vir do servidor?** Ex: a função recebe `empresa_id`/`user_id` no body e age sobre ele sem checar se o chamador tem direito → IDOR. O id do dono deve sair do JWT validado, não do body.
- **Usa service_role para operação que o usuário poderia fazer com a própria sessão?** Se sim, ela está pulando o RLS de propósito — então a checagem manual de authz dentro da função é a *única* proteção. Ela existe?

**Grep:** `Deno.serve`, `supabase.functions`, `createClient`, `SERVICE_ROLE`, `req.headers`, `Authorization`, `getUser(`, `auth.getUser`, `verify`, `.rpc(`
Sinal de perigo: função com `service_role` + sem `getUser`/validação de JWT no topo.

**Correção (padrão):**
```ts
const authHeader = req.headers.get("Authorization");
const { data: { user }, error } = await supabaseClient.auth.getUser(
  authHeader?.replace("Bearer ", "")
);
if (error || !user) return new Response("Unauthorized", { status: 401 });
// e DEPOIS: confirmar que `user` pode agir sobre o recurso pedido
```

## 4. Postgres functions com SECURITY DEFINER

`CREATE FUNCTION ... SECURITY DEFINER` roda com os privilégios de quem criou (geralmente admin), ignorando o RLS de quem chama. Útil, mas se a função não valida os argumentos, vira porta dos fundos.

**Grep:** `SECURITY DEFINER`, `search_path`
- Toda `SECURITY DEFINER` deve fixar `SET search_path = ...` (senão, ataque via search_path).
- Deve validar internamente o que o chamador pode acessar — não confiar nos argumentos cegamente.

## 5. Storage buckets

**Grep:** `storage.from(`, `createBucket`, `public: true`, políticas de storage
- Bucket `public: true` expõe todo arquivo por URL adivinhável. PII (documentos, laudos, exames) em bucket público = vazamento.
- Buckets privados precisam de políticas de storage (mesma lógica de RLS) para SELECT/INSERT. Confirme que existem.

## 6. Client-side authorization (não confie no front)

No Supabase é tentador esconder um botão no React e achar que protegeu. Não protegeu: o cliente fala direto com o banco. **Toda** regra de acesso tem que viver no RLS ou na função de servidor. Se a única coisa que impede o técnico de ver dados de admin é a UI não mostrar, é furo.

## 7. CVE/incidentes recentes (⏱ vintage jul/2026 — confira se saiu mais novo)

- **CVE-2025-48757 — RLS desligado por padrão (o furo que mais atinge apps Lovable).** Tabela criada por SQL/Table Editor nasce **sem RLS**; sem o toggle "Enable RLS on new tables", quem tem a anon key lê/escreve tudo. Uma análise (mai/2025) achou **10,3% dos apps Lovable** com tabelas legíveis por qualquer um com a anon key. **O app de CS / CRM nasceu no Lovable → é a primeira coisa a conferir:** para CADA tabela, `ENABLE ROW LEVEL SECURITY` está ligado **E** há política real (não `USING(true)`) para os 4 comandos?
- **Vazamento de `service_role` por edge function** — caminhos comuns: logar o `env` no boot, devolver mensagem de erro com detalhe de conexão, ou expor o **source map** da function. ~83% dos incidentes Supabase são má-configuração de RLS; o resto costuma ser chave vazada por um desses caminhos. Confirme: nenhuma function loga env nem devolve `str(e)` cru; source maps não publicados.

## Prioridade ao auditar os apps do usuário

1. Toda edge/server function do app de CS / CRM: valida JWT + autoriza no servidor? (furo histórico)
2. service_role não vaza para o front/bundle/log.
3. RLS ligado + políticas reais (não `USING(true)`) em toda tabela com dado de cliente/PII.
4. Buckets com PII não são públicos.
