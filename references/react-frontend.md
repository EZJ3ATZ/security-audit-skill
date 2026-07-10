# React / TanStack / front — classes de falha

Regra de ouro do front: **tudo que vai para o navegador é público e não confiável.** O bundle é lido pelo atacante, o state é editável, as chamadas de API são forjáveis. Segurança de verdade mora no servidor; no front você evita vazar segredo e evita XSS. Nunca trate o front como fronteira de autorização.

## XSS (Cross-Site Scripting)

React escapa por padrão — o furo aparece quando você desliga isso.

**Grep:** `dangerouslySetInnerHTML`, `innerHTML`, `document.write`, `eval(`, `new Function(`, `href={`, `src={`, `<a href={user`, `insertAdjacentHTML`
- `dangerouslySetInnerHTML={{__html: userData}}` = XSS armazenado se `userData` vem do banco/usuário. Se precisa renderizar HTML, sanitize com DOMPurify antes.
- `href`/`src` com valor do usuário → `javascript:` URI executa script. Valide o esquema (só `http`/`https`/`mailto`).
- Markdown/rich text renderizado sem sanitização.

## Secrets no bundle

Tudo que o build empacota vai para o cliente. Variáveis `VITE_*`, `NEXT_PUBLIC_*`, `REACT_APP_*` **estão no bundle** — visíveis para qualquer um que abrir o DevTools.

**Grep:** `VITE_`, `NEXT_PUBLIC_`, `REACT_APP_`, `import.meta.env`, `process.env`, `apiKey`, `secret`, `token`, `Bearer`, `sk-`, `service_role`, `eyJ`
- Chave de API privada, service_role do Supabase, secret do Stripe, credencial de integração → **nunca** em env do front. Só a anon key do Supabase (que depende de RLS) e chaves *publicáveis* podem ir.
- Endpoint/credencial de admin hardcoded no componente.

Se achar segredo sensível no front: a correção não é ofuscar — é **mover a operação para o servidor** (edge function / back) e o front só chamar via API autenticada.

## Autorização confiada ao cliente

O erro conceitual mais caro no front. Esconder um botão, um menu de admin, ou uma rota (`<Route>` protegida só no client) **não é segurança** — o atacante chama a API direto.

**Grep:** `isAdmin`, `role ===`, `if (user.role`, `hasPermission`, rotas protegidas, `useAuth`
- Toda checagem `if (isAdmin)` no front é só UX. A API/RLS por trás precisa ter a mesma checagem no servidor. Verifique que existe do outro lado.
- Dados sensíveis que o front "esconde" mas a API retorna para todos → vazam via network tab. O servidor não deve mandar o que o usuário não pode ver.

## Chamadas de API sem/ com auth errada

**Grep:** `fetch(`, `axios`, `useQuery`, `useMutation`, `queryFn`, `headers:`, `Authorization`
- Chamada a endpoint sensível sem enviar token → ou o endpoint está aberto (furo no back), ou vai falhar. Rastreie para confirmar que o back exige auth.
- Token guardado em `localStorage`/`sessionStorage` é acessível por qualquer XSS. `httpOnly` cookie é mais seguro contra roubo de token. Avalie o trade-off (localStorage é comum, mas some com XSS o token todo).

**Grep:** `localStorage.setItem`, `sessionStorage`, `document.cookie`

## Dados sensíveis vazando pelo cliente

- PII em logs de console (`console.log(user)`, `console.log(response)`) que sobra em produção.
- State/cache do TanStack Query com dados de outro usuário persistidos (ex: em `localStorage` persister) sem limpar no logout.
- Comentários/TODOs com credencial ou lógica interna no código enviado.

**Grep:** `console.log`, `console.debug`, `persistQueryClient`, `persister`

## CORS e postMessage

- Backend com `Access-Control-Allow-Origin: *` + credenciais → qualquer site lê respostas autenticadas. Confirme origem restrita.
- `window.addEventListener("message")` sem checar `event.origin` → qualquer página injeta dados. **Grep:** `addEventListener("message"`, `postMessage`, `Allow-Origin`

## Dependências

`npm audit` para vulnerabilidade conhecida em dependência. Pacote abandonado/typosquat no `package.json`. Não é o foco principal, mas vale um `npm audit` ao final.

## Se o front usar Next.js: CVE-2025-29927 (⏱ vintage jul/2026)

Se a autorização depende de **middleware do Next.js**, cheque a versão: **CVE-2025-29927** (crítica) — o header interno `x-middleware-subrequest`, se forjado no request, faz o Next **pular o middleware inteiro**, incluindo auth/authz. O atacante manda o header e alcança rota protegida sem passar pelo gate. Fix: Next ≥ 15.2.3 / 14.2.25 / 13.5.9 / 12.3.5, ou tirar/limpar o header na borda (proxy/CDN). ⚠ Reforça a regra de ouro: **authz no middleware do front não é fronteira** — o RLS/servidor tem que barrar de novo. (O app Supabase via Lovable costuma ser Vite+React, não Next — confirme o build antes de gastar tempo aqui.)

## Prioridade ao auditar o front do usuário (um app Supabase/React — React/TanStack)

1. Nenhum segredo sensível no bundle (service_role, chaves de integração). Só anon key.
2. Toda checagem de role/permissão no front tem equivalente no servidor (RLS/edge function).
3. Sem `dangerouslySetInnerHTML` com dado de usuário sem sanitizar.
4. Token não some junto num XSS de forma que dê acesso total (avaliar localStorage vs cookie).
