# Flask / Python / Postgres — classes de falha

Ordem sugerida: comece por injection e authz (é onde estão os furos que mais doem), depois o resto.

## SQL injection

O clássico e ainda o mais perigoso. Procure query construída por concatenação/f-string/`%` com dado do usuário.

**Grep:** `execute\(.*%`, `execute\(f"`, `execute\(.*\+`, `\.format\(.*\)`, `text\(f"`, `cursor\.execute`
Também: SQLAlchemy `text()` com interpolação, `filter(text(...))`, ORDER BY dinâmico (nome de coluna vindo do usuário — não parametrizável, precisa whitelist).

**Ruim:**
```python
cur.execute(f"SELECT * FROM demandas WHERE empresa_id = {empresa_id}")
cur.execute("... WHERE nome = '%s'" % nome)
```
**Correção — sempre parâmetro, nunca string:**
```python
cur.execute("SELECT * FROM demandas WHERE empresa_id = %s", (empresa_id,))
```
Para nome de coluna/tabela dinâmico (não dá para parametrizar): valide contra uma lista fixa de nomes permitidos antes de interpolar.

## Autenticação e autorização (IDOR / broken access control)

O furo mais comum em app de negócio: o usuário está logado, mas acessa recurso que não é dele. Autenticação (quem é) ≠ autorização (o que pode).

**Procure em cada rota que recebe um id:** o código checa se aquele recurso pertence ao usuário/empresa dele? Ou confia que "se está logado, pode ver"?

**Grep:** `<int:`, `<id>`, `request.args.get`, `request.json`, `@app.route`, `before_request`, `session[`, `current_user`, `role`, `is_admin`

**Ruim (IDOR):**
```python
@app.route("/os/<int:os_id>")
def ver_os(os_id):
    return get_os(os_id)   # qualquer logado vê qualquer OS
```
**Correção — amarrar o recurso ao dono:**
```python
def ver_os(os_id):
    os = get_os(os_id)
    if os.empresa_id not in empresas_do_usuario(session["user_id"]):
        abort(403)
    return os
```

**Checagens específicas do um app Flask/Postgres:**
- O guard `@app.before_request` que bloqueia não-GET para `visualizador` cobre **todos** os blueprints? Um blueprint registrado sem passar pelo guard fura tudo. Confirme que o guard está no app, não em cada blueprint.
- Ferramentas de manutenção/admin (Diagnóstico, Reprocessar, Verificar fantasmas, baixa em lote) exigem role admin **no servidor**? Esconder no frontend não protege — o endpoint tem que checar.
- Autorização é só por role, ou também por recurso? Role `tecnico` que vê OS de qualquer empresa ainda é IDOR mesmo com role certo.

## Server-Side Request Forgery (SSRF)

Onde o servidor faz uma requisição de saída (requests, urllib, httpx) com URL/host que o usuário influencia. Perigoso com integrações (integrações externas) e com metadata de cloud.

**Grep:** `requests.get(`, `requests.post(`, `httpx`, `urlopen`, `urllib`, `fetch`, `session.get(`
Veja se algum pedaço da URL vem de input (id de caixa, endpoint, hostname, redirect).

**Risco:** usuário faz o servidor bater em `http://169.254.169.254/` (metadata), rede interna, ou caixa de e-mail que não deveria. Com Graph app-only lendo qualquer caixa do tenant, um endpoint que aceita o e-mail-alvo do usuário sem validar = leitura indevida.

**Correção:** whitelist de hosts/destinos permitidos; nunca deixe o usuário passar URL/host livre. Para Graph, o e-mail/caixa consultado deve ser derivado da sessão do usuário, não do request.

## Template injection (SSTI) e XSS via Jinja

**Grep:** `render_template_string`, `|safe`, `Markup(`, `{% autoescape false %}`
`render_template_string` com input do usuário = SSTI (leva a RCE). `|safe`/`Markup` com dado do usuário = XSS. Jinja autoescapa por padrão — desligar isso ou marcar safe reintroduz XSS.

**Correção:** nunca renderize template a partir de string com input; nunca marque `|safe` conteúdo que veio do usuário.

## Secrets e configuração

**Grep:** `SECRET`, `PASSWORD`, `API_KEY`, `token =`, `password =`, `sk-`, `Bearer `, chaves hardcoded, `.env` commitado, `app.run(debug=True)`
- Chave/senha/token hardcoded no código → mover para env var.
- `debug=True` em produção → RCE via Werkzeug debugger. Desligar.
- `SECRET_KEY` fixo/previsível → forja de sessão. Deve ser aleatório e vir do ambiente.
- Segredo aparecendo em log (print/logging de request completo, de headers, de tokens).

## Mass assignment / whitelist de campos

Endpoint PUT/POST que joga o JSON inteiro no update, deixando o usuário setar campo que não deveria (ex: `role`, `is_admin`, `empresa_id`, `data_resultado`).

**Grep:** `.update(request.json`, `**request.json`, `**data`, `for k, v in request.json`
**Correção:** whitelist explícita de campos aceitos. (No app Flask isso já existe no PUT de amostradores — conferir que todo endpoint de escrita tem a mesma trava, não só esse.)

## Upload de arquivo

**Grep:** `save(`, `secure_filename`, `request.files`, `open(.*request`
- Nome de arquivo do usuário usado direto no path → path traversal (`../../`). Use `secure_filename`.
- Sem validação de tipo/tamanho → DoS ou upload de executável.
- Path do arquivo montado com input → escrita/leitura arbitrária.

## Path traversal

**Grep:** `send_file`, `send_from_directory`, `open(`, `os.path.join(.*request`, `<path:`
Rota `<path:...>` ou `send_file` com caminho derivado de input → ler arquivo arbitrário. Valide/normalize e confine a um diretório base.

## Desserialização insegura

**Grep:** `pickle.loads`, `yaml.load(` (sem `SafeLoader`), `eval(`, `exec(`, `__import__`
Desserializar dado não confiável com pickle/yaml.load/eval = RCE. Use `yaml.safe_load`, nunca `pickle` em dado externo, nunca `eval`/`exec` com input.

## CSRF

Formulários/endpoints que mudam estado via cookie de sessão sem token CSRF. Flask não protege por padrão — precisa de Flask-WTF/CSRFProtect ou checagem equivalente. Menos crítico se a auth é por token no header (não cookie), mas confirme qual é o caso.

## Rate limiting e DoS barato

Endpoints caros (sync, extração, geração de DOCX, login) sem limite → abuso/força-bruta. Login sem lockout → brute force de senha. Não é crítico sozinho, mas vale nota em endpoints de auth e nos caros.

## CVEs recentes a checar — Werkzeug/Flask (⏱ vintage jul/2026 — confira se saiu correção mais nova)

Confira a versão instalada (`pip show werkzeug flask`) contra:
- **CVE-2024-34069** — CSRF no **debugger interativo** → RCE: atacante que atrai o dev a um subdomínio malicioso contorna o PIN e executa código. Só afeta app com o debugger ligado. Fix: Werkzeug ≥ 3.0.3 — e **nunca** `debug=True` em produção (já é achado por si).
- **CVE-2024-49766 / 49767** — `safe_join()` produz caminho inseguro (path traversal) em **Windows** ou Python < 3.11; e consumo descontrolado de recurso. Fix: Werkzeug ≥ 3.0.6. Relevante se o dev/CI roda Windows.
- **PIN do console via LFI** — havendo path traversal/LFI, dá para ler `/proc/self/environ` + a fonte e **forjar o PIN** do console → RCE. Ou seja: um LFI "só leitura" **encadeia para RCE** se o debugger estiver no ar. Nunca exponha o debugger.
