# -*- coding: utf-8 -*-
"""
schema_drift.py — detector de DERIVA entre o que o código assume e o que o banco aplica.

Por que existe: o code review (whitebox) lê `app.py` e vê as *suposições* do código —
mas o estado REAL de produção não mora no git. Uma tabela com RLS desligada, um GRANT
para o papel `anon`, uma policy permissiva (`USING true`), ou uma coluna sensível que a
whitelist do código nem cobre: nada disso aparece lendo o código. É a única classe de
furo que um modelo forte NÃO enxerga sozinho (5 evals saturaram provando que ele acha o
resto). Aqui o valor é ORTOGONAL ao modelo — igual ao scan.py, mas para a camada de dados.

Filosofia (igual ao resto da skill):
  - Só-leitura. Nunca escreve, nunca altera policy/schema. Consulta catálogo do banco.
  - Degrada com HONESTIDADE: sem driver / sem credencial / backend não suportado = SKIPPED
    explícito, nunca silêncio. Silêncio sobre cobertura lê-se como "cobri tudo".
  - Saída é TRIAGEM: aponta a deriva; a skill confirma o impacto por rastreio (passo 5).
  - O diff é contra uma EXPECTATIVA declarada pelo auditor (o que ele acredita, lendo o
    código) — assim o loop fecha: código diz X, banco faz Y, a ferramenta acha o Y != X.

Uso:
  py schema_drift.py --dsn postgres://user:pass@host/db  [--expect expect.json] [--json out.json]
  py schema_drift.py --sqlite caminho.db --expect expect.json
  (sem --expect: só inventário + heurísticas de risco; com --expect: diff contra o esperado)

Formato de --expect (tudo opcional):
  {
    "postgres": {
      "rls_required": ["empresas","os","contatos"],   // estas tabelas TÊM de ter RLS on
      "no_anon_grants": true,                          // papel anon não pode ter grant de tabela
      "no_permissive_policies": true                   // acende policy com USING/CHECK = true
    },
    "columns": {
      "os": {"client_editable": ["observacao","data_prevista","responsavel"],
             "sensitive": ["empresa_id","status","id"]}
    }
  }
"""
import sys, json, argparse

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

SEV = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "BAIXO": 3, "INFO": 4}


def _finding(sev, classe, onde, detalhe, correcao=""):
    return {"sev": sev, "classe": classe, "onde": onde, "detalhe": detalhe, "correcao": correcao}


# ---------------------------------------------------------------- backends
def _connect_postgres(dsn):
    """Retorna (conn, driver_name) ou (None, motivo_skip)."""
    for mod in ("psycopg", "psycopg2"):
        try:
            drv = __import__(mod)
        except ImportError:
            continue
        try:
            return drv.connect(dsn), mod
        except Exception as e:
            return None, f"driver {mod} presente, mas conexão falhou: {e}"
    return None, "sem driver psycopg/psycopg2 (py -m pip install 'psycopg[binary]')"


def extrair_postgres(conn):
    """Fatos de segurança do catálogo. Só SELECT em pg_* / information_schema."""
    cur = conn.cursor()
    fatos = {"backend": "postgres", "tabelas": {}, "grants_anon": [], "policies": []}

    cur.execute(
        "SELECT c.relname, c.relrowsecurity "
        "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE c.relkind='r' AND n.nspname='public'"
    )
    for nome, rls_on in cur.fetchall():
        fatos["tabelas"][nome] = {"rls": bool(rls_on), "policies": 0, "colunas": []}

    cur.execute(
        "SELECT tablename, policyname, cmd, qual, with_check FROM pg_policies WHERE schemaname='public'"
    )
    for tabela, pol, cmd, qual, check in cur.fetchall():
        if tabela in fatos["tabelas"]:
            fatos["tabelas"][tabela]["policies"] += 1
        fatos["policies"].append(
            {"tabela": tabela, "policy": pol, "cmd": cmd,
             "using": (qual or "").strip(), "check": (check or "").strip()}
        )

    cur.execute(
        "SELECT table_name, privilege_type FROM information_schema.role_table_grants "
        "WHERE grantee='anon' AND table_schema='public'"
    )
    fatos["grants_anon"] = [{"tabela": t, "priv": p} for t, p in cur.fetchall()]

    cur.execute(
        "SELECT table_name, column_name FROM information_schema.columns "
        "WHERE table_schema='public' ORDER BY table_name, ordinal_position"
    )
    for t, col in cur.fetchall():
        if t in fatos["tabelas"]:
            fatos["tabelas"][t]["colunas"].append(col)
    return fatos


def extrair_sqlite(path):
    import sqlite3
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    fatos = {"backend": "sqlite", "tabelas": {}, "grants_anon": [], "policies": []}
    try:
        tabelas = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        for (nome,) in [(r["name"],) for r in tabelas]:
            cols = [r["name"] for r in con.execute(f'PRAGMA table_info("{nome}")').fetchall()]
            # SQLite não tem RLS/roles — não fingimos que tem.
            fatos["tabelas"][nome] = {"rls": None, "policies": None, "colunas": cols}
    finally:
        con.close()
    return fatos


# ---------------------------------------------------------------- análise
def analisar(fatos, expect):
    achados = []
    pg = fatos["backend"] == "postgres"
    exp_pg = (expect or {}).get("postgres", {})
    exp_cols = (expect or {}).get("columns", {})

    if pg:
        # RLS desligada em tabela que o auditor declarou que precisa ter.
        for t in exp_pg.get("rls_required", []):
            info = fatos["tabelas"].get(t)
            if info is None:
                achados.append(_finding(
                    "MEDIO", "expectativa-sem-tabela", t,
                    "tabela esperada em rls_required não existe no schema (drift de nome ou tabela removida)."))
            elif info["rls"] is False:
                achados.append(_finding(
                    "CRITICO", "RLS desligada (CWE-284/A01)", f"tabela {t}",
                    "o código assume proteção por RLS, mas a tabela está com RLS OFF — qualquer papel com grant lê/escreve tudo.",
                    "ALTER TABLE {} ENABLE ROW LEVEL SECURITY; + policy explícita.".format(t)))

        # RLS ligada mas sem policy = deny-all (ou só service_role) — geralmente engano.
        for t, info in fatos["tabelas"].items():
            if info["rls"] and info["policies"] == 0:
                achados.append(_finding(
                    "BAIXO", "RLS on sem policy", f"tabela {t}",
                    "RLS ligada e ZERO policies: nega tudo para anon/authenticated (só service_role passa). Confirme se é intencional."))

        # Grants para anon.
        if exp_pg.get("no_anon_grants") and fatos["grants_anon"]:
            for g in fatos["grants_anon"]:
                achados.append(_finding(
                    "ALTO", "GRANT para anon (A01/A05)", f"{g['tabela']} ({g['priv']})",
                    "papel anon (não autenticado) tem privilégio direto na tabela — supabase expõe anon ao público.",
                    "REVOKE {} ON {} FROM anon; e depender de policy + authenticated.".format(g["priv"], g["tabela"])))

        # Policies permissivas.
        if exp_pg.get("no_permissive_policies"):
            for p in fatos["policies"]:
                for campo, rotulo in (("using", "USING"), ("check", "WITH CHECK")):
                    val = p[campo].lower().replace(" ", "")
                    if val in ("true", "(true)"):
                        achados.append(_finding(
                            "ALTO", "policy permissiva", f"{p['tabela']}.{p['policy']} [{p['cmd']}]",
                            f"{rotulo} = true — a policy não restringe nada (equivale a RLS off para esse comando).",
                            "trocar por predicado de tenancy, ex.: (empresa_id IN (SELECT ...))"))
    else:
        achados.append(_finding(
            "INFO", "backend sem RLS", fatos["backend"],
            "SQLite não tem RLS/roles/policies — as checagens de RLS/grant/policy foram PULADAS (só a de colunas roda). Rode o --dsn do Postgres real para essa camada."))

    # Diff de colunas (roda em qualquer backend) — a whitelist do código vs. colunas reais.
    for tabela, regra in exp_cols.items():
        info = fatos["tabelas"].get(tabela)
        if info is None:
            achados.append(_finding(
                "MEDIO", "expectativa-sem-tabela", tabela,
                "tabela declarada em columns não existe no schema (drift de nome)."))
            continue
        reais = set(info["colunas"])
        editaveis = set(regra.get("client_editable", []))
        sensiveis = set(regra.get("sensitive", []))

        # Sensível marcada como editável pelo cliente = invariante violável.
        for c in sorted(editaveis & sensiveis):
            achados.append(_finding(
                "CRITICO", "coluna sensível editável (CWE-915)", f"{tabela}.{c}",
                "coluna sensível está na whitelist de edição do cliente — mass assignment do campo que sustenta a authz."))
        # Whitelist cita coluna que não existe (drift: renomearam/removeram).
        for c in sorted(editaveis - reais):
            achados.append(_finding(
                "BAIXO", "whitelist aponta coluna inexistente", f"{tabela}.{c}",
                "o código permite editar uma coluna que não existe no banco — drift de schema; a proteção pode estar no lugar errado."))
        # Colunas reais que o auditor não classificou = superfície não coberta.
        naoclass = reais - editaveis - sensiveis
        if naoclass:
            achados.append(_finding(
                "MEDIO", "colunas não classificadas", tabela,
                "colunas reais fora da whitelist e da lista sensível: {} — todo escritor da tabela precisa garantir que o cliente não as grava (verifique importadores/sync/jobs, não só a rota de edição).".format(
                    ", ".join(sorted(naoclass)))))
    return achados


# ---------------------------------------------------------------- saída
def imprimir(fatos, achados):
    print(f"\n=== schema_drift — backend: {fatos['backend']} ===")
    nt = len(fatos["tabelas"])
    if fatos["backend"] == "postgres":
        sem_rls = [t for t, i in fatos["tabelas"].items() if i["rls"] is False]
        print(f"tabelas: {nt} | com RLS off: {len(sem_rls)} | grants p/ anon: {len(fatos['grants_anon'])} | policies: {len(fatos['policies'])}")
    else:
        print(f"tabelas: {nt} (backend sem RLS — camada de policy não auditada aqui)")

    if not achados:
        print("\nNenhuma deriva detectada contra a expectativa fornecida. (Não é 'seguro' — é 'sem drift no que foi declarado'.)")
        return
    achados.sort(key=lambda a: SEV.get(a["sev"], 9))
    print(f"\n{len(achados)} item(ns) de deriva (triagem — confirmar por rastreio):\n")
    for a in achados:
        print(f"[{a['sev']}] {a['classe']} — {a['onde']}")
        print(f"    {a['detalhe']}")
        if a["correcao"]:
            print(f"    fix: {a['correcao']}")
    print()


def main():
    ap = argparse.ArgumentParser(description="Detector de schema/RLS drift (só-leitura).")
    ap.add_argument("--dsn", help="DSN Postgres/Supabase (postgres://...)")
    ap.add_argument("--sqlite", help="caminho de um .db SQLite (self-test / apps SQLite)")
    ap.add_argument("--expect", help="JSON de expectativas (o que o código assume)")
    ap.add_argument("--json", help="grava o resultado estruturado neste arquivo")
    args = ap.parse_args()

    if not args.dsn and not args.sqlite:
        ap.error("informe --dsn (Postgres/Supabase) ou --sqlite")

    expect = None
    if args.expect:
        with open(args.expect, encoding="utf-8") as f:
            expect = json.load(f)

    if args.dsn:
        conn, info = _connect_postgres(args.dsn)
        if conn is None:
            print(f"[SKIPPED] Postgres não auditado: {info}")
            sys.exit(2)
        try:
            fatos = extrair_postgres(conn)
        finally:
            conn.close()
    else:
        fatos = extrair_sqlite(args.sqlite)

    achados = analisar(fatos, expect)
    imprimir(fatos, achados)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({"fatos": fatos, "achados": achados}, f, ensure_ascii=False, indent=2)
        print(f"(resultado gravado em {args.json})")


if __name__ == "__main__":
    main()
