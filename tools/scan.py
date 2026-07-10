# -*- coding: utf-8 -*-
"""
scan.py — orquestrador de ferramentas de segurança executáveis da skill `security-audit`.

Roda o ferramental determinístico ANTES da leitura à mão (passo 3 da metodologia do
SKILL.md): secret-scan + SAST + auditoria de dependência. É o valor ORTOGONAL ao modelo —
pega o que o raciocínio num ponto no tempo não pega (segredo no working tree, dependência
com CVE, sink perigoso clássico).

Filosofia (igual ao resto da skill):
  - Degrada com HONESTIDADE: ferramenta ausente vira SKIPPED explícito, nunca silêncio.
    "Silêncio sobre cobertura lê-se como 'cobri tudo'." (SKILL.md §Cobertura e honestidade)
  - Nunca falha o processo inteiro por causa de uma ferramenta — captura o erro e segue.
  - Saída é TRIAGEM, não veredito: o modelo confirma cada achado por rastreio (passo 5).
    Ferramenta acha candidato; a skill decide se é real (disciplina de falso-positivo).

Uso:
  py scan.py <caminho-do-alvo> [--json saida.json] [--include-deps]

Ferramentas suportadas (roda as que existirem):
  detect-secrets (segredos)  ·  bandit (SAST Python)  ·  pip-audit (CVE de deps Python)
  gitleaks / semgrep / npm audit  → detectadas se instaladas; hoje ausentes nesta máquina.

Invoca por `sys.executable -m <mod>` (não depende de PATH — os .exe do pip não estão no PATH).
"""
import sys, os, json, subprocess, shutil, argparse, re

# Console do Windows costuma ser cp1252 → caractere fora dele derruba o print.
# Força utf-8 na saída (a saída JSON já usa ensure_ascii=False).
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass

PY = sys.executable

# Diretórios que só geram ruído/lentidão — nunca contêm o código de aplicação a auditar.
EXCLUDE_DIRS = ['node_modules', '.git', '.venv', 'venv', '__pycache__',
                'dist', 'build', '.next', 'site-packages', 'playwright_profile']
EXCLUDE_RE = r'(^|[\\/])(' + '|'.join(re.escape(d) for d in EXCLUDE_DIRS) + r')([\\/]|$)'


def _mod_ok(mod):
    """True se o módulo Python está importável (invocável por -m)."""
    try:
        return subprocess.run([PY, '-c', f'import {mod}'],
                              capture_output=True, timeout=30).returncode == 0
    except Exception:
        return False


def _run(cmd, timeout=300):
    """Roda um comando, devolve (returncode, stdout, stderr). Nunca levanta."""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           encoding='utf-8', errors='replace')
        return p.returncode, p.stdout or '', p.stderr or ''
    except subprocess.TimeoutExpired:
        return None, '', f'TIMEOUT após {timeout}s'
    except Exception as e:
        return None, '', f'ERRO ao executar: {e}'


def scan_secrets(target):
    """detect-secrets — segredos por entropia + padrões conhecidos no working tree."""
    if not _mod_ok('detect_secrets'):
        return {'tool': 'detect-secrets', 'status': 'skipped',
                'motivo': 'não instalado (py -m pip install detect-secrets)'}
    rc, out, err = _run([PY, '-m', 'detect_secrets', 'scan', target,
                         '--exclude-files', EXCLUDE_RE])
    if rc is None:
        return {'tool': 'detect-secrets', 'status': 'error', 'motivo': err.strip()}
    try:
        data = json.loads(out)
        results = data.get('results', {})
        achados = [{'arquivo': f, 'tipo': it.get('type'), 'linha': it.get('line_number')}
                   for f, items in results.items() for it in items]
        return {'tool': 'detect-secrets', 'status': 'ran',
                'total': len(achados), 'achados': achados[:50],
                'nota': 'candidatos por entropia — confirmar se é segredo VIVO (não placeholder/teste)'}
    except json.JSONDecodeError:
        return {'tool': 'detect-secrets', 'status': 'error',
                'motivo': 'saída não-JSON', 'raw': (out or err)[:500]}


def scan_sast(target):
    """bandit — SAST Python (injeção, cripto fraca, subprocess shell, etc.)."""
    if not _mod_ok('bandit'):
        return {'tool': 'bandit', 'status': 'skipped',
                'motivo': 'não instalado (py -m pip install bandit)'}
    rc, out, err = _run([PY, '-m', 'bandit', '-r', target, '-f', 'json',
                         '-x', ','.join(EXCLUDE_DIRS)])
    # bandit retorna 1 quando ACHA algo — não é erro.
    if rc is None:
        return {'tool': 'bandit', 'status': 'error', 'motivo': err.strip()}
    try:
        data = json.loads(out)
        res = data.get('results', [])
        por_sev = {}
        for r in res:
            por_sev[r.get('issue_severity', '?')] = por_sev.get(r.get('issue_severity', '?'), 0) + 1
        # AGRUPA POR test_id — NÃO cortar globalmente por severidade: um test_id
        # ruidoso (B608/B110 com dezenas de hits) soterraria um tipo raro e mais
        # perigoso (B323 TLS off, B314 XXE) que aparece 1x. Cada classe deve ser
        # vista. (Lição da 1ª rodada: o corte global em 40 escondeu B323/B310.)
        sev_rank = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        por_teste = {}
        for r in res:
            por_teste.setdefault(r.get('test_id', '?'), []).append(r)
        resumo_testes = sorted(
            ({'teste': tid, 'n': len(rs), 'severidade': rs[0].get('issue_severity'),
              'problema': rs[0].get('issue_text', '')[:90]} for tid, rs in por_teste.items()),
            key=lambda x: (sev_rank.get(x['severidade'], 3), -x['n']))
        # Amostra: até 5 ocorrências POR test_id, tipos mais graves/raros primeiro.
        achados = []
        for tid in sorted(por_teste, key=lambda t: (sev_rank.get(por_teste[t][0].get('issue_severity'), 3), len(por_teste[t]))):
            for r in por_teste[tid][:5]:
                achados.append({'arquivo': os.path.relpath(r['filename'], target) if r.get('filename') else '?',
                                'linha': r.get('line_number'), 'severidade': r.get('issue_severity'),
                                'confianca': r.get('issue_confidence'), 'teste': r.get('test_id'),
                                'problema': r.get('issue_text', '')[:160]})
        return {'tool': 'bandit', 'status': 'ran',
                'total': len(res), 'por_severidade': por_sev,
                'tipos': resumo_testes, 'achados': achados,
                'nota': 'agrupado por test_id (tipo raro/grave primeiro; até 5 exemplos por tipo). '
                        'Confirmar cada um por rastreio — B608/B110 costumam ser FP; B323/B314/B310/B105 valem checagem'}
    except json.JSONDecodeError:
        return {'tool': 'bandit', 'status': 'error',
                'motivo': 'saída não-JSON', 'raw': (out or err)[:500]}


def scan_deps(target):
    """pip-audit — CVE em dependências Python (precisa de requirements.txt + rede)."""
    if not _mod_ok('pip_audit'):
        return {'tool': 'pip-audit', 'status': 'skipped',
                'motivo': 'não instalado (py -m pip install pip-audit)'}
    req = None
    for cand in ('requirements.txt', 'requirements-dev.txt'):
        p = os.path.join(target, cand)
        if os.path.isfile(p):
            req = p
            break
    if not req:
        return {'tool': 'pip-audit', 'status': 'skipped',
                'motivo': 'sem requirements.txt no alvo'}
    rc, out, err = _run([PY, '-m', 'pip_audit', '-r', req, '-f', 'json'], timeout=180)
    if rc is None:
        return {'tool': 'pip-audit', 'status': 'error',
                'motivo': err.strip()[:300] + ' (offline? a base de CVE precisa de rede)'}
    try:
        data = json.loads(out)
        deps = data.get('dependencies', data if isinstance(data, list) else [])
        vulns = [{'pacote': d.get('name'), 'versao': d.get('version'),
                  'vulns': [v.get('id') for v in d.get('vulns', [])]}
                 for d in deps if d.get('vulns')]
        return {'tool': 'pip-audit', 'status': 'ran', 'requirements': os.path.basename(req),
                'pacotes_vulneraveis': len(vulns), 'achados': vulns,
                'nota': 'CVE conhecido em dependência — atualizar para a versão corrigida'}
    except json.JSONDecodeError:
        return {'tool': 'pip-audit', 'status': 'error',
                'motivo': 'saída não-JSON (talvez sem rede)', 'raw': (out or err)[:500]}


def scan_extras(target):
    """Ferramentas de binário externo — rodadas SE presentes no PATH; senão SKIPPED honesto."""
    out = []
    # gitleaks (secret scan por entropia, mais forte que detect-secrets no histórico git)
    if shutil.which('gitleaks'):
        rc, so, se = _run(['gitleaks', 'detect', '--source', target, '--no-git',
                           '--report-format', 'json', '--report-path', '-'])
        out.append({'tool': 'gitleaks', 'status': 'ran' if rc is not None else 'error',
                    'raw': (so or se)[:400]})
    else:
        out.append({'tool': 'gitleaks', 'status': 'skipped',
                    'motivo': 'binário ausente (Go binary; opcional — detect-secrets já cobre a classe)'})
    # semgrep (SAST multi-linguagem, regras da comunidade)
    if shutil.which('semgrep'):
        rc, so, se = _run(['semgrep', '--config', 'auto', '--json', target], timeout=420)
        out.append({'tool': 'semgrep', 'status': 'ran' if rc is not None else 'error',
                    'raw_len': len(so)})
    else:
        out.append({'tool': 'semgrep', 'status': 'skipped',
                    'motivo': 'ausente (py -m pip install semgrep; no Windows costuma exigir WSL)'})
    # npm audit (CVE de deps JS) — só se houver package-lock e npm
    if shutil.which('npm') and os.path.isfile(os.path.join(target, 'package-lock.json')):
        rc, so, se = _run(['npm', 'audit', '--json', '--prefix', target], timeout=180)
        try:
            data = json.loads(so)
            meta = data.get('metadata', {}).get('vulnerabilities', {})
            out.append({'tool': 'npm audit', 'status': 'ran', 'por_severidade': meta})
        except Exception:
            out.append({'tool': 'npm audit', 'status': 'error', 'raw': (so or se)[:300]})
    else:
        out.append({'tool': 'npm audit', 'status': 'skipped',
                    'motivo': 'sem npm ou sem package-lock.json no alvo'})
    return out


def main():
    ap = argparse.ArgumentParser(description='Orquestrador de scanners da skill security-audit')
    ap.add_argument('target', help='caminho do alvo a escanear')
    ap.add_argument('--json', help='salva o relatório completo neste arquivo')
    ap.add_argument('--include-deps', action='store_true',
                    help='inclui pip-audit (precisa de rede)')
    args = ap.parse_args()

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        print(f'ERRO: alvo não é um diretório: {target}')
        sys.exit(2)

    print(f'== scan.py — alvo: {target} ==\n')
    report = {'target': target, 'tools': []}

    report['tools'].append(scan_secrets(target))
    report['tools'].append(scan_sast(target))
    if args.include_deps:
        report['tools'].append(scan_deps(target))
    else:
        report['tools'].append({'tool': 'pip-audit', 'status': 'skipped',
                                'motivo': 'passe --include-deps para rodar (precisa de rede)'})
    report['tools'].extend(scan_extras(target))

    # Resumo legível
    for t in report['tools']:
        st = t['status'].upper()
        if t['status'] == 'ran':
            n = t.get('total', t.get('pacotes_vulneraveis', t.get('por_severidade', '')))
            print(f'[{st:7}] {t["tool"]:15} — {n if n != "" else "ver detalhes"}')
            # Quebra por tipo (bandit) — para tipo raro/grave não sumir no total.
            for tp in t.get('tipos', []):
                print(f'            └ {tp["severidade"]:7} {tp["teste"]} x{tp["n"]}  {tp["problema"]}')
        else:
            print(f'[{st:7}] {t["tool"]:15} — {t.get("motivo", "")}')

    # Honestidade de cobertura
    rodou = [t['tool'] for t in report['tools'] if t['status'] == 'ran']
    pulou = [t['tool'] for t in report['tools'] if t['status'] == 'skipped']
    print(f'\nCobertura: rodaram [{", ".join(rodou) or "nenhuma"}]; '
          f'pularam [{", ".join(pulou) or "nenhuma"}].')
    print('Lembrete: isto é TRIAGEM. Cada candidato deve ser confirmado por rastreio '
          '(passo 5 do SKILL.md) antes de virar achado — a ferramenta não decide, a skill decide.')

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f'\nRelatório completo salvo em: {args.json}')


if __name__ == '__main__':
    main()
