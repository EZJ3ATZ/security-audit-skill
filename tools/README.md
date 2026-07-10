# tools/ — ferramental executável da skill `security-audit`

Ferramentas determinísticas que rodam **antes** da leitura à mão (passo 3 da metodologia).
Valor **ortogonal ao modelo**: pegam o que um raciocínio num ponto no tempo não pega —
segredo no working tree, dependência com CVE, sink perigoso clássico.

## `scan.py` — orquestrador de scanners

```
py tools/scan.py <caminho-do-alvo> [--include-deps] [--json saida.json]
```

Roda as que existirem (degrada com honestidade — ausente vira `SKIPPED` explícito):

| Ferramenta | Classe | Instalação |
|---|---|---|
| **detect-secrets** | segredos (entropia + padrões) | `py -m pip install detect-secrets` |
| **bandit** | SAST Python | `py -m pip install bandit` |
| **pip-audit** | CVE de deps Python (`--include-deps`, precisa de rede) | `py -m pip install pip-audit` |
| gitleaks | segredos no histórico git | binário Go (opcional) |
| semgrep | SAST multi-linguagem | `py -m pip install semgrep` (Windows: WSL) |
| npm audit | CVE de deps JS | vem com o npm |

**Trio mínimo (o que roda nesta máquina):** `py -m pip install detect-secrets bandit pip-audit`
(os `.exe` ficam em `%APPDATA%\Python\...\Scripts`, fora do PATH — por isso o runner invoca
por `sys.executable -m <mod>`, não depende do PATH).

## Princípios (iguais aos do SKILL.md)

- **A saída é TRIAGEM, não veredito.** A ferramenta acha candidato; a skill confirma por
  rastreio (passo 5). Ex.: na estreia (10/07) bandit deu 226 candidatos → **1 real**
  (`um_cliente_http.py` TLS off) + 78 B608 SQLi todos FP (o código parametriza com `?`).
- **Ruído não esconde raro.** O runner agrupa por `test_id` (tipo grave/raro primeiro),
  para um B608/B110 com dezenas de hits não soterrar um B323/B314 que aparece 1×.
- **Cobertura honesta.** Sempre imprime o que rodou e o que pulou.
- **Nunca falha o processo por uma ferramenta** — erro de uma vira `error`/`skipped`, segue.

## Sinais que valem checagem sempre (baixo FP)
`B323` TLS off · `B314/B405` XXE · `B105` segredo hardcoded · `B310` SSRF/scheme ·
`B602/B605` shell=True · qualquer achado do detect-secrets/gitleaks · qualquer CVE do pip-audit.

## Costumam ser FP (confirmar, mas não alarmar cedo)
`B608` SQLi (se o valor vai em `?` e só constante/whitelist é interpolada) · `B110/B112`
try/except/pass (code smell) · `B101` assert · `B104` bind 0.0.0.0 (normal em container).
