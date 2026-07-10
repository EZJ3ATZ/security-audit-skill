# Changelog — security-audit

Versionamento semântico. Método é atemporal; notas de CVE são datadas.

## [1.1.0] — 2026-07-10
### Adicionado
- **Link-first:** o primeiro passo passa a ser pedir a URL do sistema; a auditoria começa
  pelo sistema vivo (Fase 1 pela URL → Fase 2 no código), não por trecho solto.
- **Ferramental cabeado:** `tools/scan.py` orquestra detect-secrets + bandit + pip-audit
  (gitleaks/semgrep/npm audit se presentes) como passo de triagem antes da leitura à mão.
- Seção "O que ela agrega (honesto)": rigor/forma + achados de runtime/config + tooling
  determinístico — com a ressalva de que as medições são de N pequeno.

### Mudado
- Proposta de valor reposicionada: "não é *só* um scanner" (roda ferramental e raciocina por
  cima); parou de sugerir "detector superior" e passou a prometer rigor + runtime + automação.

## [1.0.0] — 2026-07-10
### Adicionado
- Protocolo invasor-primeiro em 2 fases (hipótese antes do código; anti-ancoragem).
- Portão de validação (6 perguntas) para todo achado ≥ Médio.
- Chaining de achados e declaração de cobertura honesta obrigatória.
- 11 referências carregadas sob demanda por stack: Flask/Python/Postgres, Supabase/RLS,
  React/TanStack, API (OWASP API Top 10), auth/cripto, cloud/CI-CD, LLM/prompt-injection,
  threat modeling/CVSS/CWE, OWASP Web Top 10, blackbox/DAST + template de contexto local.
- Notas de CVEs recentes por stack (Werkzeug debugger RCE, Supabase RLS off-by-default,
  Next.js middleware bypass).

### Segurança
- Publicação por sanitização (fonte privada rica → cópia pública genérica). Retidos do
  público: `evals/`, `references/contexto-local.md` real e workspace de resultados.
- Porta de sanitização durável (`evals/check_publish_safe.py`): bloqueia identificador
  interno e mojibake; `LICENSE` (autoria) é exceção aprovada.
- Removido número de OS real de um exemplo do `SKILL.md`.
