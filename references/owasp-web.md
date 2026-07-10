# OWASP Top 10 + severidade — checklist transversal

Use este arquivo como rede de segurança: depois de varrer a stack específica, passe por estas categorias para não deixar buraco. Cada uma aponta para onde o detalhe está. **Este é o dono canônico da escala de severidade** — os outros arquivos referenciam, não redefinem. O **template de achado** é o do SKILL.md (§Formatos de saída) — fonte única; este arquivo não o recopia. Para API REST, complemente com `api-security.md` (OWASP API Top 10 é distinto deste).

## OWASP Top 10 (2021) — mapa rápido

| # | Categoria | Onde checar / o que procurar |
|---|-----------|------------------------------|
| A01 | **Broken Access Control** | IDOR, authz por recurso, guards de rota, RLS. A campeã de impacto. Ver flask-python.md §authz e supabase-rls.md §RLS/functions |
| A02 | **Cryptographic Failures** | Segredo hardcoded, TLS desabilitado (`verify=False`/`_create_unverified_context` — CWE-295), hash de senha fraco, RNG inseguro, compare não constante, cripto caseira. Detalhe em auth-tokens.md §criptografia |
| A03 | **Injection** | SQLi, SSTI, command injection (`os.system`, `subprocess` com input), XSS. Ver flask-python.md §injection |
| A04 | **Insecure Design** | Falta de rate limit, fluxo que confia no cliente, ausência de limite de tentativas — problema de arquitetura, não de bug pontual |
| A05 | **Security Misconfiguration** | `debug=True`, CORS `*`, headers de segurança ausentes, erro verboso (stack trace para o usuário), defaults inseguros, bucket público |
| A06 | **Vulnerable Components** | `npm audit`, `pip list --outdated` / deps com CVE conhecido |
| A07 | **Auth Failures** | Brute force sem lockout, sessão que não expira, `SECRET_KEY` fraco, reset de senha inseguro, credencial default |
| A08 | **Data Integrity Failures** | Desserialização insegura (pickle/yaml.load), update sem assinatura, dependência de fonte não confiável |
| A09 | **Logging & Monitoring** | Sem log de evento de segurança (login, falha de authz), OU o oposto: log vazando secret/PII |
| A10 | **SSRF** | Requisição de saída com host/URL do usuário. Ver flask-python.md §SSRF |

## Command injection (não esquecer)

**Grep:** `os.system`, `subprocess.` (com `shell=True`), `os.popen`, `eval`, `commands.`
Input do usuário chegando a shell = RCE. Use `subprocess.run([...], shell=False)` com lista de args, nunca string com `shell=True`.

## Headers de segurança (hardening — geralmente Baixo)

Verifique presença: `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `X-Frame-Options`/`frame-ancestors` (clickjacking), `Strict-Transport-Security`, `Set-Cookie` com `Secure; HttpOnly; SameSite`.
Cookie de sessão sem `HttpOnly`/`Secure`/`SameSite` é achado real (Médio se a sessão for sensível).

## Escala de severidade — como calibrar

Severidade = **impacto** × **facilidade de exploração**. Não classifique pelo nome da vuln, classifique pelo dano concreto no *contexto deste app*.

**Crítico** — exploração leva a comprometimento total ou dano em massa, por atacante sem privilégio ou com privilégio baixo:
- RCE (SSTI, pickle, `debug=True`, command injection)
- Bypass de autenticação
- SQLi com acesso a dados sensíveis / escrita
- service_role vazada / RLS ausente em tabela com PII
- Edge function privilegiada sem checar chamador

**Alto** — dano sério mas com escopo ou pré-condição:
- IDOR expondo PII (dados de trabalhadores, e-mails internos)
- SSRF
- Privilege escalation dentro do app
- XSS armazenado atingindo outros usuários
- Auth com brute force viável (sem lockout) em conta privilegiada

**Médio** — dano limitado ou precisa de interação/condição:
- XSS refletido
- CSRF em ação sensível
- Exposição de informação que facilita ataque maior (stack trace, versões, estrutura interna)
- Cookie sem flags de segurança em sessão sensível
- Rate limit ausente em endpoint caro/de auth

**Baixo** — hardening, boa prática, sem caminho de exploração claro:
- Headers de segurança faltando
- Verbosidade de erro sem dado sensível
- Dependência desatualizada sem CVE explorável no seu uso
- Log ausente

## Regra anti-falso-positivo

Antes de marcar qualquer coisa acima de Baixo, você precisa conseguir escrever a frase: **"com input X, um atacante Y consegue Z"** com X, Y e Z concretos. Se não consegue montar o cenário, rebaixe para "verificar" ou Baixo. Um relatório com achado inflado faz o usuário perder confiança em todos os outros — e aí a auditoria inteira vira ruído.

## Portão de validação (todo achado ≥Médio passa por aqui antes de entrar no relatório)

Checklist único que consolida as regras espalhadas (confirmar, advogado-do-diabo, fato×hipótese, severidade contextual). Rode as 6 perguntas em cada achado ≥Médio. **Falhou uma → rebaixa ou vira "A verificar", não entra como Confirmado.** É o que separa 5 achados sólidos de 20 "pode ser" (a régua da elementalsouls/shuvonsec chama de "7-Question Gate"; aqui são 6, calibradas a whitebox defensivo):

1. **Alcançável?** Existe caminho **real** do input não confiável até o sink — não teórico? Um ator concreto chega até lá?
2. **Sem mitigação no caminho?** Você checou as outras camadas que poderiam barrar (guard `before_request`, RLS, validação na fronteira, escape do framework, constraint de banco)? Uma delas mata o achado?
3. **Cenário concreto?** Consegue escrever *"com input X, ator Y consegue Z"* com X/Y/Z reais deste app (não genéricos)?
4. **Contraprova falhou?** O advogado do diabo tentou inocentar (interpretação inocente, mitigação não vista, sink inalcançável) e **não** conseguiu?
5. **Severidade = dano real aqui?** Classificou pelo impacto **neste** app (que PII vaza, que ação abusa, quem afeta), não pelo nome da classe da vuln?
6. **Fato ou hipótese?** Rastreou de ponta a ponta (ou executou)? Se não chegou ao fim, o Status honesto é **"A verificar"**, não "Confirmado".

No modo invasor-primeiro, este portão é a ponte da Fase 2: cada hipótese da Fase 1 só vira achado depois de passar as 6.
