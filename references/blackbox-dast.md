# Blackbox / DAST — testar o app publicado do próprio usuário

Complemento **opt-in** do whitebox. Aqui você não lê código — você bate no app rodando de fora e observa o comportamento real. Serve para **confirmar ou refutar** o que a análise estática levantou (o whitebox suspeita; o runtime prova) e para achar o que só aparece em produção: header ausente, flag de cookie, endpoint esquecido no ar, verbosidade de erro real.

## Escopo — sistemas autorizados

O critério é **autorização**, não autoria. Em escopo: qualquer sistema de que o usuário/organização é dono ou tem permissão explícita para testar. **Quando o usuário aponta uma URL, ele está afirmando autorização — leia e teste.** Não fique pedindo confirmação de propriedade a cada URL dentro do escopo já declarado.

Alvos típicos: os apps do próprio usuário/organização (ex.: `https://seu-app.example.com/`) e qualquer app/URL interno que o usuário mandar analisar.

**Único freio real:** propósito + propriedade. Se o alvo for claramente infra de um terceiro **sem relação com o usuário/organização** e o pedido for para *atacar/explorar em proveito próprio* (não blindar), pare — aí é crime (lei de uso indevido de computador, ex.: CFAA), não auditoria. No fluxo autorizado normal, o alvo é interno e o objetivo é corrigir. Prossiga.

## Quando ativar

- O usuário pediu explicitamente ("testa o app rodando", "pentest", "confirma em produção").
- A fase whitebox achou algo que **só o runtime resolve** — então proponha e explique o porquê. Exemplos que quase sempre justificam:
  - Suspeita de header/cookie/TLS → só a resposta HTTP real confirma.
  - Endpoint de debug/admin achado no código → está de fato alcançável e gated no ar?
  - Handler que parece vazar `str(e)` → o corpo da resposta real vaza mesmo?

## Regra de segurança operacional (não quebrar produção)

- **Default read-only.** Use `GET` e leitura de resposta. Nada de disparar `POST/PUT/DELETE` destrutivo contra produção.
- Se precisar testar um fluxo de escrita (ex.: confirmar CSRF, testar mass-assignment), **confirme com o usuário antes** e prefira dado descartável / ambiente de staging. Deploy do app Flask é automático no `main` e o banco é o de produção — não há rede de segurança.
- **Sem varredura agressiva.** Nada de brute force / fuzzing pesado / nuclei com mil templates contra um app single-instance no Railway — derruba o serviço (auto-DoS). Rate baixo, alvo cirúrgico.
- Não exfiltrar PII real nas evidências — mascarar CPF/nome/e-mail nos exemplos do relatório.

## O que checar (probe → o que esperar)

### Headers de segurança
```
curl -sI https://seu-app.example.com/
```
Procure ausência de: `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options`/CSP `frame-ancestors` (clickjacking), `Content-Security-Policy`. Ausência = achado de hardening (Baixo/Médio). Casa com owasp-web.md §headers.

### Cookie de sessão (flags reais)
No `Set-Cookie` da resposta de login, confirme `HttpOnly`, `Secure`, `SameSite`. O whitebox viu a config; aqui você vê o que o browser recebe de verdade (proxy/Railway pode alterar). Falta de flag em cookie de sessão = achado real.

### TLS
```
curl -sI https://<host>/     # 200/redirect sob TLS válido?
```
Certificado válido, sem downgrade para HTTP, versão de TLS aceitável. (No lado cliente: confirmar que o app não tem `verify=False` — isso é whitebox, ver auth-tokens.md §cripto.)

### Endpoints expostos / auth de fato aplicada
- Bata em rota sensível **sem** cookie de sessão → deve vir 401/redirect, não dado. Se vier dado, é auth ausente (Crítico).
- Bata num endpoint de debug/admin achado no código (`/controle/graph/debug*`, `/controle/reset`) **como usuário comum / sem login** → deve ser 403/401. Se executar, é BFLA (ver api-security.md §API5).
- Descoberta leve de rota: só caminhos que você já conhece do código ou do sitemap — não fuzzing cego.

### Verbosidade de erro
Force um input malformado num GET e veja o corpo: veio stack trace / `str(e)` / SQL? = info disclosure (CWE-209, ver owasp-web.md).

### CORS
```
curl -sI -H "Origin: https://evil.example" https://<host>/api/<algo>
```
`Access-Control-Allow-Origin` refletindo qualquer origem + `Allow-Credentials: true` = furo. Confirma o que o whitebox só suspeita.

## Ferramentas (leves, no seu contexto)

- `curl` — o cavalo de batalha (headers, cookies, CORS, status). Suficiente para 80% do DAST manual.
- **OWASP ZAP baseline scan** (`zap-baseline.py -t <url>`) — passivo, não intrusivo, bom primeiro retrato.
- `testssl.sh` / `sslyze` — postura de TLS.
- `nuclei` **com moderação** — só templates de exposição/misconfig, rate baixo, contra seu próprio host. Nunca a base inteira num app single-instance.
- Navegador + DevTools (Network) — para o que exige sessão autenticada.

## Fechar o laço com o whitebox

Todo achado blackbox deve voltar ao código: header ausente → onde adicionar no Flask; endpoint alcançável → qual guard falhou (routes.py); erro verboso → o handler (app.py). O blackbox **prova o sintoma**; a correção mora no código. Reporte no mesmo template de achado (owasp-web.md), com **Status: Confirmado (runtime)** e a requisição/resposta como evidência (PII mascarada).
