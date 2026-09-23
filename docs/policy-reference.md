# Referência da policy

A policy é um arquivo YAML passado em `omotai start --policy <arquivo>`. Ela decide o que o agente pode fazer **usando só fatos que não dependem de interpretação**: esquema, origem, método HTTP, destino de formulário, tipo de campo. Nenhum texto de página ou do modelo entra na decisão. Regra central: a policy só **libera** com fatos; qualquer classificação semântica só pode **endurecer** (por exemplo, trocar `allow` por `confirm`).

Exemplos prontos na pasta `policies/`: `eval-portal.yaml` (somente leitura), `eval-portal-confirm.yaml` (escritas com confirmação) e `demo-confirm.yaml` (a usada no Docker, com login pelo cofre).

## 1. Chaves

| Chave | Padrão | Significado |
| --- | --- | --- |
| `allowed_origins` | `[]` | Lista de origens que o navegador pode acessar (`http://localhost:8001`). Tudo que não estiver aqui (nem na tabela de domínios) é negado, para qualquer método e tipo de recurso. Cada valor é normalizado: `HTTP://Portal.TEST:80/x` vira `http://portal.test` |
| `read_only` | `true` | Escritas (qualquer método que não seja GET, HEAD ou OPTIONS) são negadas, exceto nas janelas que o próprio runtime abre (login e confirmações). Com `false`, **toda** escrita para uma origem permitida passa; use só em ambiente controlado |
| `confirm_writes` | `false` | Um submit de formulário que o `read_only` negaria passa a esperar a aprovação do operador. Exige `read_only: true` (senão o carregamento falha) |
| `confirm_timeout_seconds` | `30` | Tempo que uma confirmação espera. Sem resposta = negada. Mínimo 1. Vale também para `ask_human` |
| `max_confirmations` | `3` | Quantas confirmações uma sessão pode pedir. As seguintes são negadas sem incomodar o operador. Mínimo 0 |
| `max_actions` | `40` | Máximo de tool calls de navegação/ação (`navigate`, `back`, `act`) por **processo** |
| `max_seconds` | `600` | Tempo total desde a subida do servidor, por **processo** |
| `login` | nenhum | Login feito pelo runtime na subida (seção 3) |
| `denied_paths` | `[]` | Caminhos bloqueados mesmo em origem permitida (seção 4) |

Chaves desconhecidas ou valores inválidos fazem o carregamento falhar na subida; o servidor não inicia com uma policy que ele não entendeu.

Os limites são contados desde a subida e valem para o processo todo. Num servidor SSE de longa duração, aumente-os (a `demo-confirm.yaml` usa `max_actions: 500` e `max_seconds: 7200`); depois de atingidos, toda tool devolve `DENIED (max_actions)` ou `DENIED (max_seconds)`.

## 2. Domínios dinâmicos

Além do arquivo, as origens podem ser liberadas ou bloqueadas pela aba **Domains** do dashboard ou por `omotai domain add <origem> --allow|--deny` (tabela `domains` do banco). A origem efetiva é:

```
(allowed_origins do arquivo  ∪  origens "allow" do banco)  −  origens "deny" do banco
```

- **Deny vence allow**, venha o allow do arquivo ou do banco.
- A tabela é relida a cada tool call: a mudança vale na **próxima ação do agente**, sem reiniciar.
- Se a tabela não puder ser lida (arquivo corrompido, por exemplo), a ação é negada com `domains_unreadable`; o runtime não segue com regras que podem estar velhas. Ausência do banco ou da tabela equivale a nenhum domínio dinâmico.
- O login da subida usa a policy carregada **antes** de o servidor iniciar: a origem do portal precisa estar no arquivo ou já na tabela.

## 3. Login

O agente nunca vê nem digita credenciais; o runtime faz o login uma vez, ao subir.

```yaml
login:
  url: http://localhost:8001/login      # deve estar em uma origem permitida
  user_field: user                      # atributo name dos campos do formulário
  password_field: password
  # credenciais: uma das duas formas abaixo
  secret_id: portal-login               # 1) do cofre (omotai secret add portal-login ...)
  user: cliente                         #    usuário, se o segredo for só a senha
  # user_env: OMOTAI_LOGIN_USER         # 2) de variáveis de ambiente
  # password_env: OMOTAI_LOGIN_PASSWORD
```

- Com `secret_id`, o valor do segredo pode ser a senha pura (o usuário vem de `login.user`) ou um JSON `{"user": "...", "password": "..."}`. Se o segredo não existir, o servidor não sobe (`login failed: secret ... not found in vault`).
- O formulário precisa ser `POST` para uma origem permitida. Durante o login, e só nele, o runtime abre uma janela de escrita para esse único POST.
- Qualquer valor de segredo guardado é substituído por `[redacted]` no que o agente vê e nos logs.

## 4. Caminhos bloqueados

```yaml
denied_paths:
  - origin: http://localhost:3000
    path_prefix: /socket.io/
```

Todo request para essa origem sob esse prefixo é negado (`path_denied`), para qualquer método e inclusive dentro da janela de login. O caminho é comparado depois de decodificar `%xx` até estabilizar, resolver `.` e `..`, ignorar barras vazias e passar para minúsculas. `path_prefix` precisa começar com `/`, e `/` sozinho é recusado (para bloquear uma origem inteira, tire-a de `allowed_origins`).

## 5. Confirmação de escritas (`confirm_writes`)

```yaml
read_only: true
confirm_writes: true
confirm_timeout_seconds: 60
max_confirmations: 5
```

Quando o agente clica num botão de envio (ou pressiona Enter num campo) de um formulário com método não seguro, para uma origem permitida:

1. O runtime cria uma aprovação pendente (origem `runtime` na aba Human Approvals) e a chamada do agente **fica pendente**.
2. O texto mostrado é montado pelo runtime a partir de fatos: `MÉTODO URL-do-formulário (form submit by click|press); fields: nome='valor', ...` (campos de senha, ocultos e de arquivo são omitidos; valores truncados em 100 caracteres; segredos mascarados). Nunca é texto do modelo.
3. **Approve**: o runtime confere que a página não mudou (mesmo elemento, mesmo método e mesma URL de destino) e abre uma janela de escrita apenas para esse par `(método, URL)` durante aquela ação. **Deny**, tempo esgotado ou página alterada: a ação é negada e nada é enviado.
4. O agente só recebe o resultado da ação ou um `DENIED (...)`; nunca texto livre do operador.

Limites: só cobre envios de formulário presentes no DOM. Escritas feitas por script (`fetch`, XHR) continuam negadas pelo guard de rede, sem caminho de confirmação. Um destino de formulário fora das origens permitidas nunca vira confirmação: é sempre `deny`. Esperar a resposta conta no `max_seconds`.

A tool `ask_human` é outro canal, **voluntário**: o modelo decide se pergunta e a resposta não libera nada por si. Aparece com origem `agent`.

## 6. Como uma decisão é tomada

1. **Tool** (`Session`): verificações sobre fatos lidos do DOM, para dar uma negação clara antes de enviar qualquer coisa.
2. **Guard de rede**: `page.route()` avalia todo request do navegador (documentos, imagens, scripts, `fetch`, qualquer método) e WebSockets são negados; um proxy forçado avalia cada salto, inclusive redirects, que o navegador segue sem consultar a rota de novo. É o último recurso: mesmo que a camada 1 falhe, o request não sai.

Esquemas `data:`, `blob:` e `about:` não usam rede e são permitidos; qualquer outro que não seja `http`/`https` é negado.

## 7. Códigos `DENIED (...)`

Aparecem para o agente como `DENIED (código)` e no audit no campo `rule`.

| Código | Onde | Significado |
| --- | --- | --- |
| `origin_not_allowed` | navegação, request | Origem fora da lista efetiva (arquivo + banco). Inclui hosts parecidos (`portal.test.evil.test`) e outras portas |
| `scheme_not_allowed` | navegação, request | Esquema que não é `http`/`https` (nem local) |
| `unsafe_scheme` | `navigate` | URL `javascript:`, `file:`, `data:` ou `vbs:` |
| `path_denied` | navegação, request | Coincide com `denied_paths` |
| `read_only` | request de rede | Método não seguro com `read_only: true` |
| `read_only_submit` | `act` | Envio de formulário não seguro com `read_only: true` e sem `confirm_writes` |
| `write_needs_confirmation` | `act` | (decisão `confirm`, não negação) o envio espera o operador |
| `form_destination_not_allowed` | `act` | O formulário envia para origem não permitida |
| `link_origin_not_allowed` | `act` | O link clicado leva a uma origem ou caminho não permitido |
| `agent_cannot_type_passwords` | `act` | `type` ou `press` em campo de senha |
| `not_a_text_field` | `act` | `type` ou `press` em algo que não é `input`/`textarea` |
| `unsafe_ref` | `act` | `ref` que não é alfanumérico |
| `unsupported_action` / `unsupported_key` | `act` | Ação fora de `click`/`type`/`press`, ou tecla diferente de `Enter` |
| `confirmation_denied` | `act` | O operador negou, ou o tempo esgotou |
| `confirmed_action_changed` | `act` | A página mudou entre o pedido e a aprovação |
| `confirmation_budget_exhausted` | `act` | A sessão já pediu `max_confirmations` confirmações |
| `domains_unreadable` | qualquer tool | A tabela de domínios não pôde ser lida |
| `max_actions` / `max_seconds` | qualquer tool | Limite do processo atingido |

Além destes, `ERROR: unknown ref; call observe first` aparece quando o `ref` não existe na página atual, e a seção `--- blocked by runtime ---` de uma observação lista os requests que o guard barrou naquela ação.

## 8. Exemplo completo

`policies/demo-confirm.yaml` (portal do `omotai/eval` que roda no host, visto do container como `host.docker.internal`):

```yaml
allowed_origins:
  - http://host.docker.internal:8001
read_only: true
confirm_writes: true
confirm_timeout_seconds: 90
max_confirmations: 5
max_actions: 500
max_seconds: 7200
login:
  url: http://host.docker.internal:8001/login
  user_field: user
  password_field: password
  secret_id: portal-login
  user: cliente
```

O `policy.yaml` da raiz do repositório é uma policy **permissiva de desenvolvimento** (`read_only: false`, várias origens `localhost`). Não use como base para nada exposto.
