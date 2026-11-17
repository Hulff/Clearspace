# Guia para o Codex: modos de análise no Clearspace (v2, gerador de comandos)

Leia o `AGENTS.md` primeiro. Ele tem prioridade sobre este guia. Se houver conflito, siga o AGENTS.md, avise e proponha a mudança; nunca edite invariantes por conta própria.

## Objetivo

Adicionar à UI **modos de análise** ao lado da análise por diretório, que continua sendo o fluxo principal e não muda de comportamento.

Modos novos: **Docker, Caches, Logs, Arquivos grandes, Lixeira, Pacotes**.

## Decisão central (mudou na v2)

**O app não executa limpeza.** Ele analisa, o usuário revisa e seleciona, e o app **gera comandos para o usuário copiar e colar no terminal**. Isso vale para arquivos, caches, Docker, logs e pacotes.

Consequências:
- Não existe executor de limpeza. Sem `subprocess` de limpeza, sem timeout, sem tratamento de saída de comando.
- Subprocessos continuam permitidos só para **leitura** (`docker system df`, `pacman -Qdtq`, `journalctl --disk-usage`, `go env`), com lista de argumentos e sem shell.
- O app não sabe se o comando funcionou. Nunca afirma sucesso: oferece "Reescanear" para medir o espaço realmente liberado.

## Outras decisões do usuário

1. Pacotes: **somente Arch/pacman** por enquanto, estrutura extensível, sem implementar apt/dnf.
2. Comandos que exigem admin (pacman, `journalctl --vacuum`) aparecem em um bloco separado "requer administrador". O app nunca roda sudo.

## Conflito com o AGENTS.md (resolver na Fase 1)

As invariantes 3 e 7 e o "Pronto quando" descrevem um app que executa a exclusão (`Gio.File.trash`) e registra resultado. Na v2 o app gera comandos. Na Fase 1, o Codex deve **propor um diff do AGENTS.md** (invariantes 3 e 7, seção Erros e UX) e **esperar o OK do usuário**. Até lá, não altere o AGENTS.md.

Pontos que o diff deve preservar: lixeira como padrão (`gio trash`), validação de caminhos protegidos, dados do usuário só em inspeção, risco crítico bloqueado, nenhuma ação automática.

## Regras para tudo

- Nenhum caminho, nome ou tamanho da máquina do usuário no código, testes ou docs. Fixtures só sintéticas (`tmp_path`). Valores como "143 GB" ou "~/.gradle 3,1 GB" não entram.
- Novos alvos são **entradas declarativas** no registry: detecção em runtime, caminhos via XDG, comando opcional.
- Lógica (providers, registry, gerador) **não importa `gi`**. A UI só renderiza.
- Sem dependências novas (nada de libadwaita). Use `Gtk.Stack` + `Gtk.StackSidebar`.
- Dados do usuário (volumes Docker, perfis de navegador, modelos Hugging Face, repositórios, `node_modules`, `~/.config`, `~/.vscode`) são **somente inspeção**: nunca geram comando.
- UI em um único idioma (pt-BR).

## Contrato do provider (definir ANTES do código)

Crie `docs/provider-contract.md`. Cada modo é um provider de lógica pura:

```
Row:
  id: str                  # estável, ex. "cache.go.build"
  label: str
  size_bytes: int | None   # st_blocks*512 quando vier de arquivos
  risk: "low" | "medium" | "high" | "critical"
  action: "trash_path" | "tool_command" | "inspect_only"
  path: Path | None        # só para trash_path
  argv: list[str] | None   # só para tool_command, fixo no registry
  needs_admin: bool
  warnings: list[str]

ProviderResult:
  rows: list[Row]          # LIMIT 200
  smaller_count: int       # "N itens menores", pré-calculado
  smaller_bytes: int
  error: ClassifiedError | None

ClassifiedError.kind:
  protected | in_use | outside_root | permission | not_found
  | tool_missing | socket_denied | timeout | unexpected
```

`risk == "critical"` nunca gera comando. `inspect_only` nunca gera comando. O provider só roda quando o modo é aberto, em thread, em lote.

## Gerador de comandos (função pura, sem `gi`, sem subprocess)

Entrada: linhas selecionadas. Saída: texto do script para copiar, mais a lista de itens bloqueados com o motivo.

Regras:
1. Arquivos viram `gio trash -- <path>`, um por linha, citados com `shlex.quote`. **Nunca `rm`, nunca `rm -rf`, nunca glob.**
2. Comandos de ferramentas vêm só do `argv` fixo do registry, montados com `shlex.join`. Nada vem de texto digitado ou de conteúdo de arquivo.
3. Nomes de arquivo são entrada não confiável. Caminho com quebra de linha, NUL ou caractere de controle é **bloqueado** e aparece na revisão com o motivo; não entra no script.
4. Na geração, cada item é re-canonicalizado e revalidado: existe, não é protegido (caminho exato, comparado por componentes com `Path.is_relative_to`), não é `critical`. Falhou, vai para a lista de bloqueados.
5. Cada comando é independente (sem encadear com `&&`), para uma falha não impedir os demais.
6. Cabeçalho e rodapé do script mostram o espaço livre (`df -h --output=avail /`), para o usuário comparar.
7. Cada comando vem precedido por um comentário com rótulo e tamanho estimado.
8. Comandos de admin ficam em bloco separado, rotulado, e o app nunca os executa. `sudo` só aparece nesse bloco, como texto para o usuário.
9. A UI mostra o script na revisão com botão **Copiar** e o aviso "revise antes de colar". Os avisos de app em uso entram como notas na revisão (informativos).
10. Se `gio trash` falhar no terminal do usuário (lixeira indisponível), o script não faz fallback para `rm`. Exclusão permanente não é gerada nesta versão.
11. Histórico JSONL registra só o evento `command_generated` (itens, bloqueios), **sem afirmar sucesso**.

## Fases (uma skill por etapa)

### Fase 1: contrato, esqueleto e diff do AGENTS.md — `$writing-plans`
- Plano curto (arquivos, riscos, testes). Não altere código nem o AGENTS.md; espere o OK do usuário.
- Rascunhe `docs/provider-contract.md` e `docs/command-generator.md`.
- Proponha o diff do AGENTS.md descrito acima.
- Barra lateral com os modos vazios; "Pastas" continua idêntico.

### Fase 2: gerador de comandos — `$test-driven-development` + `$security-best-practices`
Esta é a peça crítica. Escreva os testes primeiro (seção "Testes" abaixo).

### Fase 3: Caches e Lixeira — `$test-driven-development`
- **Caches**: entradas declarativas para subpastas de `$XDG_CACHE_HOME` e caches de dev (npm, pnpm, Gradle, Cargo, Go, pip). Regenerável = risco baixo, aviso "será baixado de novo". Ação: `trash_path` ou `tool_command` (`pip cache purge`, `go clean -cache`, `pnpm store prune`, `npm cache clean --force`).
- **Lixeira**: lista `$XDG_DATA_HOME/Trash/files` por tamanho e idade. **Somente inspeção.**
- Cache nunca é protegido por diretório inteiro; protegido é por caminho exato canonicalizado.

### Fase 4: Arquivos grandes e Logs — `$test-driven-development`
- **Arquivos grandes**: consulta ao banco do scanner (`ORDER BY size DESC LIMIT 200`), filtro de tamanho mínimo, atalho para Downloads via XDG. Teste de contrato com as consultas EXATAS da UI contra o banco do scanner real.
- **Logs**: `journalctl --disk-usage` (leitura), `$XDG_STATE_HOME`, logs grandes legíveis. `journalctl --vacuum-size` entra no bloco de admin.

### Fase 5: Docker e Pacotes — `$test-driven-development`
- **Docker** (leitura): `docker system df`, imagens (em uso ou não), containers parados, cache de build. Comandos gerados: `docker image prune`, `docker container prune`, `docker builder prune`. **Volumes: inspect_only, sem comando de limpeza.**
- Erros classificados: Docker ausente (`tool_missing`), sem permissão no socket (`socket_denied`), daemon parado. A UI mostra a mensagem e "Tentar de novo"; nunca fica em "Loading".
- **Pacotes (Arch)**: detecção por `/etc/os-release`. Mostra tamanho de `/var/cache/pacman/pkg` e órfãos (`pacman -Qdtq`, leitura). Comandos (`paccache`, `pacman -Rns`) só no bloco de admin.
- Testes com saída de exemplo **sintética** e `subprocess` mockado.

### Fase 6: fechamento — `$verification-before-completion`
- "Reescanear" depois de colar os comandos, mostrando o ganho real via `os.statvfs` antes e depois.

## Correção pendente: falso positivo "Aplicação em uso"

O diálogo "Hyprland está usando /home/…" é um falso positivo. Use `$systematic-debugging` antes de editar: ache a causa raiz com arquivo:linha na checagem de `/proc`. Hipótese a confirmar: a comparação está invertida. Só deve contar como em uso se o `cwd` ou um fd do processo estiver **dentro do item** (`cwd.is_relative_to(item)`); ancestrais como o home ou `/` não contam. Todo texto de botão deve ser honesto: o app não fecha processos, então use "Já fechei, tentar novamente". Adicione teste de regressão em `tmp_path` com processo cujo `cwd` é ancestral do item.

## Desempenho (6 GB de RAM)

- Nunca um objeto de UI por nó; `create_func` O(1), sem consulta ao banco.
- Carregar em thread e em lote; limitar linhas vivas.
- Qualquer alegação de melhora exige medição antes e depois em `--release`.

## Comandos

```sh
python3 -m pytest -q
cargo test -q && cargo clippy --all-targets -- -D warnings && cargo fmt --check   # em scanner/
```

Se um comando não existir, diga; não invente.

## Testes obrigatórios (sem GTK, em `tmp_path`)

- **Gerador, nomes hostis**: espaços, aspas simples e duplas, `$(touch x)`, crase, `;`, `&`, nome começando com `-`, unicode, `*` e `?` literais. Para cada um, `shlex.split(linha)` deve devolver exatamente o argv esperado, sem expansão.
- Quebra de linha, NUL e caracteres de controle no nome: item bloqueado, ausente do script.
- O script nunca contém `rm`, `sudo` (fora do bloco de admin), `&&`, `|`, `$(`, crase ou glob gerado a partir de dados.
- Protegidos (exatos, por componentes), `critical` e `inspect_only` nunca geram comando; volumes Docker nunca aparecem.
- Revalidação na geração: item removido ou virado symlink para fora da raiz vira bloqueado.
- Cada provider: detecção, tamanho, risco, erro classificado. Docker/Pacotes com `subprocess` mockado.
- Todo bug ganha teste de regressão da classe do problema.

## Não faça

- Não execute comandos de limpeza no app, não use sudo, pkexec, su nem shell.
- Não gere `rm`, `rm -rf` nem exclusão permanente.
- Não adicione dependência, LLM, RAG ou telemetria.
- Não marque nem apague nada automaticamente.
- Não edite o AGENTS.md sem o OK do usuário.
- Não use `$subagent-driven-development`, `$dispatching-parallel-agents` nem `$yeet`.

## Pronto quando

Invariantes (conforme o AGENTS.md aprovado) preservadas; testes e lint passam (ou a ausência foi declarada); nenhum erro engolido; README e `docs/` atualizados; resumo com evidência e **lista do que não foi verificado** (diálogos GTK, Docker real, sistema não-Arch, execução real dos comandos gerados no terminal).

## Primeira mensagem sugerida ao Codex

> Leia AGENTS.md e docs/clearspace_update_guide.md . Comece pela Fase 1 com `$writing-plans`: devolva o plano curto, o rascunho de `docs/provider-contract.md` e `docs/command-generator.md`, e o diff proposto para o AGENTS.md, sem alterar código. Espere meu OK antes da Fase 2.