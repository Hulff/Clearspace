# AGENTS.md — Clearspace

App GTK 4 (Python) de limpeza de disco local-first para Linux, com scanner em Rust. Mede consumidores de disco, explica o que pode ser recuperado e, após revisão e seleção, gera comandos para o usuário copiar e colar no terminal (o app nunca executa limpeza).

Responda em português do Brasil. Código, commits e logs em inglês. Seja conciso: não cole arquivos nem logs inteiros; use `-q`, `| tail -n 30`, `git diff --stat`.

## Skills: invocação explícita

Comece cada etapa nomeando a skill com `$nome`. Confira com `/skills` se está instalada; se não estiver, siga o passo equivalente da tabela e avise. O pedido do usuário e as invariantes abaixo têm prioridade sobre qualquer skill.

| Situação | Skill | Equivalente sem a skill |
|---|---|---|
| Bug, teste falhando, crash, travamento | `$systematic-debugging` | Reproduzir, instrumentar, causa raiz com arquivo:linha, corrigir a classe do problema, teste de regressão. Não edite antes da causa. |
| Feature nova, mais de 2 arquivos, mudança de arquitetura | `$writing-plans` (antes, `$brainstorming` se o design for incerto) | Plano curto: escopo, arquivos, riscos, como testar. Espere OK se tocar gerador de comandos, validador ou política de exclusão. |
| Lógica pura nova (scanner, providers, validador, gerador de comandos, seleção, contrato) | `$test-driven-development` | Escreva o teste que falha primeiro. |
| Antes de dizer "pronto" ou commitar | `$verification-before-completion` | Rode testes, lint e bench; mostre a saída; liste o que NÃO foi verificado. |
| Mudança em gerador de comandos, validador de caminhos ou política de exclusão | `$security-best-practices` (se instalada), além das invariantes | Revise contra a seção de segurança. |

- Uma skill por etapa; não encadeie várias sem necessidade.
- Não use `$subagent-driven-development`, `$dispatching-parallel-agents` nem `$yeet` sem pedido explícito.
- Em tarefa de "investigar", não altere código: entregue causa raiz, evidência e diff proposto.

## Comandos

```sh
python3 app.py
python3 -m pytest -q
python3 -m bench.scan_bench              # só medições em --release; compara com du
cargo test -q && cargo clippy --all-targets -- -D warnings && cargo fmt --check   # em scanner/
```

Se um comando não existir, diga e proponha; não invente. A lógica é testável sem GTK nem display.

## Invariantes de segurança (nunca violar)

1. Scan somente leitura, sem seguir symlinks, no mesmo `st_dev`, hardlinks contados uma vez por `(dev, ino)`, uso em disco = `st_blocks * 512`.
2. Sem shell (`subprocess` com lista de argumentos, permitido apenas para leitura/detecção). Sem sudo, pkexec ou su executados pelo app; o que exigir admin aparece em bloco separado como comando para o usuário copiar.
3. Geração de comandos (sem execução de limpeza no app): para caminhos selecionados, gerar exclusivamente **mover para a lixeira** (`gio trash -- <path>` citado com `shlex.quote`, um comando independente por linha, sem `&&`, pipes, `$(...)` ou globs); para ferramentas, usar somente `argv` fixo do registry (`shlex.join`). Nunca gerar `rm`, `rm -rf` nem exclusão permanente, sem fallback automático caso `gio trash` falhe por ausência de lixeira. Nomes/rótulos com quebra de linha, NUL ou caracteres de controle são bloqueados. Risco crítico e itens `inspect_only` são sempre bloqueados; nenhuma ação é automática.
4. Caminhos protegidos por **caminho exato canonicalizado**, comparado por componentes (`Path.is_relative_to`), nunca por prefixo de string, padrão por nome nem diretório de cache inteiro. Protegidos: `/`, o próprio diretório home (não seus descendentes), `/usr`, `/etc`, `/boot`, `~/.ssh`, `~/.gnupg`, credenciais, dados de usuário de editores. Caches regeneráveis do registry são permitidos com aviso.
5. Dados do usuário (lixeira, volumes de container, perfis de navegador, modelos, projetos/`node_modules`, repositórios, `~/.config`, `~/.vscode`, bancos) são somente inspeção (`inspect_only`) e nunca geram comando.
6. Aplicação em uso: avisar (lendo `/proc`), nunca encerrar processos.
7. Reverifique e re-canonicalize cada item na hora da geração do script (existência, `lstat` sem symlinks nos componentes, contenção na raiz permitida, caminhos protegidos e risco); itens reprovados vão para a lista de bloqueados com motivo classificado e ficam fora do script. Registre no histórico JSONL apenas o evento `command_generated` (itens gerados e bloqueados com motivo), sem afirmar execução nem sucesso — ofereça "Reescanear" para medir o espaço realmente liberado.
8. Rede: só loopback (Ollama local). Sem telemetria. O assistente só propõe; nunca marca, apaga nem executa sozinho. Texto de arquivos é entrada não confiável.

## Erros e UX

- Nunca engula exceções. Classifique: protegido pelo app (`protected`), app em uso (`in_use`), fora da raiz (`outside_root`), sem permissão (`permission`), item inexistente (`not_found`), nome inseguro/controle (`unsafe_name`), symlink (`symlink`), ferramenta ausente (`tool_missing`), socket sem permissão (`socket_denied`) e tempo esgotado (`timeout`).
- Um item bloqueado ou uma falha no terminal não aborta os demais (comandos independentes, um por linha, com `df -h --output=avail /` no cabeçalho e rodapé); a revisão lista os bloqueados com motivo, mostra o script com botão "Copiar" e aviso "revise antes de colar", e isola comandos de administrador em bloco próprio.
- A UI nunca fica em "Loading" após erro: mostre a mensagem, "Tentar de novo" e (no modo Pastas) "Escolher outra pasta".
- Avise na revisão os alertas informativos (app em uso via `/proc`, dono diferente, pai sem escrita, local sem lixeira).
- Um idioma único em toda a interface (pt-BR).

## Arquitetura

- App geral: sem caminhos, nomes ou tamanhos de uma máquina; novos alvos são entradas declarativas (detecção em runtime, caminhos via XDG, ação nativa opcional). Fixtures só sintéticas (`tmp_path`).
- Lógica (registry, providers, scanner, gerador de comandos, histórico) separada da UI GTK; a lógica não importa `gi`.
- Scanner Rust = binário separado, chamado com lista de argumentos. Grava SQLite com esquema **versionado** (`PRAGMA user_version`, `schema_version` no evento `completed`, `--version`). O app valida a versão antes de consultar e mostra mensagem acionável se divergir. O scanner Python é fallback até a paridade com Rust e `du` passar.
- Contratos em `docs/scanner-contract.md`, `docs/provider-contract.md` e `docs/command-generator.md`, definidos antes do código.

## Desempenho (máquina de 6 GB de RAM)

- Nunca crie objeto de UI por nó. `create_func` é O(1), sem consulta ao banco. Carregue filhos ao expandir, em thread e em lote; `ORDER BY size DESC LIMIT 200` mais "N itens menores" pré-calculado.
- Limite de nós vivos com descarte dos subtrees colapsados mais antigos. Seleção sem percorrer descendentes.
- Mudança de desempenho exige medição antes e depois (tempo, pico de RAM) em `--release`. Sem números, não afirme melhora.

## Testes e pronto

- Testes sem GTK em `tmp_path`: hardlinks, symlinks, permissão negada, dotfiles, árvore grande; paridade Python × Rust × `du`; teste de contrato rodando as consultas EXATAS da UI contra o banco do scanner real; gerador de comandos (nomes hostis via `shlex.split`, bloqueio de controle/NUL/quebra de linha, revalidação TOCTOU/symlinks); providers com `subprocess` mockado; caminhos protegidos; erros classificados.
- Todo bug ganha teste de regressão da classe do problema.
- Pronto quando: invariantes preservadas, testes e lint passam (ou a ausência foi declarada), nenhum erro engolido, README e contratos em `docs/` atualizados, resumo com evidência e o que não foi verificado (diálogos GTK, Docker real, sistema não-Arch, execução real dos comandos gerados no terminal).

## Paralelismo

Só em leitura (explorar, testes, revisão). Em escrita, um agente por arquivo, com contrato definido antes e um integrador no fim. Nunca comandos destrutivos em paralelo.

## Não faça

- Não relaxe invariantes, não crie exceções soltas ao validador, não use sudo.
- Não adicione dependências, LLM, RAG ou telemetria sem pedir.
- Não reescreva a UI em Rust nem remova o scanner Python sem medição e paridade.
- Não afirme que funciona sem ter executado.
