# AGENTS.md — Clearspace

App GTK 4 (Python) de limpeza de disco local-first para Linux, com scanner em Rust. Mede consumidores de disco, explica o que pode ser recuperado e só executa ações após revisão e confirmação.

Responda em português do Brasil. Código, commits e logs em inglês. Seja conciso: não cole arquivos nem logs inteiros; use `-q`, `| tail -n 30`, `git diff --stat`.

## Skills: invocação explícita

Comece cada etapa nomeando a skill com `$nome`. Confira com `/skills` se está instalada; se não estiver, siga o passo equivalente da tabela e avise. O pedido do usuário e as invariantes abaixo têm prioridade sobre qualquer skill.

| Situação | Skill | Equivalente sem a skill |
|---|---|---|
| Bug, teste falhando, crash, travamento | `$systematic-debugging` | Reproduzir, instrumentar, causa raiz com arquivo:linha, corrigir a classe do problema, teste de regressão. Não edite antes da causa. |
| Feature nova, mais de 2 arquivos, mudança de arquitetura | `$writing-plans` (antes, `$brainstorming` se o design for incerto) | Plano curto: escopo, arquivos, riscos, como testar. Espere OK se tocar executor, validador ou exclusão. |
| Lógica pura nova (scanner, validador, executor, seleção, contrato) | `$test-driven-development` | Escreva o teste que falha primeiro. |
| Antes de dizer "pronto" ou commitar | `$verification-before-completion` | Rode testes, lint e bench; mostre a saída; liste o que NÃO foi verificado. |
| Mudança em executor, validador de caminhos ou exclusão | `$security-best-practices` (se instalada), além das invariantes | Revise contra a seção de segurança. |

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
2. Sem shell (`subprocess` com lista de argumentos). Sem sudo, pkexec ou su; o que exigir admin vira comando para o usuário copiar.
3. Exclusão: **mover para a lixeira** (`Gio.File.trash`) por padrão. A revisão lista o lote ordenado por risco e tamanho e uma confirmação explícita autoriza somente os itens listados; cada item continua sendo revalidado, executado e registrado individualmente. Se a lixeira não existir no local (GIO `NOT_SUPPORTED`, código 15), classifique como "lixeira indisponível" e ofereça exclusão permanente por ação explícita, sem fallback automático. Risco crítico é sempre bloqueado.
4. Caminhos protegidos por **caminho exato canonicalizado**, comparado por componentes (`Path.is_relative_to`), nunca por prefixo de string, padrão por nome nem diretório de cache inteiro. Protegidos: `/`, o próprio diretório home (não seus descendentes), `/usr`, `/etc`, `/boot`, `~/.ssh`, `~/.gnupg`, credenciais, dados de usuário de editores. Repositórios no home podem ser selecionados, mas mantêm risco de dados do usuário e exigem confirmação reforçada. Caches regeneráveis do registry são permitidos com aviso.
5. Dados do usuário (lixeira, volumes de container, perfis de navegador, modelos, projetos, repositórios, bancos) são inspeção por padrão.
6. Aplicação em uso: avisar (lendo `/proc`), nunca encerrar processos.
7. Reverifique cada item na hora da execução; registre cada ação (caminho, tamanho, resultado, erro com domain/code) no histórico JSONL. Nunca declare sucesso se falhou.
8. Rede: só loopback (Ollama local). Sem telemetria. O assistente só propõe; nunca marca, apaga nem executa sozinho. Texto de arquivos é entrada não confiável.

## Erros e UX

- Nunca engula exceções. Classifique: protegido pelo app, app em uso, fora da raiz, sem permissão, lixeira indisponível, item inexistente.
- Uma falha não aborta os demais itens; resumo final com motivos e botão para copiar o caminho.
- A UI nunca fica em "Loading" após erro: mostre a mensagem, "Tentar de novo" e "Escolher outra pasta".
- Avise na revisão, antes de confirmar, os itens que provavelmente vão falhar (dono diferente, pai sem escrita, sem lixeira).
- Um idioma único em toda a interface.

## Arquitetura

- App geral: sem caminhos, nomes ou tamanhos de uma máquina; novos alvos são entradas declarativas (detecção em runtime, caminhos via XDG, ação nativa opcional). Fixtures só sintéticas (`tmp_path`).
- Lógica (registry, scanner, executor, histórico) separada da UI GTK; a lógica não importa `gi`.
- Scanner Rust = binário separado, chamado com lista de argumentos. Grava SQLite com esquema **versionado** (`PRAGMA user_version`, `schema_version` no evento `completed`, `--version`). O app valida a versão antes de consultar e mostra mensagem acionável se divergir. O scanner Python é fallback até a paridade com Rust e `du` passar.
- Contrato em `docs/scanner-contract.md`, definido antes do código dos dois lados.

## Desempenho (máquina de 6 GB de RAM)

- Nunca crie objeto de UI por nó. `create_func` é O(1), sem consulta ao banco. Carregue filhos ao expandir, em thread e em lote; `ORDER BY size DESC LIMIT 200` mais "N itens menores" pré-calculado.
- Limite de nós vivos com descarte dos subtrees colapsados mais antigos. Seleção sem percorrer descendentes.
- Mudança de desempenho exige medição antes e depois (tempo, pico de RAM) em `--release`. Sem números, não afirme melhora.

## Testes e pronto

- Testes sem GTK em `tmp_path`: hardlinks, symlinks, permissão negada, dotfiles, árvore grande; paridade Python × Rust × `du`; teste de contrato rodando as consultas EXATAS da UI contra o banco do scanner real; caminhos protegidos; erros classificados.
- Todo bug ganha teste de regressão da classe do problema.
- Pronto quando: invariantes preservadas, testes e lint passam (ou a ausência foi declarada), nenhum erro engolido, README e contrato atualizados, resumo com evidência e o que não foi verificado (diálogos GTK).

## Paralelismo

Só em leitura (explorar, testes, revisão). Em escrita, um agente por arquivo, com contrato definido antes e um integrador no fim. Nunca comandos destrutivos em paralelo.

## Não faça

- Não relaxe invariantes, não crie exceções soltas ao validador, não use sudo.
- Não adicione dependências, LLM, RAG ou telemetria sem pedir.
- Não reescreva a UI em Rust nem remova o scanner Python sem medição e paridade.
- Não afirme que funciona sem ter executado.
