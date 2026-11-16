# AGENTS.md — Clearspace

Clearspace é um app GTK 4 em Python de limpeza de disco **local-first** para Linux. Ele mede consumidores comuns de disco, explica o que pode ser recuperado e só executa ferramentas nativas após revisão e confirmação do usuário.

Responda ao usuário em português do Brasil. Código, nomes de variáveis, commits e logs ficam em inglês.

## Princípio central: o app é geral

Clearspace deve funcionar para **qualquer usuário, distribuição e conjunto de ferramentas**, não para uma máquina específica.

- Bugs, medições e exemplos citados em conversas, issues ou documentos (como o playbook de cleanup) são **exemplos de uma máquina**, não requisitos. Não otimize o código para eles.
- Nunca escreva no código nomes de usuário, caminhos absolutos de uma máquina, tamanhos observados ou nomes de containers/volumes/projetos de alguém.
- Ao corrigir um bug, pergunte: **qual é a classe geral do problema?** Corrija a classe (ex.: "alvos de diretórios ocultos não aparecem", "erros de leitura somem"), não a instância (ex.: "falta o diretório X").
- Não adicione um alvo só porque ele existe na máquina do desenvolvedor. Adicione quando ele for um consumidor de disco **comum** e tiver uma forma segura e documentada de ser tratado.
- Testes usam **fixtures sintéticas** (`tmp_path`, ferramentas falsas), nunca dependem do conteúdo do home real.

## Comandos

```sh
python3 app.py                      # roda o app (requer GTK 4 + python-gobject)
python3 -m pytest -q                # testes (se existir tests/)
python3 -m ruff check . && python3 -m ruff format --check .   # lint, se configurado
```

Se um comando não existir no repo, não o invente: diga que falta e proponha adicioná-lo.
A lógica do scanner deve ser testável **sem importar GTK** e sem display.

## Invariantes de segurança (nunca violar)

1. **Scan é somente leitura** e permanece no filesystem do caminho escaneado (`st_dev`).
2. **Nunca invocar shell**: `subprocess.run([...])` com lista de argumentos, `shell=False`. Sem `os.system`, sem f-string em comando.
3. **Nunca pedir privilégios de administrador** (sem `sudo`, `pkexec`, `su`).
4. **Uma ação destrutiva por vez**, sempre com diálogo mostrando comando exato, tamanho medido e impacto esperado.
5. **Alvos com dados do usuário são somente inspeção**: lixeira, volumes de containers, perfis de navegador, modelos e datasets baixados, projetos, repositórios, bancos de dados, downloads.
6. Nunca usar por padrão comandos amplos e irreversíveis: `rm -rf` em caches inteiros, prune de volumes, limpeza total de cache de pacotes.
7. Canonicalizar (`Path.resolve()`) e validar qualquer caminho antes de agir; rejeitar `/`, a raiz do home, raízes do sistema e symlinks para fora do alvo.
8. Registrar comando, início/fim, exit status e saída no histórico JSONL. **Nunca declarar sucesso se o comando falhou.**
9. Nenhuma chamada de rede. O histórico não guarda conteúdo de arquivos.

Se uma tarefa exigir quebrar uma dessas regras, pare e pergunte.

## Arquitetura orientada a dados

Adicionar suporte a uma nova ferramenta deve ser **adicionar uma entrada declarativa**, sem alterar a lógica do scanner, do runner ou da UI.

Cada alvo é descrito por dados, por exemplo:

- `id`, `label`, `category` (ver classificação de risco abaixo);
- como detectar presença (executável no `PATH`, caminho existente);
- caminhos a medir, resolvidos de forma portátil (`Path.home()`, `XDG_CACHE_HOME`, `XDG_DATA_HOME`, `XDG_CONFIG_HOME`, com fallback para os padrões XDG);
- ação nativa opcional, como lista de argumentos (ou nenhuma, se for só inspeção);
- efeitos colaterais e se é regenerável, em texto para o diálogo.

Regras:

- **Detecção em tempo de execução.** Ferramenta ausente não gera ação nem erro; o app não presume Arch, Docker, Node ou qualquer ferramenta específica.
- **Gerenciadores de pacote por abstração** (pacman, apt, dnf, zypper, flatpak, etc.), cada um como provedor opcional. Nunca assumir uma distro.
- **Descoberta genérica**: além do registry, o app pode listar os maiores diretórios dentro de `~/.cache`, `~/.local/share` e `~/.config` que não estão cobertos, sempre como **somente inspeção**.
- Comandos de ferramentas devem ser conferidos contra a versão instalada antes de serem oferecidos.

### Classificação de risco

- **Regenerável / baixo risco:** caches de build e de download que a ferramenta recria.
- **Risco moderado:** arquivos antigos de pacotes, imagens não usadas, índices de editor.
- **Dados do usuário (somente inspeção):** tudo da invariante 5.
- **Crítico do sistema (nunca tocar):** `/usr`, `/etc`, `/boot`, `/var/lib` desconhecido, dados de aplicações ativas.

## Princípios de código

- Separe **lógica** (registry, scanner, runner, histórico) da **UI GTK**. A lógica não importa `gi`.
- Erros nunca são engolidos: `PermissionError`/`OSError` viram um estado visível ("não foi possível ler" com o motivo), nunca um `continue` silencioso. Tamanhos parciais são marcados como parciais.
- Qualquer filtro (tamanho mínimo, profundidade, top N) deve ser explícito, configurável e contabilizar o que foi ocultado.
- Scan roda fora da thread principal; atualizações de UI só via `GLib.idle_add`.
- Type hints em funções públicas, `pathlib.Path`, `dataclass` para modelos.
- Mudanças pequenas e focadas. Não refatore código não relacionado à tarefa.
- Sem novas dependências sem justificar e pedir confirmação.

## Fluxo de trabalho

1. **Entender**: leia os arquivos relevantes antes de editar. Em bugs, encontre a causa raiz com evidência (arquivo:linha, saída de script) e identifique a **classe geral** do problema.
2. **Planejar**: para tarefas com mais de 2 arquivos, escreva um plano curto (objetivo, arquivos, riscos, como testar).
3. **Implementar** em passos pequenos, rodando testes a cada passo.
4. **Verificar**: testes e lint; para scanner, um script headless sobre uma árvore sintética.
5. **Reportar**: o que mudou, evidência, riscos restantes e o que **não** foi testado.

Quando a tarefa for "investigar", **não altere código**: entregue causa raiz, evidência e diff proposto.

## Paralelismo

Use subagentes, tarefas paralelas ou git worktrees, conforme o ambiente permitir, onde isso economiza tempo sem gerar conflitos.

**Paralelize (leitura, independente):**
- Explorar partes diferentes do código (registry, scanner, UI, runner, histórico).
- Rodar testes, lint e scripts headless.
- Pesquisar o comportamento de ferramentas externas.
- Revisar o diff por ângulos separados (segurança, erros engolidos, generalidade, thread/UI).

**Não paralelize (escrita no mesmo lugar):**
- Dois agentes editando o mesmo arquivo. Se o código for monolítico, **um único agente escreve por vez**.
- Mudanças que dependem do resultado de outra.

**Escritas paralelas:**
1. Defina primeiro o **contrato** entre as partes (assinaturas, dataclasses, formato do registry e do JSONL).
2. Cada agente é dono de arquivos **disjuntos**, de preferência em worktree/branch própria.
3. Cada agente entrega: arquivos alterados, testes passando e riscos. Um integrador mescla e roda a suíte completa.
4. Nunca rodar em paralelo comandos destrutivos ou que alterem o ambiente do usuário.
5. Se o ganho for pequeno ou a divisão ambígua, faça em série.

Frentes típicas: registry/classificação, scanner, runner/histórico, UI, testes. (Use os nomes de módulos reais do repo.)

## Testes

- Árvores temporárias: arquivos e diretórios ocultos, symlinks (não seguidos), permissão negada, outro `st_dev` simulado, caminhos inexistentes.
- Runner com comandos falsos: `shell=False`, argumentos em lista, exit status de falha registrado.
- Alvos somente inspeção **nunca** geram ação destrutiva.
- Registry: toda entrada tem categoria, e nenhuma contém caminho absoluto fixo de usuário.
- Todo bug corrigido ganha um teste de regressão **para a classe do problema**, não só para o caso observado.

## Definição de pronto

- [ ] Invariantes de segurança preservados.
- [ ] Solução geral, sem nomes ou caminhos de uma máquina específica.
- [ ] Testes e lint passam (ou a ausência deles foi declarada).
- [ ] Nenhum erro engolido; itens ilegíveis aparecem na UI.
- [ ] README atualizado se o comportamento visível mudou.
- [ ] Resumo final com evidência, riscos e o que não foi verificado.

## Não faça

- Não aplique correções quando a tarefa pedir só investigação.
- Não codifique caminhos, usuários, tamanhos ou nomes da máquina do desenvolvedor.
- Não apague, mova ou modifique arquivos fora do repositório durante testes; use `tmp_path`.
- Não adicione LLM, RAG ou telemetria (o histórico JSONL é só base para o futuro).
- Não afirme que algo funciona sem ter executado.