Leia AGENTS.md antes de começar. Trabalhe em fases, com um commit por fase.

OBJETIVO
Transformar o Clearspace em uma UI com 3 partes, mantendo o app GERAL
(nada específico da minha máquina):
1. Árvore de arquivos e pastas ordenada por tamanho, com seleção para exclusão.
2. Motor de avisos de risco e de procedimentos recomendados.
3. Painel de chat que recebe o usuário. Ainda sem LLM, mas pronto para um depois.

FASE 0 — Contratos (sem UI)
- Atualize a seção de invariantes do AGENTS.md para a nova regra de exclusão:
  padrão = mover para lixeira via Gio; exclusão permanente só com confirmação
  digitada e nunca para risco crítico; lista de caminhos protegidos; sem sudo,
  sem shell, sem seguir symlinks; ações executadas item a item com log no JSONL.
- Defina em módulos sem GTK (dataclasses/Protocols):
  - Node: path, name, is_dir, size_bytes (uso em disco), error (estado de leitura), children_loaded.
  - SelectionModel: estados marcado / desmarcado / parcial; calcula o conjunto mínimo
    de caminhos (se a pasta está marcada, ignora filhos) e o tamanho total estimado.
  - Rule: matcher (glob, nome, categoria), risk (low, moderate, user_data, critical),
    message, recommended_procedure_id opcional. Rules são DADOS, sem caminhos de usuário.
  - Procedure: id, label, argv (lista), requires_admin, side_effects, regenerable,
    detecta presença da ferramenta. Se requires_admin, só mostra o comando para copiar.
  - Assistant (Protocol): respond(message, context) -> AssistantReply, com texto e
    ações PROPOSTAS (selecionar nó, abrir procedimento, explicar risco).
    Ações propostas nunca executam sem confirmação do usuário.

INVARIANTES DE EXCLUSÃO (obrigatórias nas fases 3–5)
- A ação destrutiva padrão é mover para a lixeira usando Gio. Exclusão permanente
  só pode ocorrer após o usuário digitar explicitamente a palavra de confirmação
  apresentada na revisão, e é sempre bloqueada para risco crítico.
- Nunca alterar raízes protegidas: `/`, a raiz do home, `/usr`, `/etc`, `/boot`,
  `/var`, `/proc`, `/sys`, `/dev`, `/run` e caminhos equivalentes após canonicalização.
  Dados de aplicações ativas e caminhos que escapem da raiz permitida também são
  protegidos. Validar cada item e seus symlinks imediatamente antes da ação.
- Não seguir symlinks durante scan nem exclusão. Não usar shell, `sudo`, `pkexec`
  ou outro mecanismo de elevação. Procedimentos que exigem administrador podem
  apenas mostrar o comando exato para cópia e nunca podem ser executados pelo app.
- Executar uma ação por vez e item a item, com revisão e confirmação do usuário.
  Registrar no histórico JSONL caminho, tamanho, ação, início/fim, resultado e
  detalhes de falha; nunca registrar conteúdo de arquivos nem declarar sucesso
  quando uma operação falhar.

Lista explícita de caminhos protegidos: `/`, a raiz do home, `/usr`, `/etc`, `/boot`,
`/var`, `/proc`, `/sys`, `/dev` e `/run`. A validação também protege equivalentes
após canonicalização, caminhos fora da raiz permitida, symlinks que escapem dela e
dados de aplicações ativas. Nenhuma regra ou procedimento pode contornar essas
proteções.

FASE 1 — Scanner em árvore (lógica)
- Carregamento preguiçoso: mede o nível atual, expande sob demanda, em thread
  (resultados na UI via GLib.idle_add).
- Meça uso em disco (st_blocks * 512), igual ao du; conte hardlinks uma vez (st_dev, st_ino);
  não siga symlinks; fique no mesmo filesystem; erros viram Node.error
  ("não foi possível ler: motivo") e tamanho parcial marcado como parcial.
- Pastas com muitos filhos mostram os maiores e um nó agregado "N itens menores".
- Inclui ARQUIVOS, não só pastas. Raiz configurável (home por padrão); o registry atual
  vira atalhos/sugestões, não o limite do que aparece.

FASE 2 — Avisos e procedimentos
- Motor que, dado um Node, devolve risco, avisos e procedimento recomendado.
- Regras genéricas por categoria (caches regeneráveis, node_modules/target/build,
  lixeira, perfis de navegador, volumes de container, modelos e datasets, repositórios
  git, jogos/saves, chaves e credenciais). Para repositório git, avise se houver
  mudanças não commitadas via ["git", "-C", path, "status", "--porcelain"] (sem shell).
- Quando existir procedimento nativo, recomende-o em vez de apagar à mão
  (ex.: cache de pacotes, build cache, journal). Detecte as ferramentas em runtime.
- Procedimentos de ferramentas ausentes não aparecem.

FASE 3 — Execução da exclusão
- Fluxo: Selecionar -> Revisar plano (lista, tamanhos, avisos, risco máximo,
  "espaço só é liberado ao esvaziar a lixeira") -> Confirmar.
- Risco user_data pede confirmação reforçada; permanente pede digitar uma palavra
  de confirmação; critical bloqueia.
- Canonicalize e valide cada caminho antes de agir (Path.resolve, rejeitar protegidos
  e symlinks para fora). Reverifique no momento da execução.
- Execute item a item, registrando no histórico JSONL (caminho, tamanho, ação,
  resultado). Nunca declare sucesso se falhou. Ao final, mostre o antes/depois do df.

FASE 4 — UI GTK 4
- Gtk.ColumnView + Gtk.TreeListModel + Gtk.SortListModel (não use Gtk.TreeView, que está
  obsoleto). Colunas: checkbox tri-state, nome com ícone, barra e tamanho, badge de risco.
  Ordenação por tamanho decrescente em cada nível; alternância opcional para
  "maiores arquivos" em lista plana.
- Barra inferior fixa: total selecionado, risco máximo e botão "Revisar".
- Painel de detalhes do nó: avisos, procedimento recomendado e "Abrir pasta".
  Abrir pasta SEMPRE com Gio/Gtk.FileLauncher, nunca um gerenciador fixo.
- A UI não faz lógica: só consome os módulos das fases anteriores.

FASE 5 — Chat (ainda sem LLM)
- Painel lateral recolhível (ou aba) com lista de mensagens e campo de entrada.
- Ao abrir, saudação com resumo real: espaço livre/total, maiores consumidores e
  chips de sugestão ("Limpeza segura", "O que é maior?", "Explique o risco de X").
- Implemente LocalRuleAssistant (baseado em regras e nos resultados do scan, sem rede).
  O LLM futuro entra trocando a implementação do Protocol Assistant.
- Respostas e ações propostas do assistente são tratadas como NÃO CONFIÁVEIS: só podem
  destacar nós, abrir painéis e sugerir procedimentos, passando pelo mesmo fluxo de
  revisão e confirmação. Nunca marcar nem apagar por conta própria.
- Mensagens ficam só na memória por padrão. Não envie nada pela rede.

PARALELISMO
Após a Fase 0, rode em paralelo (arquivos disjuntos): scanner (F1), regras/procedimentos
(F2), executor (F3) e testes. UI e chat (F4, F5) começam depois dos contratos. Um agente
integrador mescla e roda tudo. Nunca dois agentes no mesmo arquivo.

TESTES
Fixtures sintéticas em tmp_path: hardlinks, symlinks, permissão negada, arquivos
ocultos, árvore grande; seleção tri-state e conjunto mínimo; caminhos protegidos
bloqueados; exclusão com Gio falso; reverificação na execução; nenhum teste usa o home real.

ENTREGA POR FASE
O que mudou, evidência (testes ou script headless), riscos e o que NÃO foi verificado.
Se algo exigir violar uma invariante, pare e pergunte.
