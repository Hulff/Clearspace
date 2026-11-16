# Clearspace: assistente local de baixo consumo (6 GB de RAM)

Plano de ajuste do assistente com LLM local para uma máquina com apenas 6 GB de RAM, com o objetivo de consumir o mínimo necessário.

## Contexto

Com 6 GB no total, o desktop e o editor já ocupam boa parte da memória. O plano anterior (Qwen via Ollama, com RAG sobre pastas escolhidas pelo usuário) precisa ser reduzido: modelo menor, carregamento sob demanda e busca sem embeddings no início.

## Modelo

- **Padrão: `qwen3.5:0.8b`.** Pela regra de bolso de cerca de 0,6 GB por bilhão de parâmetros na quantização padrão do Ollama (Q4\_K\_M), o peso fica em torno de 0,5 GB, mais o cache de contexto. Um tutorial também indica o 0.8b para máquinas com pouca RAM.
- **Opcional: 2B**, apenas se `MemAvailable` estiver folgado no momento de carregar.
- **Evitar o 4B como padrão.** Ele sozinho ocupa cerca de 3,4 GB, o que dispara swap nessa máquina.
- **Formato de saída:** modelos de 0.8B perdem aderência a esquemas JSON com facilidade. Usar saída estruturada com schema, validar em código e ter respostas prontas como fallback.
- Confirmar o tag exato em ollama.com/library antes de fixar no código, pois os nomes mudam entre versões.

## Regras para consumir o mínimo

1. **LLM opcional e sob demanda.** O `LocalRuleAssistant` responde a maioria das perguntas (maiores itens, risco, procedimento) com templates, sem modelo. O LLM só entra em explicações livres.
2. **Carregar só quando preciso.** Usar `keep_alive` curto (ou `0`) para o Ollama descarregar o modelo logo após a resposta.
3. **Checar a RAM antes.** Ler `MemAvailable` em `/proc/meminfo`; abaixo de um limite, não carregar o modelo e mostrar "memória insuficiente" com o fallback em regras.
4. **Contexto pequeno.** `num_ctx` entre 1024 e 2048 e no máximo 3 a 5 chunks recuperados. É o contexto que mais cresce em memória.
5. **Sem modelo de embedding no começo.** Usar só FTS5 (SQLite). Um segundo modelo residente é inviável nessa RAM. Se embeddings entrarem depois, devem ser opt-in, carregados e descarregados em lote durante a indexação, nunca ao mesmo tempo que o chat.
6. **Indexação enxuta.** Fichas de pasta e metadados por padrão. Conteúdo apenas das pastas escolhidas, em lotes pequenos, com baixa prioridade (`nice`/`ionice`) e pausando se a memória cair.
7. **Servidor sob demanda.** Não deixar o `ollama serve` residente. O app pode iniciá-lo como o próprio usuário (lista de argumentos, sem shell) quando o chat for aberto e encerrá-lo ao fechar. Deve ser uma opção, sem sudo nem systemd de sistema.
8. **Scanner e UI leves.** Não manter a árvore inteira em memória. O carregamento preguiçoso e os agregados "N itens menores" já ajudam.
9. **Dica ao usuário.** zram ou swap ajudam, mas não substituem a checagem de RAM do item 3.

## Mudanças nas fases do plano

- **Fase 1:** cliente Ollama com `keep_alive`, `num_ctx`, checagem de RAM e start/stop sob demanda.
- **Fase 2:** respostas em regras primeiro; LLM só para o texto livre.
- **Fases 3 e 4:** apenas FTS5, com indexação em lotes e pausável.
- **Fase 5 (embeddings):** adiada e opt-in.
- **Fase 6:** avaliação inclui medir o pico de RAM com o modelo carregado.

## Próximo passo

Escrever o prompt para o Codex implementar as fases em ordem, já com essas restrições de memória e o paralelismo definido no `AGENTS.md`.

## Fontes

- Tutorial freeCodeCamp sobre Ollama e Qwen (tamanho do qwen3.5:4b e uso do 0.8b em pouca RAM).
- BenchLM, "Best Ollama Models" (regra de bolso de memória por parâmetro na quantização Q4\_K\_M e recomendação de verificar o tag exato).
- Comentários no Product Hunt sobre a série Qwen3.5 Small (tamanhos 0.8B, 2B, 4B e 9B e confiabilidade de JSON em modelos muito pequenos).
