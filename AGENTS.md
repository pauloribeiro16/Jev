# AGENTS.md — Diretrizes e Contexto do Repositório (Jev Playground)

Este repositório destina-se à experimentação, testes de desempenho e desenvolvimento de casos de uso práticos com o **Jev** (modelo "System 1" de decisão probabilística da **TypeSafe AI**), com foco especial em **algoritmos de procura em grafos**, **orquestração de agentes (state graphs)** e **decisões estruturadas em tempo real**.

---

## 1. Visão Geral do Jev

O **Jev** foi concebido como um motor de inferência probabilístico rápido ("System 1") em vez de um modelo gerador de texto ("System 2"):
* **Sem geração de prosa:** Avalia um estado (`state`) contra questões tipadas (`questions`) e devolve diretamente valores probabilísticos e decisões estruturadas.
* **Baixa latência e custo reduzido:** Ideal para loops rápidos de execução ("hot loops"), heurísticas e filtragem onde LLMs tradicionais são lentos e dispendiosos.
* **Primitivas Fundamentais:**
  * `Noul`: Julgamento booleano / verificação de verdade com probabilidade associada (`True`/`False` + confiança).
  * `Choice`: Seleção categórica entre múltiplos ramos, ferramentas ou caminhos candidatos.
  * `Score`: Avaliação ordinal/numérica de relevância ou pontuação heurística segundo critérios definidos.

---

## 2. Configuração e Dependências

* **Python:** 3.10+ recomendado.
* **SDK Oficial:** `typesafe-sdk` (com suporte opcional a HTTP/2 via `typesafe-sdk[http2]`).
* **Variáveis de Ambiente:**
  * `TYPESAFE_API_KEY`: Chave da API TypeSafe AI definida em `.env` ou nas variáveis do sistema.

### Exemplo Básico de Uso:
```python
import os
from dotenv import load_dotenv
from typesafe_sdk import TypeSafeClient, Noul, Choice, Score

load_dotenv()

with TypeSafeClient() as client:
    response = client.system_one(
        state={"node": "Conceito A", "meta": "Informação de contexto"},
        questions={
            "is_goal": Noul(instructions="O nó atual satisfaz o objetivo da pesquisa?"),
            "next_step": Choice(
                instructions="Qual o melhor ramo a explorar a seguir?",
                criteria={"aresta_1": "Ramo rápido", "aresta_2": "Ramo detalhado"}
            ),
            "heuristic_value": Score(
                instructions="Quão promissora é esta direção em relação ao alvo?",
                criteria=["baixa promessa", "média promessa", "alta promessa"]
            )
        }
    )
```

---

## 3. Áreas de Foco e Casos de Uso no Repositório

### A. Procura e Travessia em Grafos (Graph Search & Heuristics)
* **Função Heurística em Algoritmos Informados (A*, Best-First, Beam Search):**
  * Utilizar `Score` para calcular dinamicamente o valor heurístico $h(n)$ de nós semânticos.
* **Poda e Seleção de Arestas (`Choice`):**
  * Em grafos densos (como ontologias ou bases de conhecimento tipo Neo4j / Knowledge Graphs), selecionar os ramos mais promissores a expandir.
* **Critério de Paragem / Meta (`Noul`):**
  * Avaliar se um nó ou caminho atual atinge as condições pretendidas antes de continuar a travessia.
* **Ponderação Dinâmica de Arestas:**
  * Atribuição de pesos e confiança a relações semânticas em tempo de execução.

### B. State Graphs e Orquestração de Agentes (JevGraph / LangGraph)
* Substituição de chamadas ReAct pesadas por nós de decisão rápida em grafos de fluxo de trabalho.
* Roteamento condicional determinístico com classificação instantânea.
* Guardrails e avaliação de segurança antes da execução de ferramentas.

### C. GraphRAG e Filtragem de Recuperação
* Filtragem rápida de subgrafos e nós relevantes antes de enviar o contexto para um LLM gerador.

---

## 4. Estrutura Recomendada do Projeto

```text
.
├── .env                  # Chaves de API (ignorado no git)
├── AGENTS.md             # Instruções e diretrizes para agentes
├── requirements.txt      # Dependências do projeto
├── src/
│   ├── graph_search/     # Algoritmos de busca (A*, Beam Search, BFS semântico)
│   ├── heuristics/       # Definições de heurísticas com primitivas Jev
│   └── workflows/        # Grafos de estado / fluxos de agentes
├── tests/                # Testes unitários e mocks
└── benchmarks/           # Métricas de latência e custo vs LLMs tradicionais
```

---

## 5. Diretrizes para Agentes de IA que Trabalhem neste Repo

1. **Separação de Responsabilidades:** Manter a lógica determinística dos grafos (estruturas de dados, fila de prioridade, nós, arestas) em código Python puro; usar o Jev exclusivamente para os micro-julgamentos probabilísticos.
2. **Tratamento de Mocks:** Sempre que desenvolver testes ou scripts executáveis sem uma chave de API ativa, providenciar mecanismos de fallback ou mocks do `TypeSafeClient` para validação de pipeline offline.
3. **Métricas de Desempenho:** Sempre que implementar um algoritmo de busca, medir o tempo por expansão de nó e comparar com abordagens puramente simbólicas ou com LLMs convencionais.
4. **Formulação Clara de Questões:** Manter os prompts e critérios de `Noul`, `Choice` e `Score` curtos, objetivos e bem calibrados para maximizar a precisão do modelo System 1.
