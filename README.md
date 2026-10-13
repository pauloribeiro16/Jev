# Jev Semantic Graph Explorer — Threat Intelligence

Repositório de experimentação e investigação sobre travessia probabilística de grafos de cibersegurança usando o motor de inferência **Jev (TypeSafe AI — System 1)** integrado com o **Neo4j**.

---

## 1. Visão Geral

Ao contrário de abordagens com LLMs convencionais ("System 2"), que geram texto de forma lenta, propensa a alucinações de nós e de elevado custo por token, o **Jev** executa micro-julgamentos estruturados e probabilísticos em menos de 50ms:
* **`Noul` (Avaliação Booleana / Critério de Paragem):** Avalia a probabilidade de o nó atual satisfazer o objetivo semântico pretendido.
* **`Choice` (Seleção Categórica de Ramos):** Escolhe deterministicamente qual das arestas adjacentes no Neo4j é a mais promissora para o salto seguinte.
* **`Score` (Função Heurística $h(n)$):** Atribui uma pontuação ordinal de alinhamento com a meta para guiar algoritmos informados (A* ou Best-First Search).

---

## 2. Grafo de Conhecimento de Cibersegurança

O Neo4j contém a integração das principais ontologias técnicas de segurança:
* **CWE (Common Weakness Enumeration):** 969 fraquezas de software (CWE v4.19).
* **ATT&CK (MITRE Enterprise ATT&CK):** 836 técnicas e subtécnicas adversárias.
* **CAPEC (Common Attack Pattern Enumeration):** 615 padrões de ataque.
* **D3FEND (MITRE D3FEND):** 466 contramedidas defensivas.
* **AEGIS SubDomains & Domains:** 52 nós de pontes taxonómicas.
* **Relações Cross-Framework:**
  * `(CAPEC)-[:EXPLOITS]->(CWE)` (1.212 relações)
  * `(D3FEND)-[:MITIGATES]->(ATTACK)` (3.234 relações)
  * `(CAPEC)-[:MAPS_TO_ATTACK]->(ATTACK)` (271 relações)
  * `(*)-[:MAPS_TO_SUBDOMAIN]->(SubDomain)` (5.121 relações)

---

## 3. Estrutura do Repositório

```text
.
├── .env.example              # Exemplo de variáveis de ambiente
├── AGENTS.md                 # Diretrizes para agentes de IA
├── README.md                 # Documentação do projeto
├── requirements.txt          # Dependências Python
├── app/
│   └── graph_ui.py           # Interface Web Streamlit interativa (Vis.js + Inspector)
├── data/
│   └── tinytask_kg.cypher    # Grafo sintético inicial de referência
├── manuscritos/
│   ├── 01_traversal_confidence_analysis.md  # Manuscrito #01: Calibração de confiança
│   └── 02_threat_modeling_cwe_capec_mitre.md # Manuscrito #02: Ontologias de ameaças
├── scripts/
│   ├── enrich_threat_modeling_graph.py      # Script de povoamento e ligações cross-framework
│   ├── test_threat_hop.py                   # Teste de 1 salto semântico no grafo de ameaças
│   └── sync_react_changes.py                # Sincronização com o Template_React
└── src/
    └── graph_search/         # Algoritmos de busca em grafos
```

---

## 4. Configuração e Instalação

### Pré-requisitos
* Python 3.10+
* Instância ativa do Neo4j (`bolt://localhost:7687`)
* Chave de API da TypeSafe AI (`API_JEV`)

### Passos:
```bash
# 1. Criar e ativar ambiente virtual
python -m venv .venv
source .venv/bin/activate  # ou .venv\Scripts\activate no Windows

# 2. Instalar dependências
pip install -r requirements.txt

# 3. Configurar variáveis de ambiente
cp .env.example .env
# Preencha API_JEV e credenciais do Neo4j no .env
```

---

## 5. Executar o Visualizador Interativo

```bash
streamlit run app/graph_ui.py
```
Acesse a aplicação no navegador em **`http://localhost:8501`**.

---

## 6. Versão Full-Stack (React 19 + TypeScript + Express)

Para a versão full-stack com React e Express (disponível no repositório `Template_React`):
* **Frontend:** `http://localhost:5173` (Vite, React 19, vis-network, TanStack Query)
* **Backend:** `http://localhost:3000` (Express, neo4j-driver, TypeSafe SDK)
