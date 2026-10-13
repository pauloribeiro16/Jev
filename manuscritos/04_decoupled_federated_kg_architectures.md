# Manuscrito #04: Arquiteturas de Grafos Desacoplados vs. Monolito Neo4j

**Data:** 13 de Outubro de 2026  
**Autor:** TypeSafe AI / Jev Threat Intelligence Lab  
**Objetivo:** Estudar as diferentes abordagens para organizar ontologias de cibersegurança heterogéneas (CWE, CAPEC, ATT&CK, ATLAS, D3FEND): Grafo Monolítico Centralizado vs. Grafos Desacoplados Nativos em Ficheiro/Memória.

---

## 1. O Problema do Grafo Gigante Monolítico

No início deste projeto, todos os 5 frameworks foram consolidados numa única base de dados Neo4j (3.105 nós, 12.600 arestas). A experiência prática e os benchmarks de inferência revelaram 4 problemas estruturais:

1. **Poluição do Espaço de Busca (Semantic Clutter):**
   - Ao expandir os vizinhos de um nó como `CAPEC-1`, o motor de busca do Neo4j devolve simultaneamente nós de tipos ontológicos incompatíveis: técnicas operacionais (`ATTACK`), vulnerabilidades de código (`CWE`) e domínios taxonómicos genéricos (`SubDomain`).
   - Para o modelo probabilístico System 1 (Jev), isto cria uma distribuição de probabilidades distorcida e ruidosa na primitiva `Choice`.

2. **Perda de Proveniência e Schema Mutilado:**
   - Cada framework oficial foi concebido com uma linguagem nativa diferente:
     - **ATT&CK e CAPEC:** STIX 2.1 JSON (objetos SDO e relações SRO com carimbos temporais, plataformas, fontes de dados e revogações).
     - **D3FEND:** W3C OWL/RDF (ontologia formal de classes de engenharia de segurança).
     - **CWE:** XML hierárquico / JSON (vistas canónicas de pesquisa e desenvolvimento).
   - Ao forçar tudo para um único formato de nó plano no Neo4j, propriedades ricas oficiais (como procedimentos, mitigações detalhadas e exemplos de código) foram perdidas ou reduzidas a chaves esparsas com campos nulos.

3. **Overhead Desnecessário de Infraestrutura e Latência:**
   - O Neo4j requer um processo Java dedicado (consumindo 1-2 GB de RAM e portas de rede).
   - O protocolo Bolt adiciona **15 a 45 ms** de latência de serialização em cada salto, o que rivaliza ou supera o tempo de inferência do próprio modelo Jev (sub-50 ms).

---

## 2. Análise Comparativa das Abordagens

| Critério | Abordagem A: Monolito Centralizado (Neo4j Atual) | Abordagem B: Adaptadores Nativos Desacoplados (Memória / JSON / STIX) | Abordagem C: Grafos Embarcados (KùzuDB / SQLite) |
| :--- | :--- | :--- | :--- |
| **Infraestrutura** | Pesada (requer servidor Neo4j ativo, JVM, portas de rede, autenticação). | **Zero** (corre 100% local em ficheiros JSON/STIX e Python/TypeScript). | Leve (ficheiro `.db` local, sem servidor). |
| **Latência por Busca** | 15 ms – 45 ms (protocolo Bolt + Cypher parsing). | **< 0.1 ms** (pesquisa indexada em dicionário em memória RAM). | 1 ms – 5 ms (queries em disco/memória local). |
| **Fidelidade com a Origem** | Baixa (schema ad-hoc; perde propriedades da versão oficial). | **100% Canónica** (usa os ficheiros JSON/STIX originais emitidos pela MITRE/CISA). | Média (requer conversão de schema). |
| **Atualização de Versão** | Complexa (requer scripts de ingestão e reconciliação de arestas). | **Instantânea** (basta descarregar o novo `.json` da MITRE e reiniciar). | Moderada (reimportação de tabelas). |
| **Consumo de Memória** | 1.5 GB – 3.0 GB (JVM do Neo4j). | **~120 MB – 160 MB** (toda a taxonomia agregada cabe em RAM limpa). | ~100 MB – 200 MB. |
| **Orquestração pelo Jev** | O Jev filtra os resultados de uma query monolítica heterogénea. | **O Jev orquestra a federação:** escolhe a quem perguntar e consulta o módulo certo. | O Jev consulta tabelas relacionais ou grafos locais. |

---

## 3. A Abordagem Recomendada: "Barramento Federado de Adaptadores Nativos"

Em vez de transformar forçadamente todos os formatos num só grafo Neo4j, mantemos cada framework no seu **formato nativo oficial**, com um **Adaptador de Domínio** leve:

```
                                  ┌──────────────────────────────┐
                                  │      OBJECTIVO DO JEV        │
                                  └──────────────┬───────────────┘
                                                 │
                                  ┌──────────────▼───────────────┐
                                  │   META-ROUTER DO JEV (S1)    │
                                  │   (Orquestrador Federado)    │
                                  └──────────────┬───────────────┘
                                                 │
            ┌──────────────────┬─────────────────┼─────────────────┬──────────────────┐
            ▼                  ▼                 ▼                 ▼                  ▼
   ┌────────────────┐ ┌────────────────┐ ┌───────────────┐ ┌────────────────┐ ┌────────────────┐
   │   CWE Store    │ │  CAPEC Store   │ │ ATT&CK Store  │ │  D3FEND Store  │ │  ATLAS Store   │
   │  (MITRE JSON)  │ │ (STIX 2.1 JSON)│ │(STIX 2.1 JSON)│ │  (OWL / JSON)  │ │  (STIX / YAML) │
   └───────┬────────┘ └───────┬────────┘ └───────┬───────┘ └───────┬────────┘ └───────┬────────┘
           │                  │                  │                 │                  │
           └──────────────────┴─────────▲────────┴─────────────────┴──────────────────┘
                                        │
                         ┌──────────────┴───────────────┐
                         │   TABELA CANÓNICA DE PONTES  │
                         │   • CWE ➔ CAPEC (exploitedBy)│
                         │   • CAPEC ➔ ATT&CK (leadsTo) │
                         │   • D3FEND ➔ ATT&CK(mitigates│
                         └──────────────────────────────┘
```

### Como funcionam os Adaptadores Nativos:

1. **`CWEStore`:**
   - Carrega `cwec_latest.json`.
   - Oferece: `get_weakness(id)`, `get_children(id)`, `get_parent(id)`, `get_related_capec(id)`.
2. **`CAPECStore`:**
   - Carrega `capec.json` (STIX 2.1).
   - Oferece: `get_attack_pattern(id)`, `get_execution_flow(id)`, `get_cwe_ids(id)`, `get_attack_ids(id)`.
3. **`AttackStore`:**
   - Carrega `enterprise-attack.json` (STIX 2.1).
   - Oferece: `get_technique(id)`, `get_subtechniques(id)`, `get_tactics(id)`.
4. **`D3FENDStore`:**
   - Carrega `d3fend.json`.
   - Oferece: `get_artifact(id)`, `get_mitigations(attack_id)`.
5. **`AtlasStore`:**
   - Carrega `ATLAS.json` (STIX 2.1).
   - Oferece técnicas e vetores adversários para modelos de IA/ML.

---

## 4. Conclusão

Desacoplar o grafo gigante em **adaptadores de domínio nativos** é a melhor decisão técnica e arquitetural:
1. Elimina a necessidade de manter o Neo4j a correr em background.
2. Elimina a perda de propriedades e atributos canónicos das especificações do MITRE.
3. Reduz a latência de busca para **<0.1 ms**, tornando o loop do Jev puramente limitado pela velocidade de inferência.
4. Concede ao Meta-Router do Jev o seu verdadeiro papel: um **motor de inferência federado** que decide quem consultar, como consultar e como sintetizar a inteligência de ameaças.
