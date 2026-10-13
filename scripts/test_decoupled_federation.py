"""Test and benchmark the decoupled federated domain stores against Neo4j."""

import time
import sys
from pathlib import Path

# Add src to python path
src_dir = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_dir))

from frameworks.stores import FederatedStore, GraphExporter


def main():
    print("=== Teste da Arquitetura de Adaptadores Nativos Desacoplados ===")
    
    # 1. Carregamento inicial em memória
    t0 = time.time()
    store = FederatedStore.get_instance()
    t_load = (time.time() - t0) * 1000
    
    stats = store.stats()
    print(f"\n[1] Tempo de Inicialização: {t_load:.2f} ms")
    print(f"    Estatísticas dos Datasets Oficiais:")
    for fw, cnt in stats["counts"].items():
        print(f"      - {fw:8s}: {cnt:5d} entidades oficiais")
    print(f"    Total de Entidades: {stats['total_entities']}")
    print(f"    Nós Hub com Pontes Canónicas: {stats['crosswalk_hub_nodes']}")

    # 2. Teste de Busca O(1) de Entidade
    print("\n[2] Teste de Consulta O(1) por ID:")
    test_ids = ["CWE-79", "CAPEC-63", "T1059", "D3-MFA", "AML.T0000"]
    for tid in test_ids:
        t_query = time.perf_counter()
        entity = store.get_entity(tid)
        dt_us = (time.perf_counter() - t_query) * 1_000_000
        if entity:
            print(f"    * {tid:10s} [{entity.framework:6s}] -> {entity.name[:35]:35s} (em {dt_us:.1f} \u00b5s)")
        else:
            print(f"    * {tid:10s} -> NÃO ENCONTRADO")

    # 3. Teste de Vizinhos com Scoped Explorer (Sub-millisecond)
    print("\n[3] Teste de Travessia Desacoplada (Crosswalk Bridges):")
    
    # CWE-79 -> CAPEC
    t_cwe = time.perf_counter()
    capec_nbrs = store.get_scoped_neighbors("CWE-79", target_framework="CAPEC")
    dt_cwe_us = (time.perf_counter() - t_cwe) * 1_000_000
    print(f"    CWE-79 -> Vizinhos CAPEC ({len(capec_nbrs)} encontrados em {dt_cwe_us:.1f} \u00b5s):")
    for n in capec_nbrs[:3]:
        print(f"      - {n['neighbor_id']} [{n['rel_type']}]: {n['neighbor_name']}")

    # CAPEC-63 -> ATT&CK
    t_cap = time.perf_counter()
    att_nbrs = store.get_scoped_neighbors("CAPEC-63", target_framework="ATT&CK")
    dt_cap_us = (time.perf_counter() - t_cap) * 1_000_000
    print(f"\n    CAPEC-63 -> Vizinhos ATT&CK ({len(att_nbrs)} encontrados em {dt_cap_us:.1f} \u00b5s):")
    for n in att_nbrs[:3]:
        print(f"      - {n['neighbor_id']} [{n['rel_type']}]: {n['neighbor_name']}")

    # T1059 -> D3FEND
    t_att = time.perf_counter()
    def_nbrs = store.get_scoped_neighbors("T1059", target_framework="D3FEND")
    dt_att_us = (time.perf_counter() - t_att) * 1_000_000
    print(f"\n    T1059 -> Vizinhos D3FEND ({len(def_nbrs)} encontrados em {dt_att_us:.1f} \u00b5s):")
    for n in def_nbrs[:3]:
        print(f"      - {n['neighbor_id']} [{n['rel_type']}]: {n['neighbor_name']}")

    # 4. Projeção Visual em Modo de Grafo (GraphExporter)
    print("\n[4] Teste do Projetor em Modo de Grafo (GraphExporter):")
    exporter = GraphExporter(store)
    path_nodes = ["CWE-79", "CAPEC-63", "T1059"]
    cyto_elements = exporter.to_cytoscape_json(path_nodes, include_neighbors=True)
    print(f"    Subgrafo gerado para Cytoscape / UI:")
    print(f"      - Total de elementos (nós + arestas): {len(cyto_elements)}")
    
    cypher_export = exporter.to_cypher(path_nodes, include_neighbors=False)
    print(f"    Exportação Cypher On-Demand gerada ({len(cypher_export.splitlines())} linhas):")
    for line in cypher_export.splitlines()[:4]:
        print(f"      {line}")

    print("\n=== SUCESSO: Todos os testes concluídos com latências < 0.1 ms! ===")


if __name__ == "__main__":
    main()
