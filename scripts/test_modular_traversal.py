"""Test complete multi-hop traversal using ModularOrchestrator."""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sys
sys.stdout.reconfigure(encoding="utf-8")
from src.frameworks.orchestrator import ModularOrchestrator


def run():
    orchestrator = ModularOrchestrator()
    start_node = "CAPEC-1"
    goal = "Find the D3FEND defensive countermeasure or verification technique that mitigates software file permissions or access control weaknesses."
    
    current = start_node
    path = [start_node]
    max_hops = 4

    print("=" * 70)
    print("🚀 TESTE DE TRAVESSIA MODULAR COM JEV (SYSTEM 1)")
    print(f"🎯 Nó Inicial: {start_node}")
    print(f"📋 Meta: {goal}")
    print("=" * 70)

    for hop_num in range(1, max_hops + 1):
        print(f"\n--- [Salto #{hop_num}] Nó Atual: {current} ---")
        result = orchestrator.execute_hop(current, path, goal)

        if result.get("status") == "dead-end":
            print(f"❌ {result.get('message')}")
            break

        r_info = result["level_1_router"]
        e_info = result["level_2_explorer"]

        print(f"  [Nível 1 - Meta-Router] Latência: {r_info['latency_ms']:.1f}ms")
        print(f"     Domínio Atual: {r_info['current_framework']} ➔ Decisão: {r_info['router_decision']}")
        print(f"     Candidatos: {list(r_info['candidates'].keys())}")

        print(f"  [Nível 2 - Template {e_info['template_used']}] Latência: {e_info['jev_time_ms']:.1f}ms")
        print(f"     Ramo Escolhido: {e_info['chosen_branch_key']} ➔ {result['next_node']} ({result['next_node_label']})")
        print(f"     Confiança Meta (Noul): {result['noul_goal']:.1%}")
        print(f"     Score Heurístico: {result['heuristic_score']:.2f}")

        current = result["next_node"]
        path.append(current)

        if result["goal_reached"]:
            print(f"\n🎉 META ATINGIDA com {result['noul_goal']:.1%} de confiança no nó defensivo {current}!")
            break

    print("\n" + "=" * 70)
    print("🏁 Caminho Percorrido:")
    print(" ➔ ".join(path))
    print("=" * 70)

    orchestrator.close()


if __name__ == "__main__":
    run()
