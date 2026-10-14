"""
Benchmark & Validation: Jev Early Prune Guard & Dead-End Elimination.

Tests the System 1 capability to:
1. Cut inviable branches early (poda precoce).
2. Eliminate zero-defense dead ends before expanding downstream.
3. Detect contextual and adversarial traps (e.g. physical tampering in a Cloud API scenario).
4. Quantify calls and tokens saved while preserving ground-truth defenses (zero false negatives).
"""

import json
import os
import sys
import time
from pathlib import Path
from dataclasses import asdict

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.frameworks.stores.federated_store import FederatedStore
from src.frameworks.jev_budget import get_client
from src.graph_search.pruning_search import PruningGuardSearch


SCENARIOS = [
    {
        "id": "case_1_idor",
        "title": "TinyTask Multi-Tenant IDOR (Authorization Bypass)",
        "scenario": (
            "An authenticated member in Workspace A manipulates the URL parameter "
            "`/api/v1/workspaces/ws_987/members` with the ID of Workspace B (`ws_123`) "
            "to modify access control lists and elevate user privileges across tenant boundaries."
        ),
        "target_asset": "Workspace Member Access Control List & Role Bindings",
        "actor": "Authenticated user with standard 'Viewer' role in Workspace A",
        "initial_cwe": "CWE-285",
        "ground_truth_defenses": ["D3-AZET", "D3-SU", "D3-SWI", "D3-AVE"]
    },
    {
        "id": "case_2_ssrf",
        "title": "Cloud-Native SSRF to IMDSv2 Credentials Exfiltration",
        "scenario": (
            "A malicious actor submits a crafted URL `http://169.254.169.254/latest/meta-data/` "
            "into a PDF generation microservice input to query the cloud instance metadata service "
            "and exfiltrate temporary IAM role session tokens."
        ),
        "target_asset": "Cloud Instance Metadata Service (IMDS) & IAM Session Tokens",
        "actor": "External unauthenticated attacker with web service input access",
        "initial_cwe": "CWE-918",
        "ground_truth_defenses": ["D3-ITF", "D3-NTA", "D3-IRA"]
    },
    {
        "id": "case_3_supply_chain",
        "title": "CI/CD Pipeline Dependency Confusion & Poisoning",
        "scenario": (
            "An attacker registers a malicious public package matching an internal private module name. "
            "The automated build runner fetches and executes the integrity-compromised package, "
            "injecting a backdoor into production container artifacts."
        ),
        "target_asset": "Automated Build Worker & Production Container Registry",
        "actor": "External adversary targeting open-source supply chain namespaces",
        "initial_cwe": "CWE-494",
        "ground_truth_defenses": ["D3-SWI", "D3-SU"]
    },
    {
        "id": "case_4_prompt_injection",
        "title": "Indirect Prompt Injection in Customer Support Agent",
        "scenario": (
            "An adversary places hidden prompt injection instructions inside a shared invoice PDF. "
            "When the enterprise LLM assistant processes the document to summarize costs, it executes "
            "the embedded adversarial instructions, triggering unauthorized tool execution."
        ),
        "target_asset": "LLM Assistant Tool Execution Engine & Internal CRM API",
        "actor": "External client submitting untrusted business documents",
        "initial_cwe": "CWE-20",
        "ground_truth_defenses": ["D3-MFA", "D3-IRA", "D3-FE"]
    }
]


def main():
    print("=" * 80)
    print("  JEV EARLY PRUNE GUARD & DEAD-END ELIMINATION BENCHMARK")
    print("=" * 80)

    is_mock = "--mock" in sys.argv or not bool(os.getenv("TYPESAFE_API_KEY") or os.getenv("API_JEV"))
    if is_mock:
        print("[*] Running in Calibrated Mock Mode (no live API key required).")
    else:
        print("[*] Running in Live TypeSafe Jev API Mode.")

    store = FederatedStore.get_instance()
    client = get_client(site="pruning_benchmark", mock=is_mock)
    searcher = PruningGuardSearch(store=store, client=client)

    scenario_results = []
    total_unpruned = 0
    total_pruned = 0
    total_traps_injected = 0
    total_traps_pruned = 0
    total_false_negatives = 0

    for idx, sc in enumerate(SCENARIOS, 1):
        print(f"\n[{idx}/4] Avaliando: {sc['title']}")
        print(f"      Ponto de Partida: {sc['initial_cwe']} -> Alvos Defensivos: {', '.join(sc['ground_truth_defenses'])}")

        res = searcher.run_benchmark(
            incident_ctx=sc,
            initial_cwe=sc["initial_cwe"],
            ground_truth_targets=sc["ground_truth_defenses"],
            inject_traps=True
        )

        total_unpruned += res.unpruned_expansions
        total_pruned += res.pruned_expansions
        total_traps_injected += res.traps_injected
        total_traps_pruned += res.traps_pruned
        total_false_negatives += res.false_negative_count

        print(f"      [Expansões] Cego: {res.unpruned_expansions} | Jev Guard: {res.pruned_expansions} (Poupança: {res.savings_percent}%)")
        print(f"      [Armadilhas] {res.traps_pruned}/{res.traps_injected} podadas ({res.trap_detection_rate}%)")
        print(f"      [Falsos Negativos] {res.false_negative_count} (Alvo Alcançado: {res.target_reached})")
        print(f"      [Ramos Podados] {len(res.pruned_branches)} ramos cortados precocemente")

        res_dict = {
            "id": sc["id"],
            "title": res.incident_title,
            "initial_cwe": res.initial_cwe,
            "target_d3fend": res.target_d3fend,
            "unpruned_expansions": res.unpruned_expansions,
            "pruned_expansions": res.pruned_expansions,
            "expansions_saved": res.expansions_saved,
            "savings_percent": res.savings_percent,
            "unpruned_dead_ends": res.unpruned_dead_ends,
            "pruned_dead_ends_prevented": res.pruned_dead_ends_prevented,
            "traps_injected": res.traps_injected,
            "traps_pruned": res.traps_pruned,
            "trap_detection_rate": res.trap_detection_rate,
            "false_negative_count": res.false_negative_count,
            "target_reached": res.target_reached,
            "surviving_paths": res.surviving_paths,
            "pruned_branches": [asdict(b) for b in res.pruned_branches],
            "total_time_ms": res.total_time_ms,
            "avg_decision_latency_ms": res.avg_decision_latency_ms
        }
        scenario_results.append(res_dict)

    overall_savings = round(((total_unpruned - total_pruned) / max(1, total_unpruned)) * 100, 1)
    overall_trap_rate = round((total_traps_pruned / max(1, total_traps_injected)) * 100, 1)

    print("\n" + "=" * 80)
    print("  RESUMO GLOBAL DO BENCHMARK")
    print("=" * 80)
    print(f"  Expansões Sem Poda (Baseline Cega) : {total_unpruned}")
    print(f"  Expansões com Jev Early Guard     : {total_pruned}")
    print(f"  Poupança Global de Chamadas/Nós   : {overall_savings}%")
    print(f"  Taxa de Deteção de Armadilhas     : {overall_trap_rate}% ({total_traps_pruned}/{total_traps_injected})")
    print(f"  Falsos Negativos (Caminhos Válidos Perdidos) : {total_false_negatives}")

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": "mock" if is_mock else "live_typesafe_api",
        "overall_metrics": {
            "total_unpruned_expansions": total_unpruned,
            "total_pruned_expansions": total_pruned,
            "total_expansions_saved": total_unpruned - total_pruned,
            "overall_savings_percent": overall_savings,
            "total_traps_injected": total_traps_injected,
            "total_traps_pruned": total_traps_pruned,
            "overall_trap_detection_rate": overall_trap_rate,
            "total_false_negatives": total_false_negatives,
            "zero_false_negatives_verified": total_false_negatives == 0
        },
        "scenarios": scenario_results
    }

    # Save report for Web App
    out_public = ROOT / "web" / "public" / "pruning_report.json"
    out_dist = ROOT / "web" / "dist" / "pruning_report.json"
    for out_path in [out_public, out_dist]:
        if out_path.parent.exists():
            out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[+] Relatório de Poda e Eliminação de Becos exportado para {out_public}")


if __name__ == "__main__":
    main()
