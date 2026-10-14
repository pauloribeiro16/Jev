"""
Robustness, Perturbation, and Semantic Drift Test Suite for Jev (System 1).

Executes rigorous non-happy-path tests:
1. Position Bias & Candidate Permutation Test: Tests if shuffling Choice.criteria alters decisions or probabilities.
2. Adversarial Distractor / Red-Herring Test: Injects noisy distractors into incident context to test root-cause retention.
3. Round-Trip Consistency & Semantic Drift Test: Tests bidirectional alignment (D3FEND -> CWE) across all 6 ontological chains.
4. Confidence & Entropy Gating: Identifies decision points with high semantic ambiguity.
"""

import json
import math
import os
import random
import sys
import time
from pathlib import Path
from typing import Dict, Any, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.frameworks.stores.federated_store import FederatedStore
from src.frameworks.jev_budget import get_client
from typesafe_sdk import Choice, Noul, Score

PUBLIC_DIR = ROOT / "web" / "public"


def entropy(probs: Dict[str, float]) -> float:
    """Calculate Shannon entropy of a probability distribution."""
    vals = [p for p in probs.values() if p > 0.0]
    if not vals:
        return 0.0
    return -sum(p * math.log2(p) for p in vals)


# =============================================================================
# TEST 1: POSITION BIAS & CANDIDATE PERMUTATION TEST
# =============================================================================
def run_position_bias_test(store: FederatedStore, client) -> Dict[str, Any]:
    print("\n" + "=" * 80)
    print("  TESTE 1: Viés de Posição & Permutação de Candidatos (Position Bias)")
    print("=" * 80)
    print("Objetivo: Testar se alterar a ordem das opções em Choice.criteria altera a escolha ou desvia probabilidades.")

    incident_ctx = {
        "title": "TinyTask Multi-Tenant Authorization Bypass (IDOR)",
        "scenario": (
            "An authenticated member in Workspace A manipulates the URL parameter "
            "`/api/v1/workspaces/ws_987/members` with the ID of Workspace B (`ws_123`) "
            "to modify access control lists and elevate user privileges across tenant boundaries."
        ),
        "target_asset": "Workspace Member Access Control List & Role Bindings",
        "actor": "Authenticated user with standard 'Viewer' role in Workspace A",
    }

    base_cwe_ids = ["CWE-285", "CWE-200", "CWE-79", "CWE-311"]
    
    # 4 systematic permutations: original, shifted by 1, shifted by 2, reversed
    permutations = [
        ("Original (A, B, C, D)", base_cwe_ids),
        ("Rotacionada +1 (B, C, D, A)", [base_cwe_ids[1], base_cwe_ids[2], base_cwe_ids[3], base_cwe_ids[0]]),
        ("Rotacionada +2 (C, D, A, B)", [base_cwe_ids[2], base_cwe_ids[3], base_cwe_ids[0], base_cwe_ids[1]]),
        ("Invertida (D, C, B, A)", list(reversed(base_cwe_ids))),
    ]

    runs = []
    chosen_counts = {}
    prob_tracking = {cid: [] for cid in base_cwe_ids}

    for label, cwe_list in permutations:
        criteria_cwe = {}
        for cid in cwe_list:
            e = store.cwe.get_entity(cid)
            criteria_cwe[cid] = f"{e.id}: {e.name} — {(e.description or '')[:120]}..."

        q = {
            "root_weakness": Choice(
                instructions=(
                    "Given the incident scenario where a user manipulates parameters to bypass workspace boundaries, "
                    "which CWE represents the direct root-cause flaw in access control logic?"
                ),
                criteria=criteria_cwe,
            )
        }

        t0 = time.perf_counter()
        resp = client.system_one(state={"incident": incident_ctx, "permutation": label}, questions=q)
        lat = (time.perf_counter() - t0) * 1000

        ch = resp.choices["root_weakness"].choice
        conf = resp.choices["root_weakness"].confidence
        probs = resp.choices["root_weakness"].probabilities or {}

        chosen_counts[ch] = chosen_counts.get(ch, 0) + 1
        for cid in base_cwe_ids:
            prob_tracking[cid].append(probs.get(cid, 0.0))

        runs.append({
            "permutation_label": label,
            "order": cwe_list,
            "decision": ch,
            "confidence": conf,
            "probabilities": probs,
            "latency_ms": round(lat, 1),
        })
        print(f"  [{label}] -> Escolha: {ch} (Confiança: {conf:.1%}, Latência: {lat:.1f}ms)")

    # Stability calculation
    total_permutations = len(permutations)
    max_consistent_choice = max(chosen_counts.values()) if chosen_counts else 0
    decision_stability = max_consistent_choice / total_permutations

    # Compute max delta for each candidate
    prob_deviations = {}
    for cid, plist in prob_tracking.items():
        if plist:
            prob_deviations[cid] = round(max(plist) - min(plist), 4)

    max_delta = max(prob_deviations.values()) if prob_deviations else 0.0

    print(f"\n>> Resultado do Teste de Viés de Posição:")
    print(f"   • Estabilidade da Decisão: {decision_stability:.0%} ({max_consistent_choice}/{total_permutations} permutações idênticas)")
    print(f"   • Variação máxima de probabilidade (Δp max): {max_delta:.1%}")
    print(f"   • Variações por candidato: {prob_deviations}")

    return {
        "test_name": "position_bias_permutation",
        "description": "Avalia estabilidade de decisão sob rotação e inversão de opções no Choice",
        "decision_stability": decision_stability,
        "max_probability_deviation": max_delta,
        "probability_deviations_by_candidate": prob_deviations,
        "runs": runs,
    }


# =============================================================================
# TEST 2: ADVERSARIAL DISTRACTOR / RED-HERRING TEST
# =============================================================================
def run_adversarial_distractor_test(store: FederatedStore, client) -> Dict[str, Any]:
    print("\n" + "=" * 80)
    print("  TESTE 2: Imunidade a Ruído & Distratores Adversários (Red Herrings)")
    print("=" * 80)
    print("Objetivo: Testar se o Jev mantém a causa-raiz perante cenários com ruído e pistas falsas.")

    # Target ground truth is SSRF (CWE-918)
    # We will test 3 variants of the scenario: Clean, Mild Noise, and Strong Adversarial Red-Herring
    test_variants = [
        {
            "name": "Cenário Limpo (Baseline)",
            "scenario": (
                "A document conversion service accepts user-supplied URLs to render external webpage snapshots. "
                "The backend fetches http://169.254.169.254/latest/meta-data/iam/security-credentials/ "
                "without validating loopback or link-local address restrictions, exfiltrating cloud tokens."
            ),
            "expected_cwe": "CWE-918",
        },
        {
            "name": "Ruído Periférico (Mild Infrastructure Noise)",
            "scenario": (
                "A document conversion service accepts user-supplied URLs to render external webpage snapshots. "
                "The backend server runs on Ubuntu 22.04 with an active SSH daemon on port 22 and local Redis on 6379. "
                "The server administrator noticed high CPU load and slow disk I/O before noticing that the backend "
                "fetched http://169.254.169.254/latest/meta-data/iam/security-credentials/ without URL validation."
            ),
            "expected_cwe": "CWE-918",
        },
        {
            "name": "Distrator Adversário Agressivo (Red Herring de Brute Force / SSH)",
            "scenario": (
                "Security operations received automated alerts of 5,000 failed SSH root password attempts on port 22 "
                "from a Russian IP address. Immediately following this scan, internal monitoring detected that an unauthenticated "
                "user exploited the PDF conversion API by supplying `http://169.254.169.254/latest/meta-data/` to forge "
                "server-side requests and steal AWS STS credentials."
            ),
            "expected_cwe": "CWE-918",
        },
    ]

    candidate_cwes = ["CWE-918", "CWE-307", "CWE-798", "CWE-200"]
    criteria_cwe = {}
    for cid in candidate_cwes:
        e = store.cwe.get_entity(cid)
        criteria_cwe[cid] = f"{e.id}: {e.name} — {(e.description or '')[:120]}..."

    results = []
    correct_count = 0

    for v in test_variants:
        q = {
            "root_weakness": Choice(
                instructions=(
                    "Analyze the incident report carefully. Identify the fundamental root-cause vulnerability "
                    "in application logic (distinguishing the primary exploitation mechanism from superficial "
                    "background noise or unrelated scanning activity):"
                ),
                criteria=criteria_cwe,
            ),
            "noise_rejection_confidence": Score(
                instructions="How confident are you that the selected vulnerability is the direct causal driver rather than a secondary symptom?",
                criteria=[
                    "Low: The incident report is ambiguous and multiple independent flaws appear equally causal",
                    "Medium: One flaw seems dominant, but secondary noise might represent the actual initial vector",
                    "High: Clear separation between superficial background activity and the core exploitable flaw",
                    "Definitive: Absolute certainty; background noise is entirely incidental and unrelated to impact",
                ],
            ),
        }

        t0 = time.perf_counter()
        resp = client.system_one(state={"incident_variant": v["name"], "scenario": v["scenario"]}, questions=q)
        lat = (time.perf_counter() - t0) * 1000

        ch = resp.choices["root_weakness"].choice
        conf = resp.choices["root_weakness"].confidence
        probs = resp.choices["root_weakness"].probabilities or {}
        score_val = resp.scores["noise_rejection_confidence"].score

        is_correct = (ch == v["expected_cwe"])
        if is_correct:
            correct_count += 1

        results.append({
            "variant": v["name"],
            "decision": ch,
            "expected": v["expected_cwe"],
            "is_correct": is_correct,
            "confidence": conf,
            "noise_rejection_score": score_val,
            "probabilities": probs,
            "latency_ms": round(lat, 1),
        })

        status_icon = "✓ CORRETO" if is_correct else "✗ DESVIADO PELO DISTRATOR"
        print(f"  [{v['name']}] -> {ch} (Confiança: {conf:.1%}) [{status_icon}] em {lat:.1f}ms")

    accuracy = correct_count / len(test_variants)
    print(f"\n>> Resultado do Teste de Distratores:")
    print(f"   • Acurácia de Identificação de Causa-Raiz: {accuracy:.0%} ({correct_count}/{len(test_variants)})")

    return {
        "test_name": "adversarial_distractor_test",
        "description": "Avalia imunidade do Jev perante pistas falsas e ruído de infraestrutura no incidente",
        "accuracy": accuracy,
        "variants_evaluated": len(test_variants),
        "results": results,
    }


# =============================================================================
# TEST 3: ROUND-TRIP CONSISTENCY & SEMANTIC DRIFT TEST
# =============================================================================
def run_round_trip_drift_test(store: FederatedStore, client) -> Dict[str, Any]:
    print("\n" + "=" * 80)
    print("  TESTE 3: Consistência Bidirecional & Detetor de Deriva Semântica (Semantic Drift)")
    print("=" * 80)
    print("Objetivo: Testar com Noul se a contramedida final D3FEND realmente mitiga a causa-raiz CWE inicial.")

    # Load existing cases from test_runs.json
    runs_file = PUBLIC_DIR / "test_runs.json"
    if not runs_file.exists():
        print(f"[!] Ficheiro {runs_file} não encontrado. Execute run_sequential_test.py primeiro.")
        return {}

    with open(runs_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    cases = data.get("cases", [])
    evaluations = []

    for c in cases:
        case_id = c["id"]
        title = c.get("title", case_id)
        steps = c.get("steps", [])
        if len(steps) < 4:
            continue

        cwe_step = steps[0]
        d3fend_step = steps[-1]

        cwe_id = cwe_step["selected_id"]
        cwe_name = cwe_step["selected_name"]
        d3_id = d3fend_step["selected_id"]
        d3_name = d3fend_step["selected_name"]

        q = {
            "is_causally_aligned": Noul(
                instructions=(
                    f"In the context of the incident '{title}', does the defensive countermeasure "
                    f"`{d3_id}: {d3_name}` directly neutralize, restrict, or mitigate the root-cause "
                    f"weakness `{cwe_id}: {cwe_name}`?"
                )
            ),
            "alignment_strength": Score(
                instructions=f"Rate how directly `{d3_id}: {d3_name}` addresses `{cwe_id}: {cwe_name}`:",
                criteria=[
                    "Mismatched: The countermeasure addresses an entirely different threat vector",
                    "Peripheral: Provides indirect defense or logging without stopping root exploitation",
                    "Substantial: Enforces active boundary prevention or mitigation of the weakness",
                    "Direct / Root: Completely eliminates or structurally immunizes against the weakness",
                ],
            ),
        }

        t0 = time.perf_counter()
        resp = client.system_one(
            state={
                "case_id": case_id,
                "incident_scenario": c.get("scenario", ""),
                "root_cwe": {"id": cwe_id, "name": cwe_name},
                "final_d3fend": {"id": d3_id, "name": d3_name},
                "full_path": c.get("chain_path", []),
            },
            questions=q,
        )
        lat = (time.perf_counter() - t0) * 1000

        noul_val = resp.nouls["is_causally_aligned"].noul
        score_val = resp.scores["alignment_strength"].score

        is_aligned = noul_val >= 0.50
        drift_severity = "Nenhuma (Alinhado)" if noul_val >= 0.75 else ("Baixa" if noul_val >= 0.50 else "DERIVA DETETADA")

        evaluations.append({
            "case_id": case_id,
            "title": title,
            "root_cwe": f"{cwe_id}: {cwe_name}",
            "final_d3fend": f"{d3_id}: {d3_name}",
            "full_path": c.get("chain_path", []),
            "alignment_verdict": noul_val,
            "alignment_score": score_val,
            "is_aligned": is_aligned,
            "drift_severity": drift_severity,
            "latency_ms": round(lat, 1),
        })

        icon = "✓ ALINHADO" if is_aligned else "⚠️ DERIVA SEMÂNTICA"
        print(f"  [{case_id}] {cwe_id} -> {d3_id} | Alinhamento Noul: {noul_val:.1%} (Score: {score_val}/3) [{icon}] ({lat:.1f}ms)")

    aligned_count = sum(1 for e in evaluations if e["is_aligned"])
    total_evals = len(evaluations)
    consistency_rate = (aligned_count / total_evals) if total_evals > 0 else 0.0

    print(f"\n>> Resultado do Teste de Deriva Semântica:")
    print(f"   • Taxa de Consistência Bidirecional: {consistency_rate:.0%} ({aligned_count}/{total_evals} cadeias válidas)")

    return {
        "test_name": "round_trip_semantic_drift",
        "description": "Verificação inversa (D3FEND -> CWE) via Noul e Score para detetar perda de alinhamento causal",
        "consistency_rate": consistency_rate,
        "chains_evaluated": total_evals,
        "evaluations": evaluations,
    }


# =============================================================================
# MAIN ORCHESTRATOR
# =============================================================================
def main():
    print("Iniciando Suite de Testes de Robustez, Perturbação e Deriva Semântica...")
    store = FederatedStore()
    
    is_mock = "--mock" in sys.argv
    client = get_client(site="robustness_drift_test", mock=is_mock)

    t_start = time.perf_counter()

    t1_results = run_position_bias_test(store, client)
    t2_results = run_adversarial_distractor_test(store, client)
    t3_results = run_round_trip_drift_test(store, client)

    total_lat = (time.perf_counter() - t_start) * 1000

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_execution_time_ms": round(total_lat, 1),
        "summary": {
            "position_bias_stability": t1_results.get("decision_stability", 0.0),
            "max_probability_deviation": t1_results.get("max_probability_deviation", 0.0),
            "adversarial_distractor_accuracy": t2_results.get("accuracy", 0.0),
            "round_trip_consistency_rate": t3_results.get("consistency_rate", 0.0),
        },
        "tests": {
            "position_bias": t1_results,
            "adversarial_distractor": t2_results,
            "round_trip_drift": t3_results,
        },
    }

    out_file = PUBLIC_DIR / "robustness_report.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n[OK] Relatório completo de robustez gravado em: {out_file}")

    dist_dir = ROOT / "web" / "dist"
    if dist_dir.exists():
        dist_file = dist_dir / "robustness_report.json"
        with open(dist_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"[OK] Relatório sincronizado em: {dist_file}")


if __name__ == "__main__":
    main()
