"""
Semantic Beam Search Engine for Federated Cybersecurity Knowledge Graphs.

Implements informed multi-path graph traversal across the complete ontological chain:
Incident -> CWE -> CAPEC -> ATT&CK/ATLAS -> D3FEND.

Key Features:
- Beam Width K (e.g., K=2 or K=3): Tracks top-K candidate paths.
- Probabilistic Path Scoring: Path Score = Product of edge selection probabilities (from Jev Choice).
- Backtracking & Dead-End Recovery: If the top path has no neighbors in the next framework,
  alternative beam candidates are expanded without requiring hardcoded fallbacks.
- Global Context & Drift Guard: Accumulates causal history to keep the end-to-end traversal aligned.
"""

import math
import time
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple

from typesafe_sdk import Choice, Noul, Score
from ..frameworks.stores.federated_store import FederatedStore
from ..frameworks.jev_budget import get_client


@dataclass
class SearchNode:
    entity_id: str
    entity_name: str
    framework: str
    description: str
    probability: float = 1.0


@dataclass
class BeamPath:
    nodes: List[SearchNode] = field(default_factory=list)
    cumulative_prob: float = 1.0
    drift_score: float = 1.0

    @property
    def current_node(self) -> Optional[SearchNode]:
        return self.nodes[-1] if self.nodes else None

    @property
    def path_ids(self) -> List[str]:
        return [n.entity_id for n in self.nodes]

    @property
    def score(self) -> float:
        return self.cumulative_prob * self.drift_score

    def extend(self, node: SearchNode) -> 'BeamPath':
        new_nodes = list(self.nodes) + [node]
        new_prob = self.cumulative_prob * max(node.probability, 0.001)
        return BeamPath(nodes=new_nodes, cumulative_prob=new_prob, drift_score=self.drift_score)


class SemanticBeamSearch:
    def __init__(self, store: Optional[FederatedStore] = None, client=None, beam_width: int = 2):
        self.store = store or FederatedStore.get_instance()
        self.client = client or get_client(site="beam_search")
        self.beam_width = beam_width
        self.total_expansions = 0
        self.total_latency_ms = 0.0

    def _get_entity_info(self, entity_id: str, framework: str = "") -> Optional[Tuple[str, str]]:
        e = self.store.get_entity(entity_id)
        if not e:
            return None
        return (e.name, e.description or "")

    def _get_neighbors(self, node_id: str, target_framework: str) -> List[Dict[str, Any]]:
        return self.store.get_scoped_neighbors(node_id, target_framework=target_framework)

    def search(
        self,
        incident_ctx: Dict[str, Any],
        initial_cwes: List[str],
        enable_drift_guard: bool = True
    ) -> Dict[str, Any]:
        """
        Executes Beam Search across: Incident -> CWE -> CAPEC -> ATT&CK -> D3FEND.
        """
        t_start = time.perf_counter()
        self.total_expansions = 0
        self.total_latency_ms = 0.0

        # Step 1: Initialize Beam with top-K CWEs
        print(f"\n[Beam Search] Hop 1: Avaliando CWEs iniciais para o incidente...")
        criteria_cwe = {}
        cwe_data = {}
        for cid in initial_cwes:
            info = self._get_entity_info(cid, "CWE")
            if info:
                name, desc = info
                criteria_cwe[cid] = f"{cid}: {name} — {desc[:120]}..."
                cwe_data[cid] = {"id": cid, "name": name, "description": desc[:200]}

        q1 = {
            "root_weakness": Choice(
                instructions="Which CWE represents the direct root-cause weakness in this incident?",
                criteria=criteria_cwe,
            )
        }

        t0 = time.perf_counter()
        resp1 = self.client.system_one(state={"incident": incident_ctx, "current_hop": "Incident -> CWE"}, questions=q1)
        lat1 = (time.perf_counter() - t0) * 1000
        self.total_latency_ms += lat1
        self.total_expansions += 1

        probs1 = resp1.choices["root_weakness"].probabilities or {}
        # Sort candidate CWEs by probability
        ranked_cwes = sorted(criteria_cwe.keys(), key=lambda k: probs1.get(k, 0.0), reverse=True)

        beam: List[BeamPath] = []
        for cid in ranked_cwes[:self.beam_width]:
            prob = max(probs1.get(cid, 0.0), 0.01)
            name, desc = self._get_entity_info(cid, "CWE")
            node = SearchNode(entity_id=cid, entity_name=name, framework="CWE", description=desc, probability=prob)
            beam.append(BeamPath(nodes=[node], cumulative_prob=prob))

        print(f"  * Beam inicial (K={len(beam)}): {[(p.path_ids, round(p.score, 3)) for p in beam]}")

        # Transition Hops: (CWE -> CAPEC), (CAPEC -> ATT&CK), (ATT&CK -> D3FEND)
        transitions = [
            ("CAPEC", "attack_pattern", "Which CAPEC attack pattern represents the adversary's execution mechanism?"),
            ("ATT&CK", "adversary_technique", "Which operational ATT&CK technique reflects the adversary's method?"),
            ("D3FEND", "best_defense", "Which D3FEND countermeasure best neutralizes the vulnerability and active technique?"),
        ]

        for hop_idx, (target_fw, question_key, question_prompt) in enumerate(transitions, 2):
            print(f"\n[Beam Search] Hop {hop_idx}: Expansão para {target_fw}...")
            new_candidates: List[BeamPath] = []

            for path in beam:
                curr = path.current_node
                neighbors = self._get_neighbors(curr.entity_id, target_framework=target_fw)

                # Filter neighbors that exist in store
                valid_neighs = []
                for n in neighbors:
                    nid = n["neighbor_id"]
                    info = self._get_entity_info(nid, target_fw)
                    if info:
                        valid_neighs.append((nid, info[0], info[1]))

                if not valid_neighs:
                    print(f"  [!] Ramo {path.path_ids} atingiu beco sem saída (sem vizinhos {target_fw}). Backtracking automático.")
                    continue

                # Ask Jev to evaluate candidates for this path
                criteria = {nid: f"{nid}: {name} — {desc[:120]}..." for nid, name, desc in valid_neighs[:6]}
                q = {
                    question_key: Choice(
                        instructions=f"Given causal path ({' -> '.join(path.path_ids)}), {question_prompt}",
                        criteria=criteria,
                    )
                }

                t0 = time.perf_counter()
                resp = self.client.system_one(
                    state={
                        "incident": incident_ctx,
                        "accumulated_path": path.path_ids,
                        "current_hop": f"{curr.framework} -> {target_fw}",
                    },
                    questions=q,
                )
                lat = (time.perf_counter() - t0) * 1000
                self.total_latency_ms += lat
                self.total_expansions += 1

                step_probs = resp.choices[question_key].probabilities or {}
                ranked_branches = sorted(criteria.keys(), key=lambda k: step_probs.get(k, 0.0), reverse=True)

                for nid in ranked_branches[:self.beam_width]:
                    p_val = max(step_probs.get(nid, 0.0), 0.01)
                    info = self._get_entity_info(nid, target_fw)
                    node = SearchNode(entity_id=nid, entity_name=info[0], framework=target_fw, description=info[1], probability=p_val)
                    new_candidates.append(path.extend(node))

            if not new_candidates:
                print(f"[!] Erro: Todos os ramos do Beam atingiram becos sem saída no Hop {hop_idx}!")
                break

            # Prune to Beam Width K
            new_candidates.sort(key=lambda p: p.score, reverse=True)
            beam = new_candidates[:self.beam_width]
            print(f"  * Top {len(beam)} caminhos após Hop {hop_idx}:")
            for rank, p in enumerate(beam, 1):
                print(f"     #{rank}: {' -> '.join(p.path_ids)} (Score cumulativo: {p.score:.4f})")

        total_time_ms = (time.perf_counter() - t_start) * 1000
        best_path = beam[0] if beam else None

        # Optional Drift Verification on best path
        drift_verdict = 1.0
        if enable_drift_guard and best_path and len(best_path.nodes) >= 4:
            root_cwe = best_path.nodes[0]
            final_d3 = best_path.nodes[-1]
            q_guard = {
                "causal_coherence": Noul(
                    instructions=(
                        f"Does countermeasure '{final_d3.entity_id}: {final_d3.entity_name}' directly mitigate "
                        f"root weakness '{root_cwe.entity_id}: {root_cwe.entity_name}' in this incident?"
                    )
                )
            }
            resp_guard = self.client.system_one(
                state={"incident": incident_ctx, "path": best_path.path_ids},
                questions=q_guard
            )
            drift_verdict = resp_guard.nouls["causal_coherence"].noul

        return {
            "best_path": best_path.path_ids if best_path else [],
            "best_score": round(best_path.score, 4) if best_path else 0.0,
            "all_surviving_paths": [
                {"path": p.path_ids, "score": round(p.score, 4), "cumulative_prob": round(p.cumulative_prob, 4)}
                for p in beam
            ],
            "drift_guard_verdict": round(drift_verdict, 2),
            "total_expansions": self.total_expansions,
            "total_latency_ms": round(total_time_ms, 1),
            "avg_latency_per_expansion_ms": round(self.total_latency_ms / max(self.total_expansions, 1), 1),
        }
