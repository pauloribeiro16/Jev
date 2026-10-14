"""Attack-Defense Tree search — AEGIS Phase 3 Part 2, Step 4.

Given a root adversary goal plus the Phase-1/2 context (use cases, data flows,
threat cards, RN constraints), search the federated MITRE graphs for the ADTree
that best represents the attack, per
`cases/*/03_PHASE3_SPEC/part2_threat_risk/00_METHODOLOGY...md` §2.5 and §6.4.

Division of labour:

  Jev decides — which element extends a sub-goal, whether the sub-goal is
  disjunctive (OR) or conjunctive (AND), how probable the leaf is, and which
  D3FEND countermeasure answers it.
  Python decides — the attribute algebra, which the methodology fixes exactly:
  OR is min on cost and 1 - prod(1 - p) on probability, AND is sum and product;
  skill is min under OR and max under AND. "Keep the arithmetic in code."

A defence that is verified forces its branch's probability to zero; that is the
Broken Path Proof the methodology requires per leaf.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import math
import re

from typesafe_sdk import Choice, Noul, Score

from .frameworks.jev_budget import get_client
from .frameworks.stores import FederatedStore

OR = "OR"
AND = "AND"

COST_LEVEL = {"low": 1.0, "med": 2.0, "high": 3.0}


def fw_key(framework: str) -> str:
    return "ATT&CK" if framework.replace("&", "") == "ATTACK" else framework

STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "how", "what", "does", "are",
    "was", "can", "from", "into", "them", "their", "there", "when", "which",
    "will", "would", "could", "have", "has", "been", "than", "then", "they",
    "its", "his", "her", "not", "but", "all", "any", "who", "why", "get",
    "use", "used", "using", "via", "per", "out", "own", "same", "also",
}


@dataclass
class Defense:
    """A D3FEND countermeasure bound to an RN constraint."""
    d3fend_id: str
    d3fend_name: str
    constraint: str = ""
    verified: bool = False

    def label(self) -> str:
        c = f" / {self.constraint}" if self.constraint else ""
        return f"{self.d3fend_id}: {self.d3fend_name}{c}"


@dataclass
class AttackNode:
    id: str
    title: str
    kind: str = "leaf"          # goal | or | and | leaf
    capec: str = ""
    cwe: str = ""
    attack: str = ""
    probability: float = 0.0    # inherent, before defences
    cost: float = 1.0
    skill: int = 1
    defense: Optional[Defense] = None
    children: List["AttackNode"] = field(default_factory=list)

    def brief(self) -> str:
        tags = " / ".join(t for t in (self.capec, self.cwe, self.attack) if t)
        return f"{self.title}" + (f" ({tags})" if tags else "")

    # ---- attribute algebra (methodology §2.5), computed in code ----

    def effective_probability(self) -> float:
        """A verified defence zeroes its branch — the Broken Path Proof."""
        if self.defense and self.defense.verified:
            return 0.0
        if not self.children:
            return self.probability
        ps = [c.effective_probability() for c in self.children]
        if self.kind == AND:
            out = 1.0
            for p in ps:
                out *= p
            return out
        out = 1.0
        for p in ps:
            out *= (1.0 - p)
        return 1.0 - out

    def total_cost(self) -> float:
        if not self.children:
            return self.cost
        costs = [c.total_cost() for c in self.children]
        return sum(costs) if self.kind == AND else min(costs)

    def required_skill(self) -> int:
        if not self.children:
            return self.skill
        skills = [c.required_skill() for c in self.children]
        return max(skills) if self.kind == AND else min(skills)

    def leaves(self) -> List["AttackNode"]:
        if not self.children:
            return [self]
        out = []
        for c in self.children:
            out.extend(c.leaves())
        return out

    def render(self, indent: int = 0) -> str:
        pad = "  " * indent
        tag = f"[{self.kind.upper()}] " if self.kind in (OR, AND) else ""
        line = f"{pad}{tag}{self.brief()}"
        if not self.children:
            line += f"  p={self.probability:.2f} cost={self.cost:g} skill={self.skill}"
            if self.defense:
                mark = "VERIFIED" if self.defense.verified else "proposed"
                line += f"  ← {self.defense.label()} [{mark}]"
        return "\n".join([line] + [c.render(indent + 1) for c in self.children])


class AttackTreeSearch:
    """Searches MITRE graphs for the ADTree that best represents the attack."""

    def __init__(self, store=None, client=None, mock: bool = False):
        self.store = store or FederatedStore.get_instance()
        self.mock = mock
        self.client = client or get_client(site="attack_tree", mock=mock)

    # ------------------------------------------------------------- retrieval

    def _index(self):
        """Corpus-wide term frequencies, so generic words count for little."""
        if getattr(self, "_idx", None) is None:
            docs = []
            df = {}
            for store in (self.store.capec, self.store.cwe):
                for ent in store.entities.values():
                    name = (ent.name or "").lower()
                    desc = (ent.description or "").lower()
                    cat = (ent.category or "").lower()
                    name_w = set(re.findall(r"[a-z0-9]+", name))
                    desc_w = set(re.findall(r"[a-z0-9]+", desc))
                    cat_w = set(re.findall(r"[a-z0-9]+", cat))
                    docs.append((ent, name_w, desc_w, cat_w, fw_key(ent.framework)))
                    for t in name_w | cat_w | desc_w:
                        df[t] = df.get(t, 0) + 1
            self._idx = (docs, df, len(docs))
        return self._idx

    def candidates(self, goal: str, limit: int = 8, shortlist=None) -> List[Dict]:
        """Attack patterns and weaknesses to put in front of Jev.

        `shortlist` is the proper input: the STRIDE and LINDDUN threat cards from
        Steps 2 and 3 already name candidate CWE/CAPEC pairs, so the search
        engine judges those. Without one we fall back to lexical retrieval, which
        cannot reach the right leaf on its own — "Exploiting Insecure Direct
        Object References" shares no words with "access foreign tenant data".
        That is precisely the gap Jev exists to fill, so the fallback hands it a
        broad, diverse CAPEC pool rather than pretending lexical match suffices.

        Scoring is weighted by term rarity: "tenant" and "isolation" count far
        more than "data" and "access", which match hundreds of CWE entries alone.
        """
        if shortlist:
            out = []
            for eid in shortlist:
                ent = self.store.get_entity(eid)
                if ent is not None:
                    out.append({"id": ent.id, "name": ent.name,
                                "framework": fw_key(ent.framework),
                                "description": (ent.description or "")[:240],
                                "score": 0.0})
            if out:
                return out

        terms = [t for t in re.findall(r"[a-z0-9]+", goal.lower())
                 if t not in STOPWORDS and len(t) > 2]
        if not terms:
            return []
        docs, df, total = self._index()

        def words(hay: str) -> set:
            return set(re.findall(r"[a-z0-9]+", hay))

        def hit(hay_words: set, term: str) -> bool:
            if term in hay_words:
                return True
            # Light stemming, but only on long enough stems: tenant/tenancy,
            # isolation/isolate. A 4-char stem like "multi" must NOT match
            # "multiple", which otherwise floods the results.
            if len(term) < 6:
                return False
            return any(w.startswith(term[:6]) for w in hay_words)

        scored = []
        for ent, name_w, desc_w, cat_w, fw in docs:
            score = 0.0
            for t in terms:
                idf = math.log(1 + total / (1 + df.get(t, 0)))
                if hit(name_w, t):
                    score += 4.0 * idf          # the name is the strongest signal
                if hit(cat_w, t):
                    score += 1.0 * idf
                if hit(desc_w, t):
                    score += 1.0 * idf
            if score > 0:
                scored.append((score, ent, fw))

        scored.sort(key=lambda x: (-x[0], x[1].id))
        pool = scored[:limit]
        seen = {e.id for _, e, _ in pool}
        # Guarantee the pool spans CAPEC as well as CWE, so Jev always has real
        # attack patterns to judge rather than only weakness titles.
        for sc, e, fw in scored:
            if fw == "CAPEC" and e.id not in seen:
                pool.append((sc, e, fw))
                seen.add(e.id)
            if len(pool) >= limit * 2:
                break

        return [
            {"id": e.id, "name": e.name, "framework": fw,
             "description": (e.description or "")[:240],
             "score": round(sc, 2)}
            for sc, e, fw in pool
        ]

    def relevance_pass(self, use_case: str, catalogue: List[Dict]) -> Dict[str, float]:
        """One Noul per catalogue entry, all in a single request.

        This is the vendor's documented reranking pattern — "one Noul per
        query-candidate pair, then sorts candidates by the value" — so every
        candidate gets judged on its own merits. Nothing is filtered out: the
        whole catalogue is scored and the ordering is what carries the signal.

        A Choice cannot be used here: the API caps it at 255 options, and a
        catalogue of 969 would have to be partitioned. Partitioning would also
        bias the result, because Choice leans toward its first option.
        """
        if self.mock or not catalogue:
            return {c["id"]: 0.5 for c in catalogue}

        # The API rejects a request whose answer set is too large
        # (max_tokens_exceeded — measured: 512 Nouls in one call is accepted,
        # 969 is not). Splitting is transport only: each Noul is judged
        # independently, so there is no cross-item ordering and no first-option
        # bias to introduce. Every entry is still scored; nothing is dropped.
        CHUNK = 512
        scores: Dict[str, float] = {}
        for i in range(0, len(catalogue), CHUNK):
            batch = catalogue[i:i + CHUNK]
            state = {
                "adversary_goal": use_case,
                "weakness_catalogue": {c["id"]: c["name"] for c in batch},
            }
            questions = {
                f"w_{c['id']}": Noul(
                    instructions=(
                        f"Could `weakness_catalogue.{c['id']}` be the software weakness this "
                        f"adversary goal exploits?"
                    ),
                    criteria={
                        "true": "This weakness would plausibly have to be present for the goal to be achievable.",
                        "false": "This weakness is unrelated to what the goal describes.",
                    },
                )
                for c in batch
            }
            resp = self.client.system_one(state=state, questions=questions)
            for c in batch:
                ans = resp.nouls.get(f"w_{c['id']}")
                scores[c["id"]] = getattr(ans, "noul", 0.0) if ans else 0.0
        return scores

    def shortlist(self, use_case: str, keep: int = 15, source=None) -> List[Dict]:
        """Score the whole CWE catalogue, return the top `keep` for the next stage."""
        catalogue = source if source is not None else [
            {"id": e.id, "name": e.name, "framework": "CWE",
             "description": (e.description or "")[:240]}
            for e in self.store.cwe.entities.values()
        ]
        scores = self.relevance_pass(use_case, catalogue)
        ranked = sorted(catalogue, key=lambda c: -scores.get(c["id"], 0.0))
        return [dict(c, relevance=scores.get(c["id"], 0.0)) for c in ranked[:keep]]

    def countermeasures(self, capec_id: str, limit: int = 4) -> List[Dict]:
        """D3FEND techniques defending a CAPEC, for the defence node.

        The crosswalk has no direct CAPEC -> D3FEND edge: defences hang off
        ATT&CK. So the lookup walks CAPEC -LEADS_TO-> ATT&CK -DEFENDED_BY-> D3FEND,
        which is the path the methodology's own traceability chain uses.
        """
        out, seen = [], set()
        for link in self.store.crosswalk.get_crosswalk_links(capec_id):
            if link.direction != "OUTGOING" or link.rel_type != "LEADS_TO":
                continue
            for d in self.store.crosswalk.get_crosswalk_links(link.target_id):
                if d.direction != "OUTGOING" or not d.target_id.startswith("D3"):
                    continue
                if d.target_id in seen:
                    continue
                ent = self.store.get_entity(d.target_id)
                if ent is None:
                    continue
                seen.add(d.target_id)
                out.append({
                    "id": ent.id,
                    "name": ent.name,
                    "via": link.target_id,
                    "description": (ent.description or "")[:200],
                })
                if len(out) >= limit:
                    return out
        return out

    # ------------------------------------------------------------ judgement

    def _judge(self, goal: str, cands: List[Dict], context: str) -> dict:
        if self.mock or not cands:
            return self._mock(cands)

        state = {
            "adversary_goal": goal,
            "sub_goal_being_decomposed": context,
            "candidate_elements": {
                c["id"]: {"name": c["name"], "framework": c["framework"],
                          "description": c["description"]}
                for c in cands
            },
        }

        q_element = Choice(
            instructions=(
                "Which entry in `candidate_elements` is the most direct way for an adversary to "
                "achieve `adversary_goal` through the sub-goal described in "
                "`sub_goal_being_decomposed`?"
            ),
            criteria={c["id"]: c["name"] for c in cands}
            | {"none": "None of these elements achieve the adversary goal."},
        )
        q_comp = Choice(
            instructions=(
                "Are the elements chosen so far alternative routes to "
                "`sub_goal_being_decomposed`, or are they all required together?"
            ),
            criteria={
                OR: "Each element on its own achieves the sub-goal; the adversary needs only one.",
                AND: "The sub-goal only holds if every one of these elements succeeds together.",
            },
        )
        q_prob = Score(
            instructions=(
                "If an adversary attempts the selected element against `adversary_goal`, how "
                "likely is it to succeed, assuming no defensive constraint is in place?"
            ),
            criteria=[
                "Would almost always fail against a reasonably configured system.",
                "Would usually fail; needs an unusual precondition or a mistake.",
                "Would sometimes succeed; needs a plausible precondition but no special access.",
                "Would usually succeed against a typical implementation of this system.",
                "Would succeed almost every time against this system as described.",
            ],
        )
        resp = self.client.system_one(
            state=state,
            questions={"element": q_element, "composition": q_comp, "likelihood": q_prob},
        )
        chosen = resp.choices["element"].choice
        return {
            "id": chosen,
            "composition": resp.choices["composition"].choice,
            "probability": resp.scores["likelihood"].score,
            "confidence": getattr(resp.choices["element"], "confidence", 0.0),
        }

    def _mock(self, cands) -> dict:
        c = cands[0] if cands else None
        return {"id": c["id"] if c else "none", "composition": OR,
                "probability": 3.0, "confidence": 0.5}

    # ---------------------------------------------------------------- search

    def build(self, goal: str, threat_id: str = "TM-D-XX.Y-NNN",
              shortlist=None, breadth: int = 3, leaves: int = 3) -> AttackNode:
        """Decompose `goal` into an OR of vectors, each a CAPEC/CWE leaf."""
        cands = self.candidates(goal, limit=breadth * 3, shortlist=shortlist)
        root = AttackNode(id=threat_id, title=goal, kind=OR)

        chosen, used = [], set()
        for _ in range(leaves):
            pool = [c for c in cands if c["id"] not in used]
            if not pool:
                break
            decision = self._judge(goal, pool, goal)
            if decision["id"] in (None, "none"):
                break
            used.add(decision["id"])
            chosen.append(decision)

        for i, d in enumerate(chosen, start=1):
            c = next(x for x in cands if x["id"] == d["id"])
            defence = self._defence_for(d["id"], self.countermeasures(d["id"]))
            leaf = AttackNode(
                id=f"AT-TREE-{threat_id[-3:]}-LEAF-{i:02d}",
                title=c["name"],
                kind="leaf",
                capec=c["id"] if c["framework"] == "CAPEC" else "",
                cwe=c["id"] if c["framework"] == "CWE" else "",
                probability=max(0.05, min(0.95, d["probability"] / 4)),
                cost=COST_LEVEL["low"],
                skill=max(1, int(round(d["probability"] / 2))),
                defense=defence,
            )
            root.children.append(leaf)

        return root

    def _defence_for(self, capec_id: str, measures: List[Dict]) -> Optional[Defense]:
        """Pick the D3FEND technique that answers this leaf."""
        if not measures:
            return None
        if self.mock:
            return Defense(measures[0]["id"], measures[0]["name"])
        return Defense(measures[0]["id"], measures[0]["name"], verified=False)

    def render(self, node: AttackNode) -> str:
        lines = [node.render()]
        lines.append(
            f"\n  Root probability (inherent) : {node.effective_probability():.3f}"
            f"   [1 - prod(1-p) over {len(node.children)} vectors]"
        )
        lines.append(f"  Attacker cost (min)        : {node.total_cost():g}")
        lines.append(f"  Skill required (min)       : {node.required_skill()}")
        defended = sum(1 for c in node.children if c.defense and c.defense.verified)
        lines.append(f"  Broken path proofs         : {defended}/{len(node.children)} "
                     f"(defences marked verified)")
        return "\n".join(lines)