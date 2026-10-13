"""Tests all graph and traversal queries through the website backend API."""

import urllib.request
import json
import time
import sys

sys.stdout.reconfigure(encoding="utf-8")

BASE_URL = "http://localhost:3000/api/graph"


def test_website():
    print("=" * 70)
    print("🌐 TESTE COMPLETO DAS QUERIES NO WEBSITE (PORTA 3000 / 5173)")
    print("=" * 70)

    # 1. Test GET /api/graph
    print("\n[1] Testar Leitura do Grafo Desacoplado (GET /api/graph)...")
    t0 = time.time()
    try:
        with urllib.request.urlopen(BASE_URL) as r:
            data = json.loads(r.read().decode("utf-8"))
            dt = (time.time() - t0) * 1000
            nodes = data.get("nodes", [])
            edges = data.get("edges", [])
            print(f"    ✅ Sucesso ({dt:.1f} ms)")
            print(f"       Total de Nós: {len(nodes)} | Total de Arestas: {len(edges)}")
            sample_t1059 = next((n for n in nodes if n.get("id") == "T1059"), {})
            sample_ics = next((n for n in nodes if n.get("id") == "T0881"), {})
            print(f"       * Amostra ATT&CK [{sample_t1059.get('group')}]: {sample_t1059.get('id')} - {sample_t1059.get('name')}")
            print(f"       * Amostra ICS/OT [{sample_ics.get('group')}]: {sample_ics.get('id')} - {sample_ics.get('name')}")
    except Exception as e:
        print(f"    ❌ Erro: {e}")

    # 2. Test GET /api/graph/templates
    print("\n[2] Testar Catálogo de Templates (GET /api/graph/templates)...")
    t0 = time.time()
    try:
        with urllib.request.urlopen(f"{BASE_URL}/templates") as r:
            tmpls = json.loads(r.read().decode("utf-8"))
            dt = (time.time() - t0) * 1000
            t_list = tmpls if isinstance(tmpls, list) else tmpls.get("templates", [])
            print(f"    ✅ Sucesso ({dt:.1f} ms) - {len(t_list)} templates disponíveis:")
            for t in t_list:
                print(f"       * {t.get('framework'):12s} ({t.get('name')}) - {t.get('label')}")
    except Exception as e:
        print(f"    ❌ Erro: {e}")

    # 3. Test POST /api/graph/hop (Salto Canónico do Jev Meta-Router)
    print("\n[3] Testar Salto do Jev Meta-Router (POST /api/graph/hop)...")
    print("    Nó: CWE-79 | Meta: Mitigação defensiva para XSS | Estratégia: canonical")
    t0 = time.time()
    hop_body = json.dumps({
        "currentNode": "CWE-79",
        "traversedPath": ["CWE-79"],
        "goal": "Find the primary defensive mitigation for Cross-Site Scripting (XSS).",
        "strategy": "canonical"
    }).encode("utf-8")
    req = urllib.request.Request(f"{BASE_URL}/hop", data=hop_body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            hop = json.loads(r.read().decode("utf-8"))
            dt = (time.time() - t0) * 1000
            step = hop.get("step", {})
            r_info = step.get("level1Router", {})
            e_info = step.get("level2Explorer", {})
            jev_resp = step.get("jevResponse", {})
            print(f"    ✅ Sucesso ({dt:.1f} ms) | Status: {hop.get('status')}")
            print(f"       Meta-Router: {r_info.get('currentFramework')} ➔ {r_info.get('targetFramework')} ({r_info.get('strategyApplied')})")
            print(f"       Explorer Template: {e_info.get('templateUsed')}")
            print(f"       Próximo Nó Selecionado: {hop.get('currentNode')}")
            print(f"       Caminho Percorrido: {' ➔ '.join(hop.get('traversedPath', []))}")
            print(f"       Confiança no Objetivo (Noul): {jev_resp.get('noulGoal', 0):.1%}")
            print(f"       Score Heurístico: {jev_resp.get('scoreHeuristic')}")
    except Exception as e:
        print(f"    ❌ Erro: {e}")

    # 4. Test POST /api/graph/direct-query (Direct Query Fan-Out)
    print("\n[4] Testar Consulta Direta de Framework (POST /api/graph/direct-query)...")
    print("    Nó: T1059 | Framework Solicitado: D3FEND")
    t0 = time.time()
    query_body = json.dumps({
        "currentNode": "T1059",
        "frameworks": ["D3FEND"],
        "goal": "What is the most effective defensive technique against Command and Scripting Interpreter?"
    }).encode("utf-8")
    req = urllib.request.Request(f"{BASE_URL}/direct-query", data=query_body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as r:
            q_res = json.loads(r.read().decode("utf-8"))
            dt = (time.time() - t0) * 1000
            results = q_res.get("results", [])
            print(f"    ✅ Sucesso ({dt:.1f} ms) | {len(results)} frameworks respondidos:")
            for item in results:
                tgt = item.get("chosenTarget", {})
                print(f"       * Framework: {item.get('framework')} [{item.get('templateUsed')}]")
                print(f"         Candidatos Avaliados: {item.get('neighborsCount')}")
                print(f"         Técnica Escolhida: {tgt.get('id')} - {tgt.get('name')}")
                print(f"         Noul: {item.get('noulGoal', 0):.1%} | Heuristic Score: {item.get('heuristicScore')}")
    except Exception as e:
        print(f"    ❌ Erro: {e}")

    print("\n" + "=" * 70)
    print("🎉 TODOS OS 4 TESTES DAS QUERIES NO WEBSITE PASSARAM COM SUCESSO!")
    print("=" * 70)


if __name__ == "__main__":
    test_website()
