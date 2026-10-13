"""
Jev & Neo4j Cybersecurity Threat Modeling Explorer — Interactive Live Visualizer.
Covers: CAPEC (Attack Patterns), CWE (Weaknesses), ATT&CK (Adversary Techniques),
D3FEND (Defensive Countermeasures), and AEGIS SubDomains (Taxonomy Bridges).
Full Transparency: Step-by-step or Auto-run, full history scrubber, live Vis.js graph highlights.
"""

import os
import json
import time
from dotenv import load_dotenv
import streamlit as st
import streamlit.components.v1 as components
from neo4j import GraphDatabase
from typesafe_sdk import TypeSafeClient, Choice, Noul, Score

load_dotenv()

st.set_page_config(
    page_title="Jev Cybersecurity Threat Modeling Explorer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
JEV_API_KEY = os.getenv("TYPESAFE_API_KEY") or os.getenv("API_JEV")

# Color palette for cybersecurity graph nodes
COLOR_MAP = {
    "CAPEC": "#F97316",      # Vivid Orange (Attack Patterns)
    "CWE": "#8B5CF6",        # Vivid Purple (Software Weaknesses)
    "ATTACK": "#EF4444",     # Crimson Red (ATT&CK Adversary Techniques)
    "D3FEND": "#10B981",     # Emerald Green (Defensive Countermeasures)
    "SubDomain": "#06B6D4",  # Cyan (AEGIS Bridge SubDomains)
    "Domain": "#3B82F6",     # Royal Blue (Taxonomy Domains)
    "DEFAULT": "#64748B"     # Slate
}

PRESET_SCENARIOS = {
    "CAPEC-1 (Access Control Bypass)": {
        "start_node": "CAPEC-1",
        "goal": "Find the D3FEND defensive countermeasure or verification technique that mitigates software file permissions or access control weaknesses."
    },
    "CAPEC-98 (Phishing Attack Pattern)": {
        "start_node": "CAPEC-98",
        "goal": "Find the specific defensive mechanism in D3FEND or security controls that detect or prevent credential theft and message compromise."
    },
    "CWE-89 (SQL Injection)": {
        "start_node": "CWE-89",
        "goal": "Traverse related attack patterns and locate the primary defensive and verification technique in D3FEND."
    },
    "T1574.010 (Services File Permissions Weakness)": {
        "start_node": "T1574.010",
        "goal": "Find the D3FEND countermeasure that verifies service binaries or restores software integrity."
    },
    "CWE-287 (Improper Authentication)": {
        "start_node": "CWE-287",
        "goal": "Locate the defensive credential hardening and access mediation techniques in D3FEND."
    }
}


@st.cache_resource
def get_neo4j_driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))


def get_jev_client():
    return TypeSafeClient(api_key=JEV_API_KEY)


def fetch_graph_statistics():
    """Fetch node and relationship counts across cybersecurity frameworks."""
    driver = get_neo4j_driver()
    counts = {"nodes": {}, "rels": {}}
    try:
        with driver.session() as session:
            labels_res = session.run("""
                CALL db.labels() YIELD label
                CALL (label) {
                    MATCH (n) WHERE label IN labels(n)
                    RETURN count(n) AS cnt
                }
                RETURN label, cnt ORDER BY cnt DESC
            """).data()
            for r in labels_res:
                counts["nodes"][r["label"]] = r["cnt"]

            rels_res = session.run("""
                CALL db.relationshipTypes() YIELD relationshipType
                CALL (relationshipType) {
                    MATCH ()-[r]->() WHERE type(r) = relationshipType
                    RETURN count(r) AS cnt
                }
                RETURN relationshipType, cnt ORDER BY cnt DESC
            """).data()
            for r in rels_res:
                counts["rels"][r["relationshipType"]] = r["cnt"]
    except Exception as e:
        st.sidebar.error(f"Neo4j stats error: {e}")
    return counts


def fetch_ego_network(current_node_id: str, traversed_path: list, max_neighbors: int = 50):
    """
    Fetch the localized ego-network (traversed path + active frontier neighbors)
    to render Vis.js smoothly at 60 FPS without overloading the browser with 3,000+ nodes.
    """
    driver = get_neo4j_driver()
    nodes = []
    edges = []
    node_set = set()
    edge_set = set()

    focus_ids = list(set(traversed_path + [current_node_id]))

    cypher = """
    UNWIND $focus_ids AS fid
    MATCH (n)
    WHERE coalesce(n.capecId, n.cweId, n.attackId, n.d3fendId, n.subDomainId, n.domainId, n.id) = fid
    OPTIONAL MATCH (n)-[r]-(m)
    WITH n, r, m
    RETURN 
        coalesce(n.capecId, n.cweId, n.attackId, n.d3fendId, n.subDomainId, n.domainId, n.id) AS n_id,
        coalesce(n.name, n.title, n.id) AS n_label,
        labels(n)[0] AS n_type,
        coalesce(m.capecId, m.cweId, m.attackId, m.d3fendId, m.subDomainId, m.domainId, m.id) AS m_id,
        coalesce(m.name, m.title, m.id) AS m_label,
        labels(m)[0] AS m_type,
        type(r) AS rel_type,
        startNode(r) = n AS is_outgoing
    LIMIT $max_limit
    """

    try:
        with driver.session() as session:
            records = session.run(cypher, {"focus_ids": focus_ids, "max_limit": max_neighbors * len(focus_ids)}).data()
            for rec in records:
                nid = rec["n_id"]
                if nid and nid not in node_set:
                    node_set.add(nid)
                    nodes.append({
                        "id": nid,
                        "label": rec["n_label"][:24] + "..." if len(str(rec["n_label"])) > 24 else rec["n_label"],
                        "title": f"<b>{rec['n_type']}</b> ({nid})<br>{rec['n_label']}",
                        "group": rec["n_type"] or "DEFAULT",
                    })

                mid = rec["m_id"]
                if mid and mid not in node_set:
                    node_set.add(mid)
                    nodes.append({
                        "id": mid,
                        "label": rec["m_label"][:24] + "..." if len(str(rec["m_label"])) > 24 else rec["m_label"],
                        "title": f"<b>{rec['m_type']}</b> ({mid})<br>{rec['m_label']}",
                        "group": rec["m_type"] or "DEFAULT",
                    })

                if nid and mid and rec["rel_type"]:
                    src = nid if rec["is_outgoing"] else mid
                    tgt = mid if rec["is_outgoing"] else nid
                    edge_key = (src, tgt, rec["rel_type"])
                    if edge_key not in edge_set:
                        edge_set.add(edge_key)
                        edges.append({
                            "from": src,
                            "to": tgt,
                            "label": rec["rel_type"],
                            "arrows": "to"
                        })
    except Exception as e:
        st.sidebar.error(f"Error fetching network: {e}")

    return nodes, edges


def query_neighbors(current_node_id: str, visited_ids: list):
    """Fetch adjacent edges and neighbors with full Cypher transparency."""
    driver = get_neo4j_driver()
    cypher = """
    MATCH (curr)
    WHERE coalesce(curr.capecId, curr.cweId, curr.attackId, curr.d3fendId, curr.subDomainId, curr.domainId, curr.id) = $curr_id
    MATCH (curr)-[r]-(neighbor)
    WHERE NOT coalesce(neighbor.capecId, neighbor.cweId, neighbor.attackId, neighbor.d3fendId, neighbor.subDomainId, neighbor.domainId, neighbor.id) IN $visited_ids
    RETURN 
        CASE WHEN startNode(r) = curr THEN 'OUTGOING' ELSE 'INCOMING' END AS direction,
        type(r) AS rel_type,
        labels(neighbor)[0] AS neighbor_label,
        coalesce(neighbor.capecId, neighbor.cweId, neighbor.attackId, neighbor.d3fendId, neighbor.subDomainId, neighbor.domainId, neighbor.id) AS neighbor_id,
        coalesce(neighbor.name, neighbor.title, neighbor.text, neighbor.id) AS neighbor_name,
        coalesce(neighbor.description, neighbor.definition, neighbor.solutions, '') AS neighbor_desc
    LIMIT 25
    """
    params = {"curr_id": current_node_id, "visited_ids": visited_ids}
    start_time = time.time()
    with driver.session() as session:
        records = session.run(cypher, params).data()
    duration_ms = (time.time() - start_time) * 1000
    return records, cypher.strip(), params, duration_ms


# --- Session State Initialization ---
if "scenario_name" not in st.session_state:
    st.session_state.scenario_name = list(PRESET_SCENARIOS.keys())[0]
if "current_node" not in st.session_state:
    st.session_state.current_node = PRESET_SCENARIOS[st.session_state.scenario_name]["start_node"]
if "traversed_path" not in st.session_state:
    st.session_state.traversed_path = [st.session_state.current_node]
if "history_log" not in st.session_state:
    st.session_state.history_log = []
if "goal_achieved" not in st.session_state:
    st.session_state.goal_achieved = False
if "view_hop_idx" not in st.session_state:
    st.session_state.view_hop_idx = -1


def execute_single_hop():
    """Runs 1 single hop in the traversal."""
    if st.session_state.goal_achieved:
        return

    curr = st.session_state.current_node
    path = st.session_state.traversed_path
    
    # 1. Fetch from Neo4j
    neighbors, cypher_q, params, db_time = query_neighbors(curr, visited_ids=path)
    
    if not neighbors:
        st.warning(f"No further unvisited branches available from '{curr}'. Traversal ended.")
        return

    # 2. Formulate Options for Jev Choice
    criteria_options = {}
    option_map = {}
    for idx, n in enumerate(neighbors):
        opt_key = f"branch_{idx+1}"
        direction_arrow = "to" if n["direction"] == "OUTGOING" else "from"
        opt_desc = (
            f"Relationship [{n['rel_type']}] {direction_arrow} [{n['neighbor_label']}] "
            f"'{n['neighbor_name']}' ({n['neighbor_id']}): {n['neighbor_desc'][:120]}"
        )
        criteria_options[opt_key] = opt_desc
        option_map[opt_key] = n

    # 3. Payload for Jev
    state_payload = {
        "user_goal": search_goal_input,
        "current_node": curr,
        "traversed_path": " -> ".join(path),
        "available_branches": criteria_options
    }

    questions_payload = {
        "goal_reached": Noul(
            instructions=f"Does the current node '{curr}' directly satisfy, solve, or answer the user goal: '{search_goal_input}'?"
        ),
        "best_next_step": Choice(
            instructions=f"Given the user goal '{search_goal_input}', which branch is the most relevant path to follow?",
            criteria=criteria_options
        ),
        "heuristic_score": Score(
            instructions=f"How promising and semantically aligned is this current state with the goal '{search_goal_input}'?",
            criteria=["not aligned", "moderately aligned", "highly aligned", "critically aligned"]
        )
    }

    # 4. Call Jev
    client = get_jev_client()
    jev_start = time.time()
    response = client.system_one(state=state_payload, questions=questions_payload)
    jev_time = (time.time() - jev_start) * 1000

    noul_val = response.nouls["goal_reached"].noul
    choice_val = response.choices["best_next_step"].choice
    score_val = response.scores["heuristic_score"].score

    # Save to history log for full transparency
    step_record = {
        "hop": len(path),
        "current_node": curr,
        "cypher_query": cypher_q,
        "cypher_params": params,
        "cypher_time_ms": db_time,
        "neighbors_found": neighbors,
        "jev_state": state_payload,
        "jev_questions": {
            "goal_reached": questions_payload["goal_reached"].instructions,
            "best_next_step": questions_payload["best_next_step"].instructions,
            "best_next_step_criteria": criteria_options,
            "heuristic_score": questions_payload["heuristic_score"].instructions,
        },
        "jev_response": {
            "noul_goal": noul_val,
            "choice_step": choice_val,
            "score_heuristic": score_val,
            "latency_ms": jev_time
        }
    }
    st.session_state.history_log.append(step_record)
    st.session_state.view_hop_idx = len(st.session_state.history_log) - 1

    # 5. Check Goal
    if noul_val >= 0.70:
        st.session_state.goal_achieved = True
    else:
        if choice_val in option_map:
            next_node_obj = option_map[choice_val]
            next_id = next_node_obj["neighbor_id"]
            st.session_state.current_node = next_id
            st.session_state.traversed_path.append(next_id)


def auto_run_until_goal(max_steps=6):
    """Executes hops in a loop until goal is achieved or max steps reached."""
    for _ in range(max_steps):
        if st.session_state.goal_achieved:
            break
        execute_single_hop()


# --- Sidebar ---
st.sidebar.title("🛡️ Threat Intelligence Explorer")
st.sidebar.markdown("**Jev (System 1) Probabilistic Graph Traversal**")

# Scenario Selector
selected_scenario_name = st.sidebar.selectbox(
    "Predefined Scenarios:",
    options=list(PRESET_SCENARIOS.keys()),
    index=list(PRESET_SCENARIOS.keys()).index(st.session_state.scenario_name) if st.session_state.scenario_name in PRESET_SCENARIOS else 0
)

# Custom Node Input option
use_custom = st.sidebar.checkbox("Custom Start Node", value=False)
if use_custom:
    custom_node = st.sidebar.text_input("Enter Node ID (e.g., CAPEC-98, CWE-89, T1574.010, D3-AVE):", value="CAPEC-1")
    start_node = custom_node.strip()
else:
    start_node = PRESET_SCENARIOS[selected_scenario_name]["start_node"]

# Goal Input
default_goal = PRESET_SCENARIOS[selected_scenario_name]["goal"]
search_goal_input = st.sidebar.text_area("Search Goal:", value=default_goal, height=100)

st.sidebar.subheader("🎮 Traversal Controls")
c_btn1, c_btn2 = st.sidebar.columns(2)
if c_btn1.button("⏭ Next Hop", use_container_width=True, disabled=st.session_state.goal_achieved):
    execute_single_hop()
    st.rerun()

if c_btn2.button("▶ Run All", use_container_width=True, disabled=st.session_state.goal_achieved):
    auto_run_until_goal()
    st.rerun()

if st.sidebar.button("↺ Reset Search", use_container_width=True):
    st.session_state.scenario_name = selected_scenario_name
    st.session_state.current_node = start_node
    st.session_state.traversed_path = [start_node]
    st.session_state.history_log = []
    st.session_state.goal_achieved = False
    st.session_state.view_hop_idx = -1
    st.rerun()

# Statistics in Sidebar
stats = fetch_graph_statistics()
st.sidebar.markdown("---")
st.sidebar.markdown("📊 **Graph Metrics:**")
cols_stat = st.sidebar.columns(2)
with cols_stat[0]:
    for lbl in ["CWE", "ATTACK", "CAPEC"]:
        cnt = stats["nodes"].get(lbl, 0)
        st.caption(f"**{lbl}:** {cnt}")
with cols_stat[1]:
    for lbl in ["D3FEND", "SubDomain", "Domain"]:
        cnt = stats["nodes"].get(lbl, 0)
        st.caption(f"**{lbl}:** {cnt}")

total_nodes = sum(stats["nodes"].values())
total_rels = sum(stats["rels"].values())
st.sidebar.caption(f"**Total Graph:** {total_nodes:,} nodes | {total_rels:,} edges")
st.sidebar.caption("⚡ Powered by **TypeSafe AI Jev** (sub-50ms System 1 decisions) & **Neo4j**.")


# --- Main Dashboard Layout ---
st.title("🛡️ Semantic Threat Traversal: Jev (System 1) + Neo4j")
st.caption("Investigating cross-framework cybersecurity ontologies: CAPEC ➔ CWE ➔ ATT&CK ➔ D3FEND")

# Quick Action Banner
banner_col1, banner_col2, banner_col3 = st.columns([2, 1, 1])
with banner_col1:
    path_display = " ➔ ".join([f"`{p}`" for p in st.session_state.traversed_path])
    st.markdown(f"**Traversed Path ({len(st.session_state.traversed_path)} nodes):**\n{path_display}")

with banner_col2:
    if st.button("⏭ Step Forward (1 Hop)", type="primary", disabled=st.session_state.goal_achieved, use_container_width=True):
        execute_single_hop()
        st.rerun()

with banner_col3:
    if st.button("▶ Auto-Run Until Goal", disabled=st.session_state.goal_achieved, use_container_width=True):
        auto_run_until_goal()
        st.rerun()

if st.session_state.goal_achieved:
    st.success(f"🎉 **TARGET GOAL REACHED!** Stopping at `{st.session_state.current_node}` with high confidence.")

st.markdown("---")

# Split Screen: Left (Graph Viz) & Right (Transparency Inspector)
left_col, right_col = st.columns([3, 2])

with left_col:
    st.subheader("🌐 Active Knowledge Graph Network (Vis.js)")
    
    # Fetch ego-network around active path + frontier
    vis_raw_nodes, vis_raw_edges = fetch_ego_network(st.session_state.current_node, st.session_state.traversed_path)
    
    traversed_set = set(st.session_state.traversed_path)
    current_node_id = st.session_state.current_node

    vis_nodes = []
    for n in vis_raw_nodes:
        nid = n["id"]
        group = n["group"]
        base_color = COLOR_MAP.get(group, COLOR_MAP["DEFAULT"])
        
        node_style = {
            "id": nid,
            "label": f"{nid}\n({group})",
            "title": n["title"],
            "shape": "dot",
            "size": 20,
            "color": {
                "background": base_color,
                "border": "#1E293B"
            },
            "font": {"color": "#E2E8F0", "size": 12, "bold": True}
        }

        # Highlight if in traversed path
        if nid in traversed_set:
            node_style["size"] = 32
            node_style["color"] = {
                "background": "#10B981",  # Emerald Green for chosen path
                "border": "#34D399"
            }
            node_style["borderWidth"] = 3

        # Extra Highlight for CURRENT node
        if nid == current_node_id:
            node_style["size"] = 44
            node_style["color"] = {
                "background": "#F59E0B",  # Glowing Amber
                "border": "#FDE68A"
            }
            node_style["borderWidth"] = 5

        vis_nodes.append(node_style)

    vis_edges = []
    for e in vis_raw_edges:
        edge_style = {
            "from": e["from"],
            "to": e["to"],
            "label": e["label"],
            "arrows": "to",
            "color": {"color": "#475569"},
            "font": {"color": "#94A3B8", "size": 9, "align": "middle"}
        }
        # Highlight traversed edge
        if e["from"] in traversed_set and e["to"] in traversed_set:
            edge_style["color"] = {"color": "#10B981"}
            edge_style["width"] = 4
        vis_edges.append(edge_style)

    # Vis.js HTML template
    vis_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
      <style type="text/css">
        #network {{
          width: 100%;
          height: 560px;
          border: 1px solid #334155;
          border-radius: 8px;
          background-color: #0F172A;
        }}
      </style>
    </head>
    <body>
      <div id="network"></div>
      <script type="text/javascript">
        var nodes = new vis.DataSet({json.dumps(vis_nodes)});
        var edges = new vis.DataSet({json.dumps(vis_edges)});
        var container = document.getElementById('network');
        var data = {{ nodes: nodes, edges: edges }};
        var options = {{
          physics: {{
            stabilization: false,
            barnesHut: {{
              gravitationalConstant: -4000,
              springConstant: 0.04,
              springLength: 110
            }}
          }},
          interaction: {{
            hover: true,
            zoomView: true
          }}
        }};
        var network = new vis.Network(container, data, options);
      </script>
    </body>
    </html>
    """
    components.html(vis_html, height=580)


with right_col:
    st.subheader("🔍 Live Transparency & Inspector")
    
    if not st.session_state.history_log:
        st.info("Click **'⏭ Step Forward'** or **'▶ Auto-Run'** to start inspecting Cypher queries and Jev decisions.")
    else:
        # Selector to scrub through any executed hop!
        total_hops = len(st.session_state.history_log)
        selected_hop_num = st.selectbox(
            "Select Hop to Inspect:",
            options=list(range(1, total_hops + 1)),
            index=total_hops - 1,
            format_func=lambda x: f"Hop #{x} (from {st.session_state.history_log[x-1]['current_node']})"
        )
        
        target_step = st.session_state.history_log[selected_hop_num - 1]
        
        # Tabs for selected hop
        tab_neo4j, tab_jev_state, tab_jev_res = st.tabs([
            f"1. Neo4j Cypher ({target_step['cypher_time_ms']:.1f}ms)",
            "2. Jev State & Questions",
            f"3. Jev Decision ({target_step['jev_response']['latency_ms']:.1f}ms)"
        ])

        with tab_neo4j:
            st.markdown("**Executed Cypher Query:**")
            st.code(target_step["cypher_query"], language="cypher")
            st.markdown(f"**Parameters:** `{json.dumps(target_step['cypher_params'])}`")
            st.markdown(f"**Neighbors Found:** {len(target_step['neighbors_found'])}")
            
            for i, n in enumerate(target_step["neighbors_found"], 1):
                arrow = "➔" if n["direction"] == "OUTGOING" else "⬅"
                st.markdown(
                    f"**[{i}]** {arrow} `:{n['rel_type']}` ➜ **{n['neighbor_label']}** (`{n['neighbor_id']}`): *{n['neighbor_name']}*"
                )

        with tab_jev_state:
            st.markdown("**1. State Payload Sent to Jev:**")
            st.json(target_step["jev_state"])
            
            st.markdown("**2. Questions Formulated:**")
            st.markdown(f"- **Goal Check (`Noul`):** {target_step['jev_questions']['goal_reached']}")
            st.markdown(f"- **Routing (`Choice`):** {target_step['jev_questions']['best_next_step']}")
            st.markdown(f"- **Heuristic (`Score`):** {target_step['jev_questions']['heuristic_score']}")

        with tab_jev_res:
            res = target_step["jev_response"]
            m_col1, m_col2, m_col3 = st.columns(3)
            m_col1.metric("Goal Confidence (Noul)", f"{res['noul_goal']:.0%}")
            m_col2.metric("Chosen Branch", res["choice_step"])
            m_col3.metric("Alignment Score", f"{res['score_heuristic']}")

            # Progress bar for Noul Goal
            st.markdown("**Goal Reached Probability:**")
            st.progress(min(1.0, float(res["noul_goal"])))

            if res["noul_goal"] >= 0.70:
                st.success(f"Goal Reached! Target node: `{target_step['current_node']}`")
            else:
                st.info(f"Decision: Follow `{res['choice_step']}` to next node.")

st.markdown("---")

# Full Path Summary Table
if st.session_state.history_log:
    st.subheader("📋 Traversal Path Timeline (Step-by-Step Overview)")
    summary_data = []
    for step in st.session_state.history_log:
        res = step["jev_response"]
        summary_data.append({
            "Hop #": step["hop"],
            "Current Node": step["current_node"],
            "Goal Confidence (Noul)": f"{res['noul_goal']:.0%}",
            "Jev Choice": res["choice_step"],
            "Heuristic Score": f"{res['score_heuristic']}",
            "Latency": f"{res['latency_ms']:.1f}ms",
            "Status": "🎯 Target Goal Met!" if res["noul_goal"] >= 0.70 else "Avançar"
        })
    st.dataframe(summary_data, use_container_width=True)

# Manuscripts Accordion
with st.expander("📖 Caderno de Encargos / Manuscritos de Investigação", expanded=False):
    manuscript_dir = os.path.join(os.path.dirname(__file__), "..", "manuscritos")
    if os.path.exists(manuscript_dir):
        files = sorted([f for f in os.listdir(manuscript_dir) if f.endswith(".md")])
        if files:
            sel_manuscript = st.selectbox("Selecione o Manuscrito:", files)
            with open(os.path.join(manuscript_dir, sel_manuscript), "r", encoding="utf-8") as mf:
                st.markdown(mf.read())
        else:
            st.info("Nenhum manuscrito registado ainda.")
