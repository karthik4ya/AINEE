import json
import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

def build_attack_graph(vulns_file):
    with open(vulns_file) as f:
        vulns = json.load(f)

    G = nx.DiGraph()

    G.add_node("attacker", type="attacker", reward=0.01)
    G.add_node("apache_2.4.25", type="service", reward=0)
    G.add_node("webserver_access", type="access", reward=1.5)
    G.add_node("root_access", type="goal", reward=100)

    G.add_edge("attacker", "apache_2.4.25")

    all_vulns = []
    for key, cve_list in vulns.items():
        all_vulns.extend(cve_list)

    for cve in all_vulns:
        node_id = cve["cve_id"]
        G.add_node(node_id,
                   type="vulnerability",
                   reward=cve["score_vul"],
                   severity=cve["severity"],
                   base_score=cve["base_score"])
        G.add_edge("apache_2.4.25", node_id)
        G.add_edge(node_id, "webserver_access")

    G.add_edge("webserver_access", "root_access")

    return G

def graph_to_matrix(G):
    nodes = list(G.nodes())
    n = len(nodes)
    node_index = {node: i for i, node in enumerate(nodes)}

    matrix = [[-1] * n for _ in range(n)]

    for node in nodes:
        i = node_index[node]
        matrix[i][i] = 0

    for src, dst in G.edges():
        i = node_index[src]
        j = node_index[dst]
        reward = G.nodes[dst].get("reward", 0)
        matrix[i][j] = reward

    return matrix, nodes

def save_graph_image(G):
    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G, seed=42)

    colors = []
    for node in G.nodes():
        t = G.nodes[node].get("type", "")
        if t == "attacker":
            colors.append("#1D9E75")
        elif t == "goal":
            colors.append("#E24B4A")
        elif t == "vulnerability":
            colors.append("#EF9F27")
        elif t == "access":
            colors.append("#7F77DD")
        else:
            colors.append("#888780")

    nx.draw(G, pos,
            node_color=colors,
            with_labels=True,
            node_size=2000,
            font_size=8,
            font_color="white",
            font_weight="bold",
            arrows=True,
            arrowsize=20)

    plt.title("AINEE Attack Graph")
    plt.savefig("attack_graph.png", dpi=150, bbox_inches="tight")
    print("Attack graph image saved to attack_graph.png")

if __name__ == '__main__':
    G = build_attack_graph("phase2_vulns.json")

    print(f"Nodes: {list(G.nodes(data=True))}")
    print(f"\nEdges: {list(G.edges())}")

    matrix, nodes = graph_to_matrix(G)

    print(f"\nNode order: {nodes}")
    print("\nReward matrix:")
    for i, row in enumerate(matrix):
        print(f"  {nodes[i]:30s} {row}")

    graph_data = {
        "nodes": nodes,
        "matrix": matrix,
        "node_details": dict(G.nodes(data=True))
    }

    with open("phase3_graph.json", "w") as f:
        json.dump(graph_data, f, indent=2)

    print("\nSaved to phase3_graph.json")

    save_graph_image(G)
