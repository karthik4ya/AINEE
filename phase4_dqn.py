import json
import numpy as np
import random

def load_graph(graph_file):
    with open(graph_file) as f:
        data = json.load(f)
    return data["nodes"], np.array(data["matrix"])

def dqn_train(matrix, nodes, episodes=500, gamma=0.9, epsilon=0.9, lr=0.1):
    n = len(nodes)
    q_table = np.zeros((n, n))

    start_idx = nodes.index("attacker")
    goal_idx = nodes.index("root_access")

    print(f"Training DQN for {episodes} episodes...")
    print(f"Start: {nodes[start_idx]} | Goal: {nodes[goal_idx]}\n")

    for episode in range(episodes):
        state = start_idx
        visited = set()
        visited.add(state)

        for step in range(20):
            if state == goal_idx:
                break

            valid_actions = [
                j for j in range(n)
                if matrix[state][j] != -1 and j not in visited
            ]

            if not valid_actions:
                break

            if random.random() < epsilon:
                action = random.choice(valid_actions)
            else:
                q_values = [q_table[state][j] for j in valid_actions]
                action = valid_actions[np.argmax(q_values)]

            reward = matrix[state][action]
            future_actions = [
                j for j in range(n)
                if matrix[action][j] != -1 and j not in visited
            ]
            max_future = max([q_table[action][j] for j in future_actions]) \
                         if future_actions else 0

            q_table[state][action] = (1 - lr) * q_table[state][action] + \
                                      lr * (reward + gamma * max_future)

            visited.add(action)
            state = action

        epsilon = max(0.1, epsilon * 0.995)

    return q_table

def extract_all_paths(matrix, nodes):
    n = len(nodes)
    start_idx = nodes.index("attacker")
    goal_idx = nodes.index("root_access")
    all_paths = []

    def dfs(current, path, total_reward, visited):
        if current == goal_idx:
            all_paths.append((list(path), round(total_reward, 3)))
            return
        for nxt in range(n):
            if matrix[current][nxt] != -1 and nxt not in visited:
                visited.add(nxt)
                path.append(nodes[nxt])
                dfs(nxt, path, total_reward + matrix[current][nxt], visited)
                path.pop()
                visited.remove(nxt)

    dfs(start_idx, [nodes[start_idx]], 0, {start_idx})
    all_paths.sort(key=lambda x: x[1], reverse=True)
    return all_paths

def print_results(all_paths, nodes, q_table):
    print("=" * 60)
    print("ALL ATTACK PATHS RANKED BY REWARD")
    print("=" * 60)
    for i, (path, reward) in enumerate(all_paths):
        tag = " <- OPTIMAL" if i == 0 else ""
        print(f"\nPath {i+1}{tag}")
        print(f"  Route:  {' -> '.join(path)}")
        print(f"  Total reward: {reward}")

    print("\n" + "=" * 60)
    print("Q-TABLE (learned values)")
    print("=" * 60)
    header = f"{'':25s}" + "".join(f"{n[:8]:10s}" for n in nodes)
    print(header)
    for i, row_node in enumerate(nodes):
        row = f"{row_node:25s}" + "".join(f"{q_table[i][j]:10.2f}" for j in range(len(nodes)))
        print(row)

if __name__ == '__main__':
    nodes, matrix = load_graph("phase3_graph.json")

    print("Matrix loaded:")
    for i, row in enumerate(matrix):
        print(f"  {nodes[i]:25s} {list(row)}")

    q_table = dqn_train(matrix, nodes, episodes=500)

    all_paths = extract_all_paths(matrix, nodes)

    print_results(all_paths, nodes, q_table)

    results = {
        "optimal_path": all_paths[0][0] if all_paths else [],
        "optimal_reward": all_paths[0][1] if all_paths else 0,
        "all_paths": [
            {"path": p, "reward": r}
            for p, r in all_paths
        ]
    }

    with open("phase4_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\nSaved to phase4_results.json")
