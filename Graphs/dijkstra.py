INF = float('inf')
V = 5

# Find vertex with minimum distance
def min_distance(dist, visited):
    min_val = INF
    min_index = -1

    for i in range(V):
        if not visited[i] and dist[i] < min_val:
            min_val = dist[i]
            min_index = i

    return min_index


# Function to print path
def print_path(parent, j):
    if parent[j] == -1:
        print(j, end=" ")
        return
    print_path(parent, parent[j])
    print(j, end=" ")


# Dijkstra Algorithm
def dijkstra(graph, src):
    dist = [INF] * V
    visited = [False] * V
    parent = [-1] * V

    dist[src] = 0

    for _ in range(V):
        u = min_distance(dist, visited)

        if u == -1:
            print("Graph may be disconnected")
            return

        visited[u] = True

        for v in range(V):
            if (not visited[v] and graph[u][v] != 0 and dist[u] != INF and dist[u] + graph[u][v] < dist[v]):
                dist[v] = dist[u] + graph[u][v]
                parent[v] = u

    # Output
    print("Vertex\tDistance\tPath")
    for i in range(V):
        if dist[i] == INF:
            print(f"{i}\tINF\t\tNo Path")
        else:
            print(f"{i}\t\t{dist[i]}\t\t\t", end="")
            print_path(parent, i)
            print()

graph = [
    [0, 10, 0, 30, 100],
    [10, 0, 50, 0, 0],
    [0, 50, 0, 20, 10],
    [30, 0, 20, 0, 60],
    [100, 0, 10, 60, 0]
]

dijkstra(graph, 0)