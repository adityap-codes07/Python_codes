V = 5
INF = float('inf')

cost = [
    [INF, 2, INF, 6, INF],
    [2, INF, 3, 8, 5],
    [INF, 3, INF, INF, 7],
    [6, 8, INF, INF, 9],
    [INF, 5, 7, 9, INF]
]

near = [0] * V
t = [[0, 0] for _ in range(V - 1)]

# Step 1: Find global minimum edge
min_val = INF
u, v = 0, 0

for i in range(V):
    for j in range(i, V):
        if cost[i][j] < min_val:
            min_val = cost[i][j]
            u, v = i, j

t[0][0] = u
t[0][1] = v

# Initialize near[]
for i in range(V):
    if cost[i][u] < cost[i][v]:
        near[i] = u
    else:
        near[i] = v

near[u] = near[v] = -1

# Build MST
for i in range(1, V - 1):
    min_val = INF
    k = -1

    for j in range(V):
        if near[j] != -1 and cost[j][near[j]] < min_val:
            min_val = cost[j][near[j]]
            k = j

    t[i][0] = k
    t[i][1] = near[k]

    near[k] = -1

    # Update near[]
    for j in range(V):
        if near[j] != -1 and cost[j][k] < cost[j][near[j]]:
            near[j] = k

# Print MST
print("Edges in MST:")
for i in range(V - 1):
    print(f"{t[i][0]} - {t[i][1]}")