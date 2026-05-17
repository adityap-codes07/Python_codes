import numpy as np
p = np.array([12, 15, 18, 21, 24])
print(p)
r = np.diff(p)/p[:-1]
print(r)
avg = np.mean(r)
print(avg)
ri = np.std(r)
print(ri)


print("Avg Returns :", avg)
print("Risk: ", ri)