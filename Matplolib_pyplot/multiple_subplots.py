import matplotlib.pyplot as plt
import numpy as np

x = np.arange(1, 5)

plt.figure(figsize=(8, 6))

# Subplot 1
plt.subplot(2, 2, 1)
plt.plot(x, x)
plt.title("Linear")

# Subplot 2
plt.subplot(2, 2, 2)
plt.plot(x, x**2)
plt.title("Square")

# Subplot 3
plt.subplot(2, 2, 3)
plt.plot(x, x**3)
plt.title("Cube")

# Subplot 4
plt.subplot(2, 2, 4)
plt.plot(x, np.sqrt(x))
plt.title("Square Root")

plt.tight_layout()
plt.show()
