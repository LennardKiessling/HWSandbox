import numpy as np
import matplotlib.pyplot as plt

sandbox_anzahl_values = np.linspace(1, 50, 50)
abopreis_values = np.linspace(1, 300, 50)

P, S = np.meshgrid(abopreis_values, sandbox_anzahl_values)

BE = ((12 * S * P) - (262.80 * S)) - (612 * S)

fig = plt.figure(figsize=(10, 7))
ax = fig.add_subplot(111, projection='3d')

surf = ax.plot_surface(P, S, BE, cmap='viridis')

ax.set_xlabel('Abopreis (€)', labelpad=15)
ax.set_ylabel('Sandboxanzahl', labelpad=15)
ax.set_zlabel('Betriebsergebnis (€)', labelpad=15)
ax.set_title('Betriebsergebnis in Abhängigkeit vom Abopreis und Sandboxanzahl', pad=20)

fig.colorbar(surf)

plt.show()
