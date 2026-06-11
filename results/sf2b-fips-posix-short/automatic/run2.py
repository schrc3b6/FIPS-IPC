import pandas as pd

# Datei einlesen
with open("deine_datei.txt", "r") as f:
    lines = [line.strip() for line in f if line.strip()]

data = []

# Daten blockweise (je 3 Zeilen pro Zeitstempel) verarbeiten
for i in range(0, len(lines), 3):
    block = lines[i:i+3]
    entries = []
    for line in block:
        parts = line.split()
        print(parts)  # Debug-Ausgabe
        action = parts[0]
        total_packets = int(parts[1].replace(",", ""))
        packets = int(parts[2].replace(",", ""))
        time_diff = float(parts[3])
        entries.append((action, total_packets, packets, time_diff))
    
    # Block nur hinzufügen, wenn total_packets nicht bei allen 0 ist
    if not all(entry[1] == 0 for entry in entries):
        data.extend(entries)

# DataFrame erstellen
df = pd.DataFrame(data, columns=["Action", "total packets", "packets", "time diff"])

print(df)
