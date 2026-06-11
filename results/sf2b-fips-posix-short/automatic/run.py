import pandas as pd
import matplotlib.pyplot as plt
import glob

# parse args command line python run.py label=filename label2=filename2 ...
import argparse

argparser = argparse.ArgumentParser(description='Process some integers.')
argparser.add_argument('labels', metavar='label', type=str, nargs='+',
                        help='labels for the files to be processed')

args = argparser.parse_args()

labels = {}
# split args strings by '='
for label in args.labels:
    if '=' in label:
        key, value = label.split('=')
        labels[key] = value
    else:
        print(f"Invalid argument format: {label}. Expected format is label=filename.")
        exit(1)

dfs = {}
time_axis = {}

# for all keys in labels
for key, value in labels.items():
    # check if the file exists
    try:
        with open(value, "r") as f:
            lines = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"File {value} not found.")
        exit(1)

    # remove the bottom lines until we hit the first line with "XDP_ABORTED"
    while lines and not lines[-1].startswith("XDP_ABORTED"):
        lines.pop(-1)
    lines.pop(-1)

    # remove the first lines until we hit the first line with "XDP_ABORTED"
    while lines and not lines[0].startswith("XDP_ABORTED"):
        lines.pop(0)

    data = []

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


    # Create a cumulative time index
    df['cumulative_time'] = df['time diff'].cumsum()

    # Get unique time values per group of 3 lines (1 per action group)
    # So we take every third row's cumulative_time as the time step
    time_axis[key] = df['cumulative_time'][df['Action'] == 'XDP_ABORTED'].reset_index(drop=True)

    # Build one DataFrame per action
    actions = df['Action'].unique()
    dfs[key] = {}

    for action in actions:
        dfs[key][action] = df[df['Action'] == action]['packets'].reset_index(drop=True)

# Plotting
plt.figure(figsize=(10, 6))
for key, data in dfs.items():
    for action in actions:
        y = dfs[key][action].rolling(window=10, min_periods=1).mean()
        plt.plot(time_axis[key], y, label=key+":"+action)

plt.title("Packets Over Cumulative Time by Action")
plt.xlabel("Cumulative Time (s)")
plt.ylabel("Packets")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()
# # Define the path where CSV files are stored
# csv_files = glob.glob("./*.3.csv")  # Change to the actual path
#
# plt.figure(figsize=(10, 6))
# column_names = ["Action", "total packets", "packets", "time diff"]
# # Process each CSV file
# for file in csv_files:
#     # Read the CSV file
#     df = pd.read_csv(file, delimiter=';', names=column_names)  # Ensure the delimiter matches your file format
#     print(df)
#     
#     # Compute cumulative sum for x-axis
#     df['x'] = df['time diff'].cumsum()
#     
#     # Compute rolling average for packets column
#     df['y'] = df['packets'].rolling(window=100, min_periods=1).mean()
#     
#     # Extract filename for labeling
#     
#     action_label = df["Action"].iloc[0]
#     # Plot the line
#     plt.plot(df['x'], df['y'], label=action_label)
#
# # Customize the plot
# plt.xlabel("Cumulative Time")
# plt.ylabel("Running Average of Packets")
# plt.title("Line Graph of Packets over Time")
# plt.legend()
# plt.grid(True)
#
# # Show the plot
# # plt.show()
#
# # Adjust layout

# Save the plot to a PDF
plt.savefig('static-ipc.pdf')
