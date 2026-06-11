import pandas as pd
import matplotlib.pyplot as plt
import glob

# Define the path where CSV files are stored
csv_files = glob.glob("./*.3.csv")  # Change to the actual path

plt.figure(figsize=(10, 6))
column_names = ["Action", "total packets", "packets", "time diff"]
# Process each CSV file
for file in csv_files:
    # Read the CSV file
    df = pd.read_csv(file, delimiter=';', names=column_names)  # Ensure the delimiter matches your file format
    print(df)
    
    # Compute cumulative sum for x-axis
    df['x'] = df['time diff'].cumsum()
    
    # Compute rolling average for packets column
    df['y'] = df['packets'].rolling(window=100, min_periods=1).mean()
    
    # Extract filename for labeling
    
    action_label = df["Action"].iloc[0]
    # Plot the line
    plt.plot(df['x'], df['y'], label=action_label)

# Customize the plot
plt.xlabel("Cumulative Time")
plt.ylabel("Running Average of Packets")
plt.title("Line Graph of Packets over Time")
plt.legend()
plt.grid(True)

# Show the plot
# plt.show()

# Adjust layout
plt.tight_layout()

# Save the plot to a PDF
plt.savefig('static-ipc.pdf')
