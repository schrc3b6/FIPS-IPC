import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import argparse
import sys
from itertools import cycle

def plot_nonzero_metrics(csv_path, output_pdf):
    # Read the CSV file
    try:
        df = pd.read_csv(csv_path, sep=';')
    except Exception as e:
        print(f"Error reading {csv_path}: {e}")
        sys.exit(1)
    
    # Drop completely empty columns
    df = df.dropna(how='all', axis=1)
    if 'Unnamed: 33' in df.columns:
        df = df.drop(columns=['Unnamed: 33'])

    # Convert the timestamp to datetime using the exact format
    try:
        df['timestamp'] = pd.to_datetime(df['timestamp'], format='%Y-%m-%d %H:%M:%S:%f')
    except Exception as e:
        print(f"Warning: Could not convert timestamp to datetime. X-axis formatting may fail. ({e})")

    # Separate non-zero columns into packets and bytes
    packet_cols = []
    byte_cols = []
    
    for col in df.columns:
        if col != 'timestamp':
            if (df[col].fillna(0) != 0).any():
                if 'packets' in col.lower():
                    packet_cols.append(col)
                elif 'bytes' in col.lower():
                    byte_cols.append(col)
                
    if not packet_cols and not byte_cols:
        print("No non-zero data columns found to plot.")
        sys.exit(0)

    print(f"Found {len(packet_cols)} non-zero packet metrics and {len(byte_cols)} non-zero byte metrics.")

    # Figure setup 
    fig, axes = plt.subplots(nrows=2, ncols=1, figsize=(16, 12), sharex=True)
    
    # Define a list of distinct line styles to cycle through
    # '-' = solid, '--' = dashed, '-.' = dash-dot, ':' = dotted
    line_styles = ['-', '--', '-.', ':']
    
    # ---------------------------
    # Subplot 1: Packets
    # ---------------------------
    if packet_cols:
        # Create an independent cycle iterator for the packet plot
        style_cycler = cycle(line_styles)
        for col in packet_cols:
            axes[0].plot(
                df['timestamp'], 
                df[col], 
                linewidth=2.0, 
                alpha=0.7, 
                linestyle=next(style_cycler), 
                label=col
            )
        axes[0].legend(loc='center left', bbox_to_anchor=(1.02, 0.5), borderaxespad=0.)
    
    axes[0].set_title('Packet Metrics', fontsize=14, fontweight='bold')
    axes[0].set_ylabel('Packets')
    axes[0].grid(True, linestyle='--', alpha=0.5)
    
    # ---------------------------
    # Subplot 2: Bytes
    # ---------------------------
    if byte_cols:
        # Create an independent cycle iterator for the byte plot
        style_cycler = cycle(line_styles)
        for col in byte_cols:
            axes[1].plot(
                df['timestamp'], 
                df[col], 
                linewidth=2.0, 
                alpha=0.7, 
                linestyle=next(style_cycler), 
                label=col
            )
        axes[1].legend(loc='center left', bbox_to_anchor=(1.02, 0.5), borderaxespad=0.)
        
    axes[1].set_title('Byte Metrics', fontsize=14, fontweight='bold')
    axes[1].set_ylabel('Bytes')
    axes[1].grid(True, linestyle='--', alpha=0.5)
        
    # ---------------------------
    # X-Axis Formatting
    # ---------------------------
    plt.xlabel('Timestamp', fontsize=12)
    
    # Force a tick every 5 seconds and format it as Hour:Minute:Second
    axes[1].xaxis.set_major_locator(mdates.SecondLocator(interval=5))
    axes[1].xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    # Save output
    plt.savefig(output_pdf, format='pdf', bbox_inches='tight')
    print(f"Successfully saved plot to {output_pdf}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plot non-zero network traffic grouped by packets and bytes, save to PDF.")
    parser.add_argument("csv_file", help="Path to the input CSV file")
    parser.add_argument("output_pdf", help="Path where the output PDF will be saved")
    
    args = parser.parse_args()
    plot_nonzero_metrics(args.csv_file, args.output_pdf)
