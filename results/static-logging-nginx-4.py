import os
import argparse
import pandas as pd
import matplotlib.pyplot as plt

def main():
    # Setup argument parser
    parser = argparse.ArgumentParser(description="Generate line plots for relative logged lines vs flows per second.")
    parser.add_argument("main_csv", help="Path to the main CSV file")
    parser.add_argument("bluefield_dir", help="Path to the bluefield folder")
    parser.add_argument("switch_dir", help="Path to the switch folder")
    parser.add_argument("output_pdf", help="Output path for the generated PDF plot")
    
    args = parser.parse_args()

    # Load main CSV
    # Using sep=';' based on the provided sample
    main_df = pd.read_csv(args.main_csv, sep=';')

    # Find the median row based on 'lines' for each kind and interval combination
    def get_median_row(group):
        # Sort the group by 'lines' and pick the middle row
        return group.sort_values('lines').iloc[len(group) // 2]

    # Apply grouping and median row selection
    filtered_df = main_df.groupby(['kind', 'interval'], as_index=False).apply(get_median_row).reset_index(drop=True)

    plot_data = []

    # Iterate over the filtered rows to process the corresponding bluefield files
    for _, row in filtered_df.iterrows():
        kind = row['kind']
        duration = row['duration']
        filename = row['filename']
        lines = row['lines']

        # Construct path to the bluefield file
        bf_path = os.path.join(args.bluefield_dir, filename)
        
        if not os.path.exists(bf_path):
            print(f"Warning: File {bf_path} not found. Skipping...")
            continue
        
        # Read the bluefield file
        try:
            bf_df = pd.read_csv(bf_path, sep=';')
        except Exception as e:
            print(f"Error reading {bf_path}: {e}")
            continue
            
        # Get the last number of '0-SYNs-packets'
        # Matching the exact header name shown in the example
        syn_col = '0-SYNs-packets'
        if syn_col not in bf_df.columns:
            print(f"Warning: Column '{syn_col}' not found in {filename}. Skipping...")
            continue
            
        syns_packets = bf_df[syn_col].iloc[-1]
        
        # Convert values and append to plot data
        if duration > 0 and syns_packets > 0:
            flows_per_sec = syns_packets / duration
            rel_logged_lines = lines / syns_packets
            
            plot_data.append({
                'kind': kind,
                'flows_per_sec': flows_per_sec,
                'rel_logged_lines': rel_logged_lines
            })

    # Create DataFrame for plotting
    plot_df = pd.DataFrame(plot_data)

    # Plotting
    plt.figure(figsize=(10, 6))
    
    if not plot_df.empty:
        # Group by kind and plot a line for each
        for kind, group in plot_df.groupby('kind'):
            # Sort by X axis (flows_per_sec) before plotting the line
            group = group.sort_values('flows_per_sec')
            plt.plot(group['flows_per_sec'], group['rel_logged_lines'], marker='o', label=kind)

    # Formatting the plot
    plt.xlabel('Flows per Second')
    plt.ylabel('Relative Logged Lines (lines / 0-SYNs-packets)')
    plt.title('Relative Logged Lines vs Flows per Second')
    plt.legend(title='Kind')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.xscale('log')  # Use logarithmic scale for better visibility of differences
    plt.tight_layout()

    # Save to PDF
    plt.savefig(args.output_pdf, format='pdf')
    print(f"Plot successfully saved to {args.output_pdf}")

if __name__ == "__main__":
    main()
