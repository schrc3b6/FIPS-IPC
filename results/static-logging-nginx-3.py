import argparse
import os
import pandas as pd
import matplotlib.pyplot as plt

def get_median_row(group):
    # Sort the group by 'lines' and pick the middle row to represent the median
    sorted_group = group.sort_values('lines').reset_index(drop=True)
    middle_index = len(sorted_group) // 2
    return sorted_group.iloc[middle_index]

def main():
    parser = argparse.ArgumentParser(description="Process network measurements and plot results.")
    parser.add_argument("main_csv", help="Path to the main CSV file")
    parser.add_argument("bluefield_dir", help="Path to the bluefield directory")
    parser.add_argument("switch_dir", help="Path to the switch directory")
    parser.add_argument("output_pdf", help="Output path for the generated PDF plot")
    
    args = parser.parse_args()

    # 1. Read main CSV
    df_main = pd.read_csv(args.main_csv, sep=';')

    # 2. Group by kind and interval, and extract the median row based on 'lines'
    # By applying get_median_row, we ensure we get an actual row (filename, duration, etc.)
    df_median = df_main.groupby(['kind', 'interval']).apply(get_median_row).reset_index(drop=True)

    results = []

    # 3. Process each median measurement
    for _, row in df_median.iterrows():
        kind = row['kind']
        duration = row['duration']
        filename = row['filename']
        
        bf_file = os.path.join(args.bluefield_dir, filename)
        
        # We also have the switch file path in case you need it for further additions
        # sw_file = os.path.join(args.switch_dir, filename)

        if not os.path.exists(bf_file):
            print(f"Warning: {bf_file} not found. Skipping.")
            continue
            
        # Read the bluefield file
        try:
            df_bf = pd.read_csv(bf_file, sep=';')
        except Exception as e:
            print(f"Error reading {bf_file}: {e}. Skipping.")
            exit(1)
        
        # get the total number of SYN packets and ACK_PUSH packets
        syn_packets = df_bf.sort_values('timestamp').tail(1)['0-SYNs-packets'].iloc[0]
        ack_push_packets = df_bf.sort_values('timestamp').tail(1)['1-ACK_PUSH-packets'].iloc[0]

        #syn_packets = df_bf['0-SYNs-packets'].sum()
        #ack_push_packets = df_bf['1-ACK_PUSH-packets'].sum()
        print(syn_packets, ack_push_packets)
        
        # Prevent division by zero
        if syn_packets == 0 or duration == 0:
            continue
            
        # 4. Calculate packets per second / requested metrics
        flows_per_sec = syn_packets / duration
        relative_answered_pps = ack_push_packets / syn_packets
        
        results.append({
            'kind': kind,
            'flows_per_sec': flows_per_sec,
            'relative_answered': relative_answered_pps
        })

    # Convert results to DataFrame for easy plotting
    df_plot = pd.DataFrame(results)

    if df_plot.empty:
        print("No valid data to plot.")
        return

    # 5. Create the Plot
    plt.figure(figsize=(10, 6))
    
    # Group by kind to plot one line per kind
    for kind, group in df_plot.groupby('kind'):
        # Sort by flows_per_sec (X-axis) so lines draw correctly sequentially
        group = group.sort_values('flows_per_sec')
        
        plt.plot(group['flows_per_sec'], 
                 group['relative_answered'], 
                 marker='o', 
                 linestyle='-', 
                 label=kind)

    # Styling the plot
    plt.title('Relative Answered PPS vs. Flows per Second')
    plt.xlabel('Flows per Second (0-SYNs-packets / duration)')
    plt.ylabel('Relative Answered PPS (1-ACK_PUSH / 0-SYNs)')
    plt.xscale('log')  # Use logarithmic scale for better visibility
    plt.legend(title="Kind")
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Save to PDF
    plt.tight_layout()
    plt.savefig(args.output_pdf, format='pdf')
    print(f"Plot successfully saved to {args.output_pdf}")

if __name__ == "__main__":
    main()
