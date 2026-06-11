import argparse
import os
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

def get_median_row(group):
    """
    Finds the row in a dataframe group where 'lines' is closest to the median 
    value of 'lines' for that group.
    """
    median_val = group['lines'].median()
    # Return the row whose 'lines' value is closest to the calculated median
    idx = (group['lines'] - median_val).abs().idxmin()
    return group.loc[idx]

def main():
    parser = argparse.ArgumentParser(description="Process measurement CSVs and generate a plot.")
    parser.add_argument("main_csv", help="Path to the main CSV file")
    parser.add_argument("bluefield_folder", help="Path to the directory containing bluefield CSVs")
    parser.add_argument("switch_folder", help="Path to the directory containing switch CSVs")
    parser.add_argument("output_pdf", help="Output path for the generated PDF plot")
    
    args = parser.parse_args()

    # 1. Load Main CSV
    df_main = pd.read_csv(args.main_csv, sep=';')

    # 2. Filter to use only the median 'lines' measurement for each kind/interval combination
    df_filtered = df_main.groupby(['kind', 'interval']).apply(get_median_row).reset_index(drop=True)

    # 3. Extract metrics from the Bluefield files
    results = []
    
    for _, row in df_filtered.iterrows():
        kind = row['kind']
        interval = row['interval']
        duration = row['duration']
        filename = row['filename']
        
        bf_path = os.path.join(args.bluefield_folder, filename)
        
        if not os.path.exists(bf_path):
            print(f"Warning: Bluefield file not found: {bf_path}")
            continue

        # Bluefield CSVs are semicolon-separated 
        df_bf = pd.read_csv(bf_path, sep=';')
        
        # Get the last row of the bluefield file
        last_row = df_bf.iloc[-1]
        
        # Check column name (example header had 0-SYNs-packets, prompt asked for 0-SYN-packets)
        syn_col = '0-SYNs-packets' if '0-SYNs-packets' in df_bf.columns else '0-SYN-packets'
        
        # Extract raw values
        syn_packets = last_row[syn_col]
        ack_push_packets = last_row['1-ACK_PUSH-packets']
        
        # Convert to packets per second (divide by duration)
        flows_per_sec = syn_packets / duration
        ack_push_pps = ack_push_packets / duration
        
        results.append({
            'kind': kind,
            'interval': interval,
            'flows_per_sec': flows_per_sec,
            'ack_push_pps': ack_push_pps
        })

    df_results = pd.DataFrame(results)

    if df_results.empty:
        print("Error: No data successfully parsed from Bluefield files.")
        return

    # 4. Normalize the Y-axis against kind == 'none'
    # Extract the 'none' values for each interval to use as the denominator
    none_data = df_results[df_results['kind'] == 'none'][['interval', 'ack_push_pps']]
    none_data = none_data.rename(columns={'ack_push_pps': 'none_ack_push_pps'})

    if none_data.empty:
        print("Error: No data found for kind 'none'. Cannot calculate relative values.")
        return

    # Merge the 'none' baseline back into the main results dataframe based on interval
    df_plot = pd.merge(df_results, none_data, on='interval', how='left')
    
    # Calculate the relative PPS
    df_plot['relative_pps'] = df_plot['ack_push_pps'] / df_plot['none_ack_push_pps']

    # 5. Generate the Line Plot
    plt.figure(figsize=(10, 6))

    for kind, group in df_plot.groupby('kind'):
        # Sort by flows_per_sec so the line connects properly from left to right
        # filter out any rows with flows_per_sec <= 10000
        group = group[group['flows_per_sec'] > 100000]
        group = group.sort_values('flows_per_sec')
        
        # Optional: You can skip plotting 'none' since it will always be a flat line at 1.0, 
        # but plotting it is good for a visual baseline.
        plt.plot(group['flows_per_sec'], group['relative_pps'], marker='o', label=kind)

    # Formatting the plot
    # y axis from 0 to 100
    plt.ylim(0, 1.05)
    plt.xlabel('Flows per second (0-SYNs-packets PPS)')
    plt.ylabel('Relative PPS (1-ACK_PUSH-packets vs "none")')
    plt.title('Relative ACK_PUSH PPS vs Flows per Second')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.xscale('log')  # Use logarithmic scale for better visibility of differences
    plt.legend(title='Kind')
    plt.tight_layout()

    # 6. Save as PDF
    plt.savefig(args.output_pdf, format='pdf')
    print(f"Plot successfully saved to {args.output_pdf}")

if __name__ == "__main__":
    main()
