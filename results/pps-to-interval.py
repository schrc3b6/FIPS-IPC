import os
import argparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from scipy.interpolate import interp1d

def calculate_interval_for_flows(target_flows, kind_data):
    """
    Calculates the estimated interval for a given flows per second.
    Interpolation is done in log-log space to match the logarithmic plot axes.
    """
    if target_flows <= 0:
        return None

    # Sort data by flows_per_sec to ensure proper interpolation
    sorted_data = kind_data.sort_values('flows_per_sec')
    
    x = sorted_data['flows_per_sec'].values
    y = sorted_data['interval'].values
    
    # Check if target is out of bounds
    if target_flows < x.min() or target_flows > x.max():
        print(f"  [Note] Target flows ({target_flows}) is outside the observed range [{x.min():.2f}, {x.max():.2f}]. Extrapolating...")
    
    # Convert to log10 space for interpolation
    log_x = np.log10(x)
    log_y = np.log10(y)
    
    # Create an interpolation function in log space
    interpolate_func = interp1d(log_x, log_y, kind='linear', fill_value="extrapolate")
    
    # Calculate and convert back from log space
    log_target = np.log10(target_flows)
    log_result = interpolate_func(log_target)
    
    return float(10**log_result)

def main():
    parser = argparse.ArgumentParser(description="Generate Interval vs Flows per Second plot or compute intervals.")
    parser.add_argument("main_csv", help="Path to the main CSV file")
    parser.add_argument("bluefield_dir", help="Path to the bluefield folder")
    parser.add_argument("switch_dir", help="Path to the switch folder")
    parser.add_argument("--output", help="Output path for the generated PDF plot", type=str)
    parser.add_argument("--values", help="List of flows per second (pps) to compute the interval for", nargs='+', type=float)
    
    args = parser.parse_args()

    if not args.output and not args.values:
        parser.error("You must provide either --output <filename>, --values <pps1 pps2 ...>, or both.")

    # Load main CSV
    main_df = pd.read_csv(args.main_csv, sep=';')

    # Find the median row based on 'lines'
    def get_median_row(group):
        return group.sort_values('lines').iloc[len(group) // 2]

    filtered_df = main_df.groupby(['kind', 'interval'], as_index=False).apply(get_median_row).reset_index(drop=True)

    plot_data = []

    # Process files
    for _, row in filtered_df.iterrows():
        kind = row['kind']
        interval = row['interval']
        duration = row['duration']
        filename = row['filename']

        bf_path = os.path.join(args.bluefield_dir, filename)
        
        if not os.path.exists(bf_path):
            continue
        
        try:
            bf_df = pd.read_csv(bf_path, sep=';')
        except Exception:
            continue
            
        syn_col = '0-SYNs-packets'
        if syn_col not in bf_df.columns:
            continue
            
        syns_packets = bf_df[syn_col].iloc[-1]
        
        if duration > 0 and syns_packets > 0:
            flows_per_sec = syns_packets / duration
            
            plot_data.append({
                'kind': kind,
                'interval': interval,
                'flows_per_sec': flows_per_sec
            })

    plot_df = pd.DataFrame(plot_data)

    if plot_df.empty:
        print("No valid data found to process. Exiting.")
        return

    # Handle the --values argument
    if args.values:
        print("\n--- Calculated Intervals ---")
        for kind, group in plot_df.groupby('kind'):
            print(f"\nKind: {kind}")
            for target_flow in args.values:
                estimated_interval = calculate_interval_for_flows(target_flow, group)
                if estimated_interval is not None:
                    print(f"  Target PPS: {target_flow} -> Estimated Interval: {estimated_interval:.4f}")

    # Handle the --output argument
    if args.output:
        plt.figure(figsize=(10, 6))
        
        for kind, group in plot_df.groupby('kind'):
            group = group.sort_values('flows_per_sec')
            plt.plot(group['flows_per_sec'], group['interval'], marker='o', label=kind)

        # Set Logarithmic scales
        plt.xscale('log')
        plt.yscale('log')

        # Formatting the plot
        plt.xlabel('Flows per Second (log scale)')
        plt.ylabel('Interval (log scale)')
        plt.title('Interval vs Flows per Second')
        plt.legend(title='Kind')
        plt.grid(True, which="both", ls="--", alpha=0.5)
        plt.tight_layout()

        # Save to PDF
        plt.savefig(args.output, format='pdf')
        print(f"\nPlot successfully saved to {args.output}")

if __name__ == "__main__":
    main()
