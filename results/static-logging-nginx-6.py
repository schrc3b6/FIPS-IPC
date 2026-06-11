import argparse
import pandas as pd
import matplotlib.pyplot as plt
import os

def main():
    # Setup argument parser
    parser = argparse.ArgumentParser(description="Generate relative PPS plots from measurement CSVs.")
    parser.add_argument("main_csv", help="Path to the main CSV file")
    parser.add_argument("bluefield_dir", help="Path to the bluefield directory")
    parser.add_argument("switch_dir", help="Path to the switch directory (Provided but unused in this plot)")
    parser.add_argument("output_pdf", help="Output path for the generated PDF plot")
    
    args = parser.parse_args()

    # 1. Read main CSV
    main_df = pd.read_csv(args.main_csv, sep=';')

    # 2. Filter main CSV to keep only the row with the median 'lines' for each kind/interval combination
    def get_median_row(group):
        # Sort by lines and pick the middle one to represent the median
        sorted_group = group.sort_values('lines')
        return sorted_group.iloc[len(sorted_group) // 2]
        
    df_median = main_df.groupby(['kind', 'interval'], as_index=False).apply(get_median_row).reset_index(drop=True)

    # 3. Read bluefield files and calculate values in packets per second (pps)
    flows_per_sec_list = []
    ack_push_pps_list = []
    syn_acks_pps_list = []

    for _, row in df_median.iterrows():
        bf_filename = row['filename']
        duration = row['duration']
        
        bf_path = os.path.join(args.bluefield_dir, bf_filename)
        
        # Read the bluefield file
        bf_df = pd.read_csv(bf_path, sep=';')
        
        # All values from the bluefield file should be taken from the last line
        last_row = bf_df.iloc[-1]
        
        # Convert values to packets per second
        # Note: using '0-SYNs-packets' matching your example header
        flows_per_sec = last_row['0-SYNs-packets'] / duration
        ack_push_pps = last_row['1-ACK_PUSH-packets'] / duration
        syn_acks_pps = last_row['1-SYN_ACKS-packets'] / duration
        
        flows_per_sec_list.append(flows_per_sec)
        ack_push_pps_list.append(ack_push_pps)
        syn_acks_pps_list.append(syn_acks_pps)

    df_median['flows_per_sec'] = flows_per_sec_list
    df_median['ack_push_pps'] = ack_push_pps_list
    df_median['syn_acks_pps'] = syn_acks_pps_list

    # 4. Find the reference '1-SYN_ACKS-packets' values of kind 'none' for each interval
    df_none = df_median[df_median['kind'] == 'none']
    none_ref_dict = dict(zip(df_none['interval'], df_none['syn_acks_pps']))

    # 5. Calculate the relative PPS for the y-axis
    def calc_relative_pps(row):
        interval = row['interval']
        # Divide by '1-SYN_ACKS-packets' of kind 'none' (for the same interval)
        if interval in none_ref_dict and none_ref_dict[interval] != 0:
            return row['ack_push_pps'] / none_ref_dict[interval]
        return None

    df_median['relative_pps'] = df_median.apply(calc_relative_pps, axis=1)

    # 6. Generate the Plot
    plt.figure(figsize=(10, 6))
    
    # A list of distinct markers to ensure each line is different
    markers = ['o', 's', '^', 'D', 'v', 'p', '*', 'X', 'h', '+']
    
    kinds = df_median['kind'].unique()
    for i, kind in enumerate(kinds):
        # Filter for the current kind and sort by x-axis so lines draw properly from left to right
        kind_df = df_median[df_median['kind'] == kind].dropna(subset=['relative_pps']).sort_values('flows_per_sec')
        
        plt.plot(kind_df['flows_per_sec'], kind_df['relative_pps'], 
                 marker=markers[i % len(markers)], label=kind, linestyle='-', markersize=6)

    # Plot formatting
    plt.xlabel('Flows per Second (0-SYNs-packets / duration)')
    plt.ylabel('Relative PPS (1-ACK_PUSH-pps / None 1-SYN_ACKS-pps)')
    plt.title('Relative Packets Per Second vs. Flows Per Second')
    plt.legend(title="Kind")
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Save the output
    plt.tight_layout()
    plt.savefig(args.output_pdf, format='pdf')
    print(f"Plot saved successfully to {args.output_pdf}")

if __name__ == "__main__":
    main()
