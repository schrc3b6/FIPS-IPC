import argparse
import os
import pandas as pd
import matplotlib.pyplot as plt
import math

def get_median_row(group):
    """
    Returns the row with the median 'lines' value.
    If there's an even number of rows, it picks the lower middle one.
    """
    sorted_group = group.sort_values('lines')
    median_idx = len(sorted_group) // 2
    return sorted_group.iloc[median_idx]

def main():
    parser = argparse.ArgumentParser(description="Generate plots from measurement CSVs.")
    parser.add_argument('main_csv', type=str, help="Path to the main CSV file")
    parser.add_argument('bluefield_folder', type=str, help="Path to the bluefield folder")
    parser.add_argument('switch_folder', type=str, help="Path to the switch folder")
    parser.add_argument('output_pdf', type=str, help="Output path for the generated PDF plot")
    
    args = parser.parse_args()

    # Read the main CSV
    # Using sep=';' as per your main CSV example
    df_main = pd.read_csv(args.main_csv, sep=';')

    # Keep only the median row according to 'lines' for each kind and interval
    df_median = df_main.groupby(['kind', 'interval']).apply(get_median_row).reset_index(drop=True)

    plot_data = []
    bluefield_columns = set()

    for _, row in df_median.iterrows():
        kind = row['kind']
        duration = row['duration']
        filename = row['filename']
        
        bf_path = os.path.join(args.bluefield_folder, filename)
        # sw_path = os.path.join(args.switch_folder, filename) # Switch folder passed but parsing omitted for plotting

        if not os.path.exists(bf_path):
            print(f"Warning: File {bf_path} not found. Skipping.")
            continue

        # Read the bluefield file
        df_bf = pd.read_csv(bf_path, sep=';')
        
        # Clean up empty columns (like trailing semicolons)
        df_bf = df_bf.dropna(axis=1, how='all')

        # Calculate values (sum the column and divide by duration to get PPS / Bytes-per-sec)
        # Exclude 'timestamp' from conversion
        row_data = {'kind': kind}
        
        # Check for SYN packets column name
        syn_col = '0-SYNs-packets' if '0-SYNs-packets' in df_bf.columns else '0-SYN-packets'
        
        if syn_col in df_bf.columns:
            flows_per_sec = df_bf.sort_values('timestamp').tail(1)[syn_col].iloc[0]/ duration
            row_data['flows_per_second'] = flows_per_sec
        else:
            print(f"Warning: SYN packets column not found in {filename}. Skipping.")
            continue
            
        for col in df_bf.columns:
            if col.lower() != 'timestamp' and not col.startswith('Unnamed'):
                bluefield_columns.add(col)
                # Convert to units per second
                val_per_sec = df_bf.sort_values('timestamp').tail(1)[col].iloc[0] / duration
                row_data[col] = val_per_sec
                
        plot_data.append(row_data)

    if not plot_data:
        print("No valid data found to plot.")
        return

    # Convert aggregated data into a dataframe for easier plotting
    df_plot = pd.DataFrame(plot_data)

    # Filter to only the columns that actually have non-null (and non-zero if preferred) data across the dataset
    cols_to_plot = [col for col in bluefield_columns if df_plot[col].notna().any()]
    cols_to_plot.sort()

    # Determine grid size for subplots
    num_plots = len(cols_to_plot)
    cols = 3 if num_plots >= 3 else num_plots
    rows = math.ceil(num_plots / cols)

    fig, axes = plt.subplots(rows, cols, figsize=(6 * cols, 5 * rows))
    
    # Flatten axes array for easy iteration, handling the case where axes might not be a 2D array
    if num_plots == 1:
        axes = [axes]
    else:
        axes = axes.flatten()

    kinds = df_plot['kind'].unique()

    for idx, col in enumerate(cols_to_plot):
        ax = axes[idx]
        
        for kind in kinds:
            df_kind = df_plot[df_plot['kind'] == kind].sort_values('flows_per_second')
            
            # Plot only if we have data for this kind
            if not df_kind.empty:
                ax.plot(df_kind['flows_per_second'], df_kind[col], marker='o', label=kind)
        
        ax.set_title(col)
        ax.set_xlabel('Flows per second')
        # ax.set_xscale('log')  # Set x-axis to logarithmic scale
        # ax.set_yscale('log')  # Set x-axis to logarithmic scale
        
        # Set y-label depending on whether it's packets or bytes
        if 'bytes' in col.lower():
            ax.set_ylabel('Bytes per second (Bps)')
        else:
            ax.set_ylabel('Packets per second (pps)')
            
        ax.grid(True, linestyle='--', alpha=0.7)
        ax.legend()

    # Hide any unused subplots
    for idx in range(num_plots, len(axes)):
        fig.delaxes(axes[idx])

    plt.tight_layout()
    plt.savefig(args.output_pdf, format='pdf', bbox_inches='tight')
    print(f"Plot successfully saved to {args.output_pdf}")

if __name__ == '__main__':
    main()
