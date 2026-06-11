import argparse
import os
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

def get_median_row(group):
    # Find the row where the 'lines' value is closest to the median of the group
    median_val = group['lines'].median()
    idx = (group['lines'] - median_val).abs().idxmin()
    return group.loc[idx]

def main():
    parser = argparse.ArgumentParser(description="Process networking CSVs and generate PDF plots.")
    parser.add_argument('main_csv', help="Path to the main.csv file")
    parser.add_argument('bluefield_dir', help="Path to the bluefield directory")
    parser.add_argument('switch_dir', help="Path to the switch directory (unused in plot but required as arg)")
    parser.add_argument('output_pdf', help="Path to the output PDF file")
    
    args = parser.parse_args()

    # 1. Read the main CSV
    df_main = pd.read_csv(args.main_csv, sep=';')

    # 2. Filter main dataset to keep only the row with the median 'lines' per 'kind' and 'interval'
    df_filtered = (
        df_main.groupby(['kind', 'interval'], group_keys=False)
        .apply(get_median_row)
        .reset_index(drop=True)
    )

    extracted_data = []

    # 3. Process the corresponding Bluefield files
    for _, row in df_filtered.iterrows():
        bf_filename = row['filename']
        bf_path = os.path.join(args.bluefield_dir, bf_filename)
        
        if not os.path.exists(bf_path):
            print(f"Warning: File not found at {bf_path}. Skipping.")
            continue
            
        # Read the bluefield file
        df_bf = pd.read_csv(bf_path, sep=';')
        
        # Drop 'timestamp' and empty trailing columns (Unnamed from trailing semicolons)
        cols_to_drop = [c for c in df_bf.columns if 'Unnamed' in c or c == 'timestamp']
        df_bf = df_bf.drop(columns=cols_to_drop, errors='ignore')
        
        # Convert all sums into packets/bytes per second using duration from main CSV
        # Assuming the rows in bluefield are measurements over time, so we sum them
        totals = df_bf.sum(numeric_only=True)
        rates_per_second = totals / row['duration']
        
        # Store records with identifiers
        record = {
            'kind': row['kind'],
            'interval': row['interval']
        }
        record.update(rates_per_second.to_dict())
        extracted_data.append(record)
        
    if not extracted_data:
        print("No valid data could be extracted. Exiting.")
        return

    # 4. Prepare data for plotting
    df_plot = pd.DataFrame(extracted_data)
    
    # Identify data columns (excluding identifiers)
    data_cols = [c for c in df_plot.columns if c not in ['kind', 'interval']]
    
    # Filter for columns that actually contain non-null and non-zero data
    valid_cols = [c for c in data_cols if df_plot[c].notna().any() and df_plot[c].sum() > 0]

    if not valid_cols:
        print("No non-null/non-zero data found to plot. Exiting.")
        return

    # 5. Generate plots
    num_plots = len(valid_cols)
    fig, axes = plt.subplots(num_plots, 1, figsize=(10, 4 * num_plots), sharex=True)
    
    # Ensure axes is iterable even if there's only 1 valid column
    if num_plots == 1:
        axes = [axes]

    for ax, col in zip(axes, valid_cols):
        # Plot one line per 'kind'
        for kind, group in df_plot.groupby('kind'):
            # Sort by interval to ensure continuous line plots
            group = group.sort_values('interval')
            ax.plot(group['interval'], group[col], marker='o', label=kind)
            
        ax.set_title(col)
        #set log scale for x-axis 
        ax.set_xscale('log')
        ax.set_ylabel('Rate (per second)')
        ax.grid(True, linestyle='--', alpha=0.7)
        ax.legend(title='Kind')

    axes[-1].set_xlabel('Interval')
    plt.tight_layout()
    
    # 6. Save to PDF
    with PdfPages(args.output_pdf) as pdf:
        pdf.savefig(fig)
        
    print(f"Plot saved successfully to {args.output_pdf}")

if __name__ == "__main__":
    main()
