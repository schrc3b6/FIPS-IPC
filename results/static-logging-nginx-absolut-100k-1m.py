import argparse
import pandas as pd
import matplotlib.pyplot as plt
import os

def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Generate plot from network measurement CSVs.")
    parser.add_argument("main_csv", help="Path to the main CSV file")
    parser.add_argument("bluefield_dir", help="Path to the bluefield folder")
    parser.add_argument("switch_dir", help="Path to the switch folder (provided but unused in this specific plot)")
    parser.add_argument("output_pdf", help="Output path for the generated PDF plot")

    args = parser.parse_args()

    # Read the main CSV file
    main_df = pd.read_csv(args.main_csv, sep=';')

    # Function to get the median row based on the 'lines' column
    def get_median_row(group):
        sorted_group = group.sort_values(by='lines')
        # Select the middle row to represent the median measurement
        return sorted_group.iloc[len(sorted_group) // 2]

    # Group by kind and interval, then apply the median filter
    median_df = main_df.groupby(['kind', 'interval']).apply(get_median_row).reset_index(drop=True)

    plot_data = []

    # Iterate through the filtered main dataframe
    for _, row in median_df.iterrows():
        kind = row['kind']
        duration = row['duration']
        filename = row['filename']

        bf_path = os.path.join(args.bluefield_dir, filename)

        if not os.path.exists(bf_path):
            print(f"Warning: Bluefield file {bf_path} not found. Skipping.")
            continue

        # Read the bluefield CSV
        bf_df = pd.read_csv(bf_path, sep=';')

        # Extract the last line of the bluefield file
        last_line = bf_df.iloc[-1]

        # Handle naming inconsistency between text prompt ("0-SYN-packets") and example header ("0-SYNs-packets")
        syn_col = '0-SYNs-packets' if '0-SYNs-packets' in bf_df.columns else '0-SYN-packets'
        ack_push_col = '1-ACK_PUSH-packets'

        try:
            last_syn_packets = last_line[syn_col]
            last_ack_push_packets = last_line[ack_push_col]
        except KeyError as e:
            print(f"Warning: Missing column {e} in {bf_path}. Skipping.")
            continue

        # Convert values to packets per second using the duration from the main CSV
        flows_per_second = last_syn_packets / duration
        http_responses_per_second = last_ack_push_packets / duration

        # Apply the filter constraint for the X-axis (100,000 to 1,000,000)
        #if 100000 <= flows_per_second <= 1000000:
        if flows_per_second <= 1000000:
            plot_data.append({
                'kind': kind,
                'flows_per_second': flows_per_second,
                'http_responses_per_second': http_responses_per_second
            })

    if not plot_data:
        print("Error: No data points fell within the specified flows per second range (100,000 to 1,000,000).")
        return

    # add 0,0 point for each kind to ensure the plot starts at the origin
    kinds = median_df['kind'].unique()
    for kind in kinds:
        plot_data.append({
            'kind': kind,
            'flows_per_second': 0,
            'http_responses_per_second': 0
        })


    # Convert collected data back to a DataFrame for plotting
    plot_df = pd.DataFrame(plot_data)

    # Initialize Plot
    plt.figure(figsize=(12, 7))

    # Group by 'kind' to draw one line per kind
    for kind, group in plot_df.groupby('kind'):
        # Sort by X-axis values before plotting so the line connects correctly from left to right
        sorted_group = group.sort_values(by='flows_per_second')
        plt.plot(
            sorted_group['flows_per_second'], 
            sorted_group['http_responses_per_second'], 
            marker='o', 
            linewidth=2,
            label=kind
        )

    # Styling the plot
    plt.xlabel("Flows per Second (0-SYNs-packets / s)")
    plt.ylabel("HTTP Responses per Second (1-ACK_PUSH-packets / s)")
    plt.title("Absolute HTTP Responses vs. Flows per Second")
    plt.legend(title="Kind")
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Ensure standard formatting for the axes to prevent scientific notation if desired
    plt.ticklabel_format(style='plain', axis='x')
    plt.ticklabel_format(style='plain', axis='y')

    # Save to PDF
    plt.tight_layout()
    plt.savefig(args.output_pdf, format='pdf')
    print(f"Success! Plot generated and saved to {args.output_pdf}")

if __name__ == '__main__':
    main()
