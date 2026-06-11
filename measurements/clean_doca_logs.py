import os
import re
import argparse
import shutil

def process_file(filepath, output_filepath):
    # Matches the first [timestamp], ignores subsequent [...], and captures the rest
    log_pattern = re.compile(r'^\[(.*?)\](?:\[.*?\])*\s*(.*)$')
    # Matches "Wait X seconds..." anywhere in the line
    wait_pattern = re.compile(r'Wait \d+ seconds for packets to arrive', re.IGNORECASE)

    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # 1. Idempotency Check: Now explicitly checks for empty lines as well
    needs_processing = False
    for line in lines:
        # Trigger processing if the line is entirely empty or just whitespace
        if not line.strip():
            needs_processing = True
            break
        # Trigger processing if wait message or log brackets are found
        if wait_pattern.search(line) or log_pattern.match(line):
            needs_processing = True
            break

    if not needs_processing:
        print(f"Skipping (already processed or clean): {os.path.basename(filepath)}")
        if filepath != output_filepath:
            shutil.copy2(filepath, output_filepath)
        return

    # 2. Process the lines
    new_lines = []
    for line in lines:
        line_stripped = line.strip()
        
        # Explicitly drop empty lines
        if not line_stripped:
            continue

        # Drop the "Wait X seconds..." line entirely
        if wait_pattern.search(line_stripped):
            continue

        # Check if it has the logging bracket pattern
        match = log_pattern.match(line_stripped)
        if match:
            timestamp = match.group(1)
            csv_data = match.group(2)
            
            # Smart header detection
            if "print_csv_header" in line_stripped:
                new_lines.append(f"timestamp;{csv_data}\n")
            else:
                new_lines.append(f"{timestamp};{csv_data}\n")
        else:
            # Keep normal, non-empty lines intact
            new_lines.append(line)

    # 3. Save the file
    with open(output_filepath, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    
    print(f"Processed: {os.path.basename(filepath)}")


def main():
    parser = argparse.ArgumentParser(description="Clean CSVs by removing logs, wait messages, and empty lines.")
    parser.add_argument("input_dir", help="Path to the directory containing the files.")
    parser.add_argument(
        "--output_dir", 
        "-o",
        help="Directory to save processed files. If omitted, files are modified in place.", 
        default=None
    )

    args = parser.parse_args()

    input_dir = args.input_dir
    output_dir = args.output_dir

    if not os.path.isdir(input_dir):
        print(f"Error: Input directory '{input_dir}' does not exist.")
        return

    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for filename in os.listdir(input_dir):
        filepath = os.path.join(input_dir, filename)
        
        if os.path.isfile(filepath):
            out_path = os.path.join(output_dir, filename) if output_dir else filepath
            process_file(filepath, out_path)

if __name__ == "__main__":
    main()
