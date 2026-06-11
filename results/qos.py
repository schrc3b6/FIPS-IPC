import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import re
from pathlib import Path


START_MARK = "XDP_ABORTED"

def _read_trimmed_lines(path: Path) -> list[str]:
    lines = [ln.strip() for ln in path.read_text().splitlines() if ln.strip()]
    while lines and not lines[-1].startswith(START_MARK):
        lines.pop()
    if lines:
        lines.pop()  # drop the last START_MARK itself
    while lines and not lines[0].startswith(START_MARK):
        lines.pop(0)
    if not lines:
        raise ValueError(f"No data blocks found (missing {START_MARK}) in {path}")
    return lines

def _detect_block_size(lines: list[str]) -> int:
    if not lines or not lines[0].startswith(START_MARK):
        raise ValueError("Lines must start with START_MARK to detect block size.")
    for i in range(1, len(lines)):
        if lines[i].startswith(START_MARK):
            return i
    raise ValueError("Could not detect block size (only one START_MARK found).")

def _file_to_long_df(path: Path, drop_all_zero_blocks: bool = True) -> pd.DataFrame:
    """
    Returns long DF with columns:
      block | Action | total_packets | packets | time diff
    """
    lines = _read_trimmed_lines(path)
    block_size = _detect_block_size(lines)

    rows = []
    block_idx = -1

    for i in range(0, len(lines) - (len(lines) % block_size), block_size):
        block = lines[i:i + block_size]

        parsed = []
        for ln in block:
            parts = ln.split()
            if len(parts) < 4:
                continue
            action = parts[0]
            total_packets = int(parts[1].replace(",", ""))
            packets = int(parts[2].replace(",", ""))
            time_diff = float(parts[3])
            parsed.append((action, total_packets, packets, time_diff))

        if not parsed:
            continue

        if drop_all_zero_blocks and all(tp < 10 for _, tp, _, _ in parsed):
            # Skip entirely idle blocks (prevents large time offsets at start if early blocks are idle)
            continue

        block_idx += 1
        for action, total_packets, packets, time_diff in parsed:
            rows.append((block_idx, action, total_packets, packets, time_diff))

    if not rows:
        raise ValueError(f"No usable rows parsed from {path}")

    df = pd.DataFrame(rows, columns=["block", "Action", "total_packets", "packets", "time diff"])
    return df

def build_and_save_per_action_time(
    file_dict: dict[str, str],
    window: int = 50,
    min_periods: int = 1,
    out_sep: str = ";",
    normalize_time: bool = False,
    drop_all_zero_blocks: bool = True,
    format: str = "long",  # "long" (tidy) or "wide"
) -> dict[str, pd.DataFrame]:
    """
    One CSV per key. Per-action cumulative time is computed:
        time_action = groupby(Action)['time diff'].cumsum()
    Rolling mean is applied to 'packets' per action.

    format="long": columns [block, action, time, value] (+ raw if you need)
    format="wide": columns [block, time__<act>..., <act>...] (one time column per action)
    """
    out = {}

    for key, file_path in file_dict.items():
        path = Path(file_path)
        df_long = _file_to_long_df(path, drop_all_zero_blocks=drop_all_zero_blocks)

        # per-action cumulative time
        df_long["time_action"] = df_long.groupby("Action")["time diff"].cumsum()
        if normalize_time:
            df_long["time_action"] = df_long["time_action"] - df_long.groupby("Action")["time_action"].transform("first")

        # rolling mean per action (on packets)
        df_long["value"] = (
            df_long.sort_values(["Action", "block"])
                  .groupby("Action")["packets"]
                  .transform(lambda s: s.rolling(window=window, min_periods=min_periods, center=True).mean())
                  # .transform(lambda s: s.groupby((s.index // 10)).transform("mean"))
        )
        df_long = df_long.iloc[::50, :].reset_index(drop=True)
        df_long["value"] = df_long["value"]/(1000000+42000)

        if format == "long":
            # tidy output: one row per (block, action)
            combined = (
                df_long[["block", "Action", "time_action", "value"]]
                .rename(columns={"Action": "action", "time_action": "time"})
                .sort_values(["block", "action"])
                .reset_index(drop=True)
            )
        elif format == "wide":
            # wide with separate time columns per action
            wide_values = (
                df_long.pivot_table(index="block", columns="Action", values="value", aggfunc="first")
                       .sort_index()
            )
            wide_times = (
                df_long.pivot_table(index="block", columns="Action", values="time_action", aggfunc="first")
                       .sort_index()
            )
            # prefix time columns so both can co-exist
            wide_times.columns = [f"time__{c}" for c in wide_times.columns]
            combined = pd.concat([wide_times, wide_values], axis=1).reset_index()
            # time_cols = combined.filter(like="time__")               # all cols starting with "time__"
            # combined = combined[ time_cols.lt(20).all(axis=1) ]      # keep only rows where *all* < 20
        else:
            raise ValueError("format must be 'long' or 'wide'")

        # save
        safe_suffix = str(path).replace("/", "_")
        out_name = f"./tmp/{key}_{safe_suffix}.csv"
        combined.to_csv(out_name, sep=out_sep, index=False)
        out[key] = combined

    return out


# Step 1: Load main CSV data
data = pd.read_csv("./data/results.csv", sep=";")

# Step 2: Client map for index -> number of clients
client_map = [0, 2**18, 2**17, 2**16, 2**15, 2**14, 2**13, 2**12]
MAX_QUERIES = 360 * 70000  # 25,200,000

# Step 3: Extract query count from file
def extract_query_count(filepath):
    try:
        with open(filepath, "r") as f:
            content = f.read()
            match = re.search(r"\s+Response\s+(\d+)", content)
            return int(match.group(1)) if match else None
    except FileNotFoundError:
        return None

# Step 4: Process each row
results = []
for _, row in data.iterrows():
    print(f"Processing ./data/fips2/{row['lines']}-result.txt")
    result_file = Path(f"./data/fips2/{row['lines']}-result.txt")
    query_count = extract_query_count(result_file)
    if query_count is not None and 0 <= row["clients"] < len(client_map):
        results.append({
            "kind": row["kind"],
            "clients": client_map[row["clients"]],
            "percent": (query_count / MAX_QUERIES) * 100
        })

df_plot = pd.DataFrame(results)

# print("DataFrame for plotting:")
# print(df_plot)
# Step 5: Aggregate by kind and number of clients
grouped = df_plot.groupby(["kind", "clients"]).agg(
    mean_percent=("percent", "mean"),
    std_percent=("percent", "std")
).reset_index()

print("Grouped DataFrame:")
print(grouped)

wide_values = (
    grouped.pivot_table(index="clients", columns="kind", values="mean_percent", aggfunc="first")
           .sort_index()
)
wide_values.columns = [f"mean_{c}" for c in wide_values.columns]

wide_std = (
    grouped.pivot_table(index="clients", columns="kind", values="std_percent", aggfunc="first")
           .sort_index()
)
wide_std.columns = [f"std_{c}" for c in wide_std.columns]


combined = pd.concat([wide_values, wide_std], axis=1).reset_index()

combined.to_csv("./tmp/qos_summary.csv", sep=";", index=False)

# Step 6: Plot
# Create figure
# fig = plt.figure(figsize=(16, 4))  # width, height in inches
# # plt.title("DNS Answer Rate vs Number of DoS Clients, 1 Million DoS Queries per second")
# # Define grid layout with width ratios
# gs = gridspec.GridSpec(1, 3, width_ratios=[2, 1, 1])  # 2:1:1 → 50%, 25%, 25%
#
# # Create subplots
# ax1 = fig.add_subplot(gs[0])
# ax2 = fig.add_subplot(gs[1])
# ax3 = fig.add_subplot(gs[2])
# for kind, group in grouped.groupby("kind"):
#     group_sorted = group.sort_values("clients")
#     ax1.errorbar(
#         group_sorted["clients"],
#         group_sorted["mean_percent"],
#         yerr=group_sorted["std_percent"],
#         fmt='-o',
#         capsize=5,
#         label=kind
#     )
#
# ax1.set_xlabel("Number of DoS Clients")
# ax1.set_ylabel("Answere Rate of valid Queries (%)")
# ax1.set_xscale("log", base=2)
# ax1.grid(True, which="both", linestyle="--", linewidth=0.5)
# ax1.legend(title="Kind")
#
data = build_and_save_per_action_time(
    {
        "file": "./data/fips3/85356c2f075943399809547f5c95cac8",
        "fips": "./data/fips3/7021cec5a5d34e7ba5d02bac6a7deb66",
    },
    window=50,
    min_periods=1,
    normalize_time=False,       # make each action’s time start at 0.0
    drop_all_zero_blocks=True,# keep idle periods in the time accumulation
    format="wide",             # or "wide"
)
#
# plt.tight_layout()
# plt.savefig('qos.pdf')
