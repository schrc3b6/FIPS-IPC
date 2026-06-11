import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from cycler import cycler
import re
from pathlib import Path

def get_plot_kwargs(kwargs, it):
    plot_kwargs = {}
    if it is None:
        keys = ['color', 'lw', 'linestyle']
        plot_kwargs = {k: kwargs[k] for k in keys if k in kwargs}
    else:
        keys = ['colors', 'lws', 'linestyles']
        plot_kwargs = {k[:-1]: kwargs[k][it] for k in keys if k in kwargs}
    return plot_kwargs
        

def add_answere_rate_plot(ax, filename, label, **kwargs):
    """
    Adds a plot of the answer rate from a CSV file to the given axis.
    
    Parameters:
    - ax: The axis to plot on.
    - filename: The path to the CSV file containing the data.
    - pps_selected: A list of pps values to filter the data.
    - kwargs: Additional keyword arguments for customization.
    """
    # Load the CSV file
    df = pd.read_csv(filename, sep=",", names=["time", "value", "cumulative"],header=1)
    
    # print(df)
    # Convert 'time' to seconds for plotting
    df['seconds'] = pd.to_timedelta("00:"+df['time']).dt.total_seconds()

    df['value_ma10'] = df['value'].rolling(window=10).mean()*10
    plot_kwargs = get_plot_kwargs(kwargs, None)
    line_handle = ax.plot(df['seconds'], df['value_ma10'], label=label, **plot_kwargs)
    if "x_limit" in kwargs:
        if len(kwargs["x_limit"]) == 2:
            ax.set_xlim(kwargs["x_limit"][0], kwargs["x_limit"][1])
            if kwargs.get("match_ax", None) is not None:
                kwargs["match_ax"].set_xlim(kwargs["x_limit"][0], kwargs["x_limit"][1])
        else:
            ax.set_xlim(0, kwargs["x_limit"][0])
            if kwargs.get("match_ax", None) is not None:
                kwargs["match_ax"].set_xlim(0, kwargs["x_limit"][0])
    if "no_legend" not in kwargs or not kwargs["no_legend"]:
        ax.legend(loc=1)
    ax.grid(True)
    return line_handle

# file_dict = { label: filename }
def add_ban_clients_plot(ax, file_dict,**kwargs):
    dfs = {}
    time_axis = {}
    line_handles = []
    it = 0
    
    for key, value in file_dict.items():
        # check if the file exists
        try:
            with open(value, "r") as f:
                lines = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"File {value} not found.")
            exit(1)

        # remove the bottom lines until we hit the first line with "XDP_ABORTED"
        while lines and not lines[-1].startswith("XDP_ABORTED"):
            lines.pop(-1)
        lines.pop(-1)

        # remove the first lines until we hit the first line with "XDP_ABORTED"
        while lines and not lines[0].startswith("XDP_ABORTED"):
            lines.pop(0)

        data = []

        # count the number of lines till we hit the first empty line
        block_size = 1
        while not lines[block_size].startswith("XDP_ABORTED"): 
            print(f"Block size: {block_size}, line: {lines[block_size]}")
            block_size += 1

        for i in range(0, len(lines), block_size):
            block = lines[i:i+block_size]
            entries = []
            for line in block:
                parts = line.split()
                # print(parts)  # Debug-Ausgabe
                action = parts[0]
                total_packets = int(parts[1].replace(",", ""))
                packets = int(parts[2].replace(",", ""))
                time_diff = float(parts[3])
                entries.append((action, total_packets, packets, time_diff))
            
            # Block nur hinzufügen, wenn total_packets nicht bei allen 0 ist
            if not all(entry[1] == 0 for entry in entries):
                data.extend(entries)

        # DataFrame erstellen
        df = pd.DataFrame(data, columns=["Action", "total packets", "packets", "time diff"])


        # Create a cumulative time index
        df['cumulative_time'] = df['time diff'].cumsum()
        print(f"Cumulative time for {key},{value}: {df['cumulative_time']}")
        print(f"time diff for {key},{value}: {df['time diff']}")


        # Get unique time values per group of 3 lines (1 per action group)
        # So we take every third row's cumulative_time as the time step
        time_axis[key] = df['cumulative_time'][df['Action'] == 'XDP_ABORTED'].reset_index(drop=True)
        # print(f"Time axis for {key}: {time_axis[key]}")

        # Build one DataFrame per action
        actions = df['Action'].unique()
        dfs[key] = {}

        # print(f"Processing {key} with actions: {actions}")
        print(df)
        for action in actions:
            dfs[key][action] = df[df['Action'] == action]['packets'].reset_index(drop=True)
        
    try:
        for key, data in dfs.items():
            for action in ["XDP_PASS", "XDP_DROP", "MATCH"]:
                if action not in data:
                    continue
                y =dfs[key][action].rolling(window=10, min_periods=1).mean()
                agg_df = pd.DataFrame({ 
                    "time": time_axis[key],
                    "value": dfs[key][action].rolling(window=10, min_periods=1).mean(),
                })
                agg_df.to_csv(f"{key}_{action}_{value.replace("/", "_")}.csv", sep=";", index=False)
                if action in ["XDP_PASS", "XDP_DROP"]:
                    plot_kwargs = get_plot_kwargs(kwargs, it)
                    line_handles+=ax.plot(time_axis[key], y, label=key+": "+action, **plot_kwargs)
                    it+=1
                if action in ["MATCH"]:
                    plot_kwargs = get_plot_kwargs(kwargs, it)
                    line_handles+=kwargs.get("match_ax",None).plot(time_axis[key], y, label=key+": Ingress", **plot_kwargs)
                    it+=1
                    kwargs.get("match_ax",None).set_ylabel("Response Packets")
                    kwargs.get("match_ax",None).set_xlabel("Cumulative Time (s)")
    except Exception as e:
        print(f"KeyError: {e}. This might be due to missing data for action '{e}' in one of the files: {file_dict}.")

    ax.set_xlabel("Cumulative Time (s)")
    ax.set_ylabel("Packets")
    if "x_limit" in kwargs:
        if len(kwargs["x_limit"]) == 2:
            ax.set_xlim(kwargs["x_limit"][0], kwargs["x_limit"][1])
            if kwargs.get("match_ax", None) is not None:
                kwargs["match_ax"].set_xlim(kwargs["x_limit"][0], kwargs["x_limit"][1])
        else:
            ax.set_xlim(0, kwargs["x_limit"][0])
            if kwargs.get("match_ax", None) is not None:
                kwargs["match_ax"].set_xlim(0, kwargs["x_limit"][0])
    if "no_legend" not in kwargs or not kwargs["no_legend"]:
        ax.legend(loc=1)
    ax.grid(True)
    return line_handles

# Step 1: Load main CSV data

# Step 2: Client map for index -> number of clients
client_map = [0, 2**18, 2**17, 2**16, 2**15, 2**14, 2**13, 2**12, 2**11, 2**10, 2**9, 2**8, 2**7, 2**6, 2**5, 2**4, 2**3, 2**2, 2**1, 2**0]
MAX_QUERIES = 360 * (70000*0.6)  # 25,200,000

# Step 3: Extract query count from file
def extract_query_count(filepath):
    try:
        with open(filepath, "r") as f:
            content = f.read()
            match = re.search(r"\s+Response\s+(\d+)", content)
            if match:
                return int(match.group(1))
            else:
                match = re.search(r"udp\s+frames:(\d+)", content)
                return int(match.group(1)) if match else None
    except FileNotFoundError:
        print(f"File {filepath} not found.")
        return None

# Step 4: Process each row
def generate_plot(filename, resultname, pps_selected, ban_sub_plots,max_queries=MAX_QUERIES,use_tshark=True,**kwargs):
    data = pd.read_csv(filename, sep=";")
    results = []
    for _, row in data.iterrows():
        query_count = None
        if use_tshark:
            result_file = Path(f"fips2/{row['lines']}-result.txt")
            print(f"Processing {result_file}")
            query_count = extract_query_count(result_file)
        else:
            query_count = row["packets"]
        print(f"Query count: {query_count}")
        if query_count is not None and 0 <= row["clients"] < len(client_map):
            results.append({
                "kind": row["kind"],
                "pps": row["pps"],
                "clients": client_map[row["clients"]],
                "percent": (query_count / max_queries) * 100
            })

    df_plot = pd.DataFrame(results)

    # print("DataFrame for plotting:")
    # print(df_plot)
# Step 5: Aggregate by kind and number of clients
    grouped = df_plot.groupby(["kind", "clients","pps"]).agg(
        mean_percent=("percent", "mean"),
        std_percent=("percent", "std")
    ).reset_index()

# Step 6: Plot
# Create figure
    fig = plt.figure(figsize=(16, 4))  # width, height in inches
# plt.title("DNS Answer Rate vs Number of DoS Clients, 1 Million DoS Queries per second")
# Define grid layout with width ratios
    gs = gridspec.GridSpec(1, 3, width_ratios=[2, 1, 1])  # 2:1:1 → 50%, 25%, 25%

# Create subplots
    ax1 = fig.add_subplot(gs[0])
    ax2 = fig.add_subplot(gs[1])
    ax3 = fig.add_subplot(gs[2])
    for pps, pps_group in grouped.groupby("pps"):
        if pps in pps_selected:
            for kind, group in pps_group.groupby("kind"):
                group_sorted = group.sort_values("clients")
                ax1.errorbar(
                    group_sorted["clients"],
                    group_sorted["mean_percent"],
                    yerr=group_sorted["std_percent"],
                    fmt='-o',
                    capsize=5,
                    label=f"{kind} ({pps})",
            )

    ax1.set_xlabel("Number of DoS Clients")
    ax1.set_ylabel("Answere Rate of valid Queries (%)")
    ax1.set_xscale("log", base=2)
    ax1.grid(True, which="both", linestyle="--", linewidth=0.5)
    ax1.legend(title="Kind")

    if len(ban_sub_plots) > 0:
        add_ban_clients_plot(ax2, {"fips": "fips3/"+ban_sub_plots[0]}, **kwargs.get(ban_sub_plots[0], {}))
    if len(ban_sub_plots) > 1:
        add_ban_clients_plot(ax3, {"file": "fips3/"+ban_sub_plots[1]}, **kwargs.get(ban_sub_plots[0], {}))

    plt.tight_layout()
    plt.savefig(resultname)
 #--bantime=60 --findtime=10 --limit=100
# generate_plot("./results_202505131627.csv", "dns-70k-1m.pdf", [1000000], ["b057302cb5d2447086aa5ee83b68a5ca","5eba566e721c41ed89293e0b1becbab8"], 360*70000)
# generate_plot("./results_202505131627.csv", "dns-70k-10m.pdf", [10000000], ["02557ca0881945f4bce2c97dac535f04","1f2e9f2796bd4ca0a27ab51f7823dcaf"], 360*70000)
# generate_plot("./results_202505141136.csv", "dns-42k-1m.pdf", [1000000], ["20050b29dfca40d3ad71805c6d3209ef","2168dd80e810462b97d79daf9da16c16"], 360*42000)
# generate_plot("./results_202505141136.csv", "dns-42k-10m.pdf", [10000000], ["92ff6f19546d4f0c8198165e8abaeaca","d4a21ffbae624e2ca4118ff862be9e3c"], 360*42000)
 #--bantime=60 --findtime=10 --limit=20
# generate_plot("./results_202505171609.csv", "dns-42k-10m-l20.pdf", [10000000], [], 360*42000)
# generate_plot("./results_202505171609.csv", "dns-42k-1m-l20.pdf", [1000000], [], 360*42000)
# --bantime=60 --findtime=60 --limit=5
# generate_plot("./results_202505201402.csv", "dns-42k-1m-l5.pdf", [1000000], [], 360*42000)
# generate_plot("./results_202505201402.csv", "dns-42k-10m-l5.pdf", [10000000], [], 360*42000)
# --bantime=60 --findtime=60 --limit=3

# generate_plot("./results_udp.csv", "udp-42k-1m.pdf", [1000000], ['029faf5d323b4d13a0dd76b84b3a4678'], 360*70000)
# generate_plot("./results_udp.csv", "udp-42k-10m.pdf", [10000000], [], 360*70000)
# generate_plot("./results_udp.csv", "udp-42k-15m.pdf", [15000000], [], 360*70000)
# generate_plot("./results_udp.csv", "udp-42k-20m.pdf", [20000000], [], 360*70000)
# generate_plot("./results_udp.csv", "udp-42k-25m.pdf", [25000000], [], 360*70000)
# generate_plot("./results_udp.csv", "udp-42k-30m.pdf", [30000000], [], 360*70000)
# generate_plot("./results_202505272329.csv", "udp-180k-30m.pdf", [30000000], [], 360*180000, use_tshark=False)
# generate_plot("./results_202505272329.csv", "udp-180k-25m.pdf", [25000000], [], 360*180000, use_tshark=False)
# generate_plot("./results_202505272329.csv", "udp-180k-20m.pdf", [20000000], [], 360*180000, use_tshark=False)
# generate_plot("./results_202505272329.csv", "udp-180k-15m.pdf", [15000000], [], 360*180000, use_tshark=False)
# generate_plot("./results_202505272329.csv", "udp-180k-10m.pdf", [10000000], [], 360*180000, use_tshark=False)
# generate_plot("./results_202505272329.csv", "udp-180k-1m.pdf", [1000000], [], 360*180000, use_tshark=False)
# generate_plot("./results_202506021748.csv", "dns-2m.pdf", [2000000], [], 360*42000, use_tshark=False)
# generate_plot("./results_202506021748.csv", "dns-3m.pdf", [3000000], [], 360*42000, use_tshark=False)
# generate_plot("./results_202506021748.csv", "dns-5m.pdf", [5000000], [], 360*42000, use_tshark=False)

# fig = plt.figure(figsize=(16, 4))  # width, height in inches
# ax = fig.add_subplot(141)
# add_ban_clients_plot(ax, {"file": "fips3/19f94770889841818a5e41d46af9a68a"}, x_limit=[0, 120], no_legend=True)
# add_ban_clients_plot(ax, {"fips": "fips3/f933237f423b4beeafce260e8f783644"}, x_limit=[0, 120], no_legend=True)
# add_ban_clients_plot(ax, {"uring": "fips3/f789e1c0ccee48e1a6af33b54986eb10"}, x_limit=[0, 120], no_legend=True)
# ax = fig.add_subplot(142)
# add_ban_clients_plot(ax, {"file": "fips3/798d61262ee440a9a6f6182c74ba5185"}, x_limit=[0, 120], no_legend=True)
# add_ban_clients_plot(ax, {"fips": "fips3/193d8be72486400e826455ffe2ad7792"}, x_limit=[0, 120], no_legend=True)
# add_ban_clients_plot(ax, {"uring": "fips3/f199d788561e4f9eb2ca0275e8d96cab"}, x_limit=[0, 120], no_legend=True)
# ax = fig.add_subplot(143)
# add_ban_clients_plot(ax, {"file": "fips3/b4a744a9849247529f44cf764d86d27d"}, x_limit=[0, 120], no_legend=True)
# add_ban_clients_plot(ax, {"fips": "fips3/0185f34aa089403dac27318dfb99eebd"}, x_limit=[0, 120], no_legend=True)
# add_ban_clients_plot(ax, {"uring": "fips3/d040c53b92e04c0289c0b5ace9f829c0"}, x_limit=[0, 120], no_legend=True)
# ax = fig.add_subplot(144)
# lines=[]
# lines+=add_ban_clients_plot(ax, {"file": "fips3/62802a0532014143802f8ec79e8e946c"}, x_limit=[0, 120], no_legend=True)
# lines+=add_ban_clients_plot(ax, {"fips": "fips3/fa65f3a5ca424252b69d2f55f65f8338"}, x_limit=[0, 120], no_legend=True)
# lines+=add_ban_clients_plot(ax, {"uring": "fips3/82ad5b7f1a224cabb7f8d5dd0f897c4d"}, x_limit=[0, 120], no_legend=True)
# print(lines)
# # plt.figlegend(handles=lines)
#
# # , loc='upper center', ncol=3, title="Action", bbox_to_anchor=(0.5, -1.05)
# # ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.05),
# #           fancybox=True, shadow=True, ncol=5)
# fig.legend(handles=lines, loc='outside upper center', ncol=6, title="Action", bbox_to_anchor=(0.5, 0.165))
# fig.tight_layout(rect=[0, 0.15, 1, 1])
# plt.savefig("slope-file.pdf")

fig = plt.figure(figsize=(16, 4))  # width, height in inches
ax = fig.add_subplot(121)
ax2 = fig.add_subplot(122)
ax.set_prop_cycle(cycler('color', plt.cm.tab10.colors[:4]))  # First 5 tab10 colors
ax2.set_prop_cycle(cycler('color', plt.cm.tab10.colors[4:]))  # Next 5 tab10 colors
lines=[]
lines+=add_ban_clients_plot(ax, {"file": "fips3/635d3e9287784eb5a9ecab891a1f858a"}, x_limit=[0, 80], no_legend=True, match_ax=ax2, colors=[plt.cm.tab20.colors[0], plt.cm.tab20.colors[0], plt.cm.tab20c.colors[0]], linestyles=["--", "-", "-."],lws=[2, 2, 2])
lines+=add_ban_clients_plot(ax, {"fips": "fips3/cbf53658a95f40d1881ce2c7c49518ee"}, x_limit=[0, 80], no_legend=True, match_ax=ax2, colors=[plt.cm.tab20.colors[6], plt.cm.tab20.colors[6], plt.cm.tab20c.colors[4]], linestyles=["--", "-", "-."], lws=[2, 2, 2])
lines+=add_answere_rate_plot(ax2, "hist/635d3e9287784eb5a9ecab891a1f858a-result.txt", "file: responses", x_limit=[0, 80], no_legend=True, color=plt.cm.tab20c.colors[1], linestyle="-.", lw=2)
lines+=add_answere_rate_plot(ax2, "hist/cbf53658a95f40d1881ce2c7c49518ee-result.txt", "fips: responses", x_limit=[0, 80], no_legend=True, color=plt.cm.tab20c.colors[5], linestyle="-.", lw=2)
# add_ban_clients_plot(ax, {"uring": "fips3/f789e1c0ccee48e1a6af33b54986eb10"}, x_limit=[0, 120], no_legend=True)
# ax = fig.add_subplot(242)
# ax2 = fig.add_subplot(246)
# add_ban_clients_plot(ax, {"file": "fips3/f6043a6108924600b2477fb00811826b"}, x_limit=[0, 120], no_legend=True)
# add_answere_rate_plot(ax2, "hist/f6043a6108924600b2477fb00811826b-result.txt", "File", x_limit=[0, 120], no_legend=True)
# add_ban_clients_plot(ax, {"fips": "fips3/94bf2a98918b41c19834c740bd61e8d1"}, x_limit=[0, 120], no_legend=True)
# add_answere_rate_plot(ax2, "hist/94bf2a98918b41c19834c740bd61e8d1-result.txt", "FIPS", x_limit=[0, 120], no_legend=True)
# # add_ban_clients_plot(ax, {"uring": "fips3/f199d788561e4f9eb2ca0275e8d96cab"}, x_limit=[0, 120], no_legend=True)
# ax = fig.add_subplot(243)
# ax2 = fig.add_subplot(247)
# add_ban_clients_plot(ax, {"file": "fips3/fd60b25b89eb4c93be6d6a60fea3c393"}, x_limit=[0, 120], no_legend=True, match_ax=ax2)
# add_ban_clients_plot(ax, {"fips": "fips3/ea2cc30444a442b09a04873d71cfc132"}, x_limit=[0, 120], no_legend=True, match_ax=ax2)
# # add_ban_clients_plot(ax, {"uring": "fips3/d040c53b92e04c0289c0b5ace9f829c0"}, x_limit=[0, 120], no_legend=True)
# ax = fig.add_subplot(244)
# ax2 = fig.add_subplot(248)
# lines=[]
# lines+=add_ban_clients_plot(ax, {"file": "fips3/126cf8ab443e4b98a311f0d268ac7d62"}, x_limit=[0, 120], no_legend=True, match_ax=ax2)
# lines+=add_ban_clients_plot(ax, {"fips": "fips3/fb8c8d9ae5e742a09c14dcce371a50b2"}, x_limit=[0, 120], no_legend=True, match_ax=ax2)
# lines+=add_ban_clients_plot(ax, {"uring": "fips3/82ad5b7f1a224cabb7f8d5dd0f897c4d"}, x_limit=[0, 120], no_legend=True)
# print(lines)
# plt.figlegend(handles=lines)

# , loc='upper center', ncol=3, title="Action", bbox_to_anchor=(0.5, -1.05)
# ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.05),
#           fancybox=True, shadow=True, ncol=5)
lines = lines[1::-1] + lines[4:2:-1] + lines[2:3] + lines[5:]
fig.legend(handles=lines, loc='outside upper center', ncol=8, bbox_to_anchor=(0.5, 0.165))
fig.tight_layout(rect=[0, 0.15, 1, 1])
plt.savefig("slope-file_qos.pdf")
