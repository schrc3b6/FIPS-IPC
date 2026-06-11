
import pandas as pd
import numpy as np

df = pd.read_csv("./data/baseline_xdpstats_f2b_100KR_255C_240730_08.csv")

df['aborted'] = df.filter(regex='^XDP_ABORTED').sum(axis=1)
df['drop'] = df.filter(regex='^XDP_DROP').sum(axis=1)
df['pass'] = df.filter(regex='^XDP_PASS').sum(axis=1)
df['time'] = df['Period'].cumsum()
result_df = df[['time', 'aborted', 'drop', 'pass']]
result_df.to_csv("./tmp/baseline.csv", index=False)
