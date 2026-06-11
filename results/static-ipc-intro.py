import pandas as pd

# Read data from the CSV file
df = pd.read_csv('data/static-ipc.csv', delimiter=';')

# Correct the data: Multiply 'lines' by 0.5 for rows where 'kind' is 'fips_bin'
df.loc[df['kind'] == 'fips_bin', 'lines'] *= 0.5

# Calculate percentage of packets and lines
df['packets_percent'] = df['packets'] / (df['duration'] * df['pps'])
df['lines_percent'] = df['lines'] / (df['duration'] * df['pps'])

# Calculate the median and standard deviation for each combination of kind and pps
agg_df = df.groupby(['kind', 'pps']).agg(
    packets_percent_median=('packets_percent', 'median'),
    lines_percent_median=('lines_percent', 'median'),
    packets_percent_std=('packets_percent', 'std'),
    lines_percent_std=('lines_percent', 'std')
).reset_index()

# Map 'pps' values to positions based on the labels
pps_map = { 10_000: '10k', 20_000: '20k', 30_000: '30k', 40_000: '40k', 50_000: '50k',
            60_000: '60k', 70_000: '70k', 80_000: '80k', 90_000: '90k', 
           100_000: '100k', 200_000: '200k', 300_000: '300k', 400_000: '400k', 500_000: '500k',
           600_000: '600k', 700_000: '700k', 800_000: '800k', 900_000: '900k', 1_000_000: '1m',
           2_000_000: '2m', 3_000_000: '3m', 4_000_000: '4m', 5_000_000: '5m', 6_000_000: '6m',
           7_000_000: '7m', 8_000_000: '8m', 9_000_000: '9m', 10_000_000: '10m'}
agg_df['pps']
agg_df['pps_category'] = agg_df['pps'].map(pps_map)
agg_df['pps']

agg_df.to_csv("./tmp/agg-static-ipc.csv", sep=";", index=False)
