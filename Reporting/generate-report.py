import pandas as pd
from matplotlib import pylab as plt

file_df = pd.read_csv(
    "data_ex.csv",
    names=[
        "Time",
        "Dur",
        "Protocol",
        "SAddr",
        "Sport",
        "DAddr",
        "Dport",
        "State",
        "sTos",
        "dTos",
        "TotPkts",
        "TotBytes",
    ],
)

file_df = file_df.set_index("Time")
file_df.index = pd.to_datetime(file_df.index)

print("Total bytes consumed by protocol.")
bytes_by_protocol = file_df.groupby(["Protocol"]).TotBytes.sum()
bytes_by_protocol = bytes_by_protocol.sort_values(ascending=False)
print(bytes_by_protocol)

print("Top ten talkers by src-dest ip pair (bytes)")
file_df["SAddr_DAddr"] = file_df["SAddr"] + "_" + file_df["DAddr"]
bytes_by_IPpair = file_df.groupby(["SAddr_DAddr"]).TotBytes.sum()
bytes_by_IPpair = bytes_by_IPpair.sort_values(ascending=False).head(10)
print(bytes_by_IPpair)

filtered_df = file_df[(file_df["SAddr"] == "195.250.146.99")]
filtered_df = filtered_df.TotBytes.sum()
print(f"Total bytes consumed by the 195.250.146.99 IP address: {filtered_df}")

resampled_df = file_df.TotBytes.resample("1T").sum()
plt.plot(resampled_df)
plt.title("Bytes per second as time series data")
plt.show()
