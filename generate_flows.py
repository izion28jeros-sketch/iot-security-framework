"""Generates a SYNTHETIC labelled flow dataset that imitates smart home traffic
(normal device traffic, DoS flooding and ARP-spoofing MITM) so the intrusion
detection pipeline can be demonstrated. Replace data/flows.csv with flows
extracted from real testbed captures (or the IDSH dataset of Javed et al., 2024)
before reporting results in the thesis."""
import numpy as np, pandas as pd, sys
rng = np.random.default_rng(2026)
def block(n, label):
    if label == "normal":
        d = dict(duration=rng.lognormal(1.0, 0.9, n), pkt_count=rng.poisson(18, n) + 2,
                 mean_pkt_size=rng.normal(310, 120, n), mean_iat=rng.lognormal(-1.2, 0.8, n),
                 std_iat=rng.lognormal(-1.6, 0.9, n), syn_ratio=rng.beta(1.5, 12, n),
                 rst_count=rng.poisson(0.2, n), arp_reply_rate=rng.exponential(0.15, n),
                 macs_per_ip=np.ones(n) + (rng.random(n) < 0.02), proto_udp=(rng.random(n) < 0.3).astype(int))
    elif label == "dos":
        d = dict(duration=rng.lognormal(0.3, 0.8, n), pkt_count=rng.poisson(160, n) + 20,
                 mean_pkt_size=rng.normal(90, 45, n), mean_iat=rng.lognormal(-4.2, 1.0, n),
                 std_iat=rng.lognormal(-4.5, 1.1, n), syn_ratio=rng.beta(6, 3, n),
                 rst_count=rng.poisson(4, n), arp_reply_rate=rng.exponential(0.2, n),
                 macs_per_ip=np.ones(n), proto_udp=(rng.random(n) < 0.4).astype(int))
    else:  # mitm: traffic relayed through attacker after ARP poisoning; mostly normal-looking
        d = dict(duration=rng.lognormal(1.1, 0.9, n), pkt_count=rng.poisson(22, n) + 2,
                 mean_pkt_size=rng.normal(330, 130, n), mean_iat=rng.lognormal(-1.0, 0.8, n),
                 std_iat=rng.lognormal(-1.3, 0.9, n), syn_ratio=rng.beta(1.5, 11, n),
                 rst_count=rng.poisson(0.4, n), arp_reply_rate=rng.exponential(0.9, n),
                 macs_per_ip=np.ones(n) + (rng.random(n) < 0.55), proto_udp=(rng.random(n) < 0.3).astype(int))
    df = pd.DataFrame(d); df["mean_pkt_size"] = df["mean_pkt_size"].clip(40, 1500); df["label"] = label
    return df
n = int(sys.argv[2]) if len(sys.argv) > 2 else 20000
df = pd.concat([block(int(n*.85), "normal"), block(int(n*.10), "dos"), block(int(n*.05), "mitm")]).sample(frac=1, random_state=7)
df.to_csv(sys.argv[1] if len(sys.argv) > 1 else "flows.csv", index=False)
print(df["label"].value_counts().to_dict())
