# Choosing the partition thresholds θ_max / θ_min

**Current default:** θ_max = 64, θ_min = 16 (θ_min = θ_max / 4). **Open:** Exp. 2 (section "Large dispersed
results") shows that a small θ_max makes large dispersed result sets slower, and the update cost depends on whether
the partition version stays in γ (eq. 24). Both are to be decided with the advisor before the final run.

## Measurement

`python -m bench.experiments theta --n 200000 --reps 10 --warmup 2` (indexed IMT, dataset-v3, N = 200,000,
4 domains, 1,287,471 indexed keys). Query columns are medians over the 17 shared queries at N = 200,000
(`baselines/results/exp1_queries.json`, all shapes); insert columns use frozen partitions (no split/merge) as in
Exp. 3. Raw data: `baselines/results/amtp/amtp_theta_sweep.csv`. Test machine, not final numbers.

| θ_max / θ_min | partitions | setup (s) | query end-to-end (ms) | verify (ms) | proof (KB) | keys refreshed, 1 file | insert 1 file (ms) | insert, batch 100 (ms / file) |
|---|---|---|---|---|---|---|---|---|
| 64 / 16 | 4,118 | 135 | 4.50 | 2.83 | 72.6 | 342 | **24.7** | **17.5** |
| 128 / 32 | 2,070 | 111 | 4.63 | 2.89 | 72.6 | 821 | 48.2 | 32.2 |
| 256 / 64 | 1,046 | 104 | 4.58 | 2.87 | 72.1 | 1,265 | 77.3 | 60.1 |
| 512 / 128 | 534 | 97 | 4.47 | 2.81 | 69.9 | 2,376 | 152.6 | 108.7 |
| 1024 / 256 | 272 | 92 | 4.21 | 2.57 | 65.2 | 6,455 | 283.6 | 195.1 |

(At θ_max = 1024 the largest partition is 945 documents: the per-domain partitioning never reaches the cap.)

## Why θ_max = 64

1. **Update cost is proportional to θ_max.** A modified partition bumps its version, and since γ_{w,j} binds
   v_{i,j}, every key of that partition is refreshed (eq. 24). Keys refreshed and insert time roughly double with
   each doubling of θ_max (24.7 → 48.2 → 77.3 → 152.6 → 283.6 ms per file). After the indexed IMT this is the
   only update cost that is left, so θ_max sets AMTP's Exp. 3 result directly.
2. **Query cost of the shared Exp. 1 queries hardly depends on θ_max.** Over a 16× range the median end-to-end
   query time stays within 4.2–4.6 ms and proof size within 65–73 KB. Smaller partitions add a few more PAPC
   openings (s_Q 43 → 68), but the result-set and IMT parts of the proof dominate. This does not hold for large
   result sets spread over many partitions (next section).
3. **The price of a small θ_max is setup time and partition count**, both one-off or cheap: setup is 135 s instead
   of 104 s at θ_max = 256 (+30 %), and 4,118 partitions are 4,118 leaves of the partition tree (R^part).
4. Going below 64 was not measured; the remaining gain is bounded (insert is already ~25 ms per file, with fixed
   per-commit work that does not shrink with θ) while setup and partition count keep growing.

## Large dispersed results (Exp. 2)

The sweep's queries return few files. Exp. 2 (N = 200,000, one marker keyword matching exactly r_Q files) shows the
other side: when the r_Q files sit in different partitions, the proof opens one PAPC per partition touched, and a
small θ_max means more partitions to open. AMTP's worst case is the `partition_spread` layout: one file per AMTP
partition, round robin.

| r_Q | verify, θ = 64/16 (4,118 partitions) | verify, θ = 256/64 (1,046 partitions) | ratio | proof, 64/16 | proof, 256/64 |
|---|---|---|---|---|---|
| 10 | 0.39 ms | 0.41 ms | 0.95× | 9.0 KB | 10.1 KB |
| 100 | 3.35 ms | 3.67 ms | 0.91× | 67.6 KB | 81.0 KB |
| 1,000 | 56.25 ms | 59.31 ms | 0.95× | 656.3 KB | 792.2 KB |
| 5,000 | 710.17 ms | 234.14 ms | 3.03× | 2,705.5 KB | 1,030.9 KB |

Sources: θ = 64/16 = `baselines/results/amtp/amtp_exp2_selective_proof.csv` (layout `partition_spread` of the shared
`baselines/results/exp2_layouts.json`); θ = 256/64 = `baselines/results/amtp/amtp_exp2_theta256.csv` (the earlier run
at commit 79fe2d3, layout `dispersed`, which was then defined the same way: one file per partition, round robin, over
that run's 1,046 partitions). 1 KB = 1000 B.

Up to r_Q = 1,000 θ_max = 64 is not slower. At r_Q = 5,000 every one of the 4,118 partitions is touched and θ_max = 64
is slower and its proof larger, by the ratios in the table. θ_max = 128 was not measured in Exp. 2 and may be the
better compromise.

## Why θ_min = θ_max / 4

- Split/merge needs hysteresis: a split of a partition of θ_max + 1 documents gives two halves of about θ_max / 2,
  which must stay above θ_min, otherwise they are immediately merged again. That requires 2·θ_min < θ_max.
- θ_min = θ_max / 4 leaves a factor 2 of slack on both sides: after a split each half (≈ θ_max / 2) is 2× above
  θ_min, and after a merge of two partitions just under θ_min the result (≈ θ_max / 2) is 2× below θ_max, so a
  partition does not oscillate between split and merge under small insert/delete bursts.
- The sweep keeps this ratio for every θ_max, so the table compares like with like.
