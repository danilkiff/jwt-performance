The notebook processes multiple k6 performance runs. Each run is a directory `run-*` containing:

```text
$ tree .
.
├── es256.json
├── hs256.json
├── jwe.json
├── metadata.json
├── plain.json
└── rs256.json
```

## Metadata structure - `metadata.json`

```text
$ cat metadata.json 
{
  "title":  "Xeon no resource limits",
  "cpu":    "2 x Intel(R) Xeon(R) CPU E5-2660 v2 @ 2.20GHz",
  "ram":    "4 x 32 Gb DDR3 @ 800MHz (1.2ns)",
  "ssd":    "2Tb",
  "limits": "none"
}
```

## Workflow

1. Notebook scans all `run-*` directories and builds a consolidated dataframe.
2. Algorithms are inferred from filenames.
3. Derived metric `efficiency_score` is added.
4. Visualization is per-run: `plot_run(df, "run-1")`

Produces a 2x2 panel:

* request rate;
* p95 latency;
* efficiency score;
* rate vs p95 scatter.

Ordering is descending by request rate. Colors are stable across panels. Bar plots include numeric labels.

## Notes

* extra files in run directories are ignored;
* missing metrics become `NaN` and affect ordering.
