# k6 Load Test Suite

Synthetic load tests for evaluating JWT/JWE verification overhead in Spring
Cloud Gateway. All tokens are **pre-generated** to remove signing cost from
the benchmark and isolate gateway crypto paths.

Each script defaults to:

```javascript
export const options = {
  vus: 200,
  duration: "60s",
};
```

Adjust VUs and duration to push the gateway to steady-state throughput.
