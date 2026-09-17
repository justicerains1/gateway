use dashmap::DashMap;
use std::sync::Arc;

use crate::rebalance::RebalanceCounter;

const TOTAL_KEY: &str = "_total";

struct TrackedDeployment {
    counter: Arc<RebalanceCounter>,
    /// Model name (alias-resolved, same value audit logs as `model_name`)
    /// recorded with the most recent request. Kept alongside the counter so
    /// the stats chart can label a series even after the deployment is
    /// deleted/renamed in the live store — reverse lookup would return "-".
    model: String,
}

/// Tracks per-deployment request counts over the last 60 minutes.
///
/// Internally a DashMap of deployment_id → TrackedDeployment
/// (60-bucket ring buffer + last-seen model name).
/// A special `_total` key aggregates all deployments.
pub struct RequestRateTracker {
    counters: DashMap<String, TrackedDeployment>,
}

impl RequestRateTracker {
    pub fn new() -> Self {
        let counters = DashMap::new();
        counters.insert(
            TOTAL_KEY.to_string(),
            TrackedDeployment {
                counter: Arc::new(RebalanceCounter::new()),
                model: TOTAL_KEY.to_string(),
            },
        );
        Self { counters }
    }

    /// Record one request for the given deployment_id (also increments _total).
    /// `model` is the alias-resolved model name used for chart attribution.
    pub fn record(&self, deployment_id: &str, model: &str) {
        let mut entry = self
            .counters
            .entry(deployment_id.to_string())
            .or_insert_with(|| TrackedDeployment {
                counter: Arc::new(RebalanceCounter::new()),
                model: model.to_string(),
            });
        entry.counter.record();
        entry.model = model.to_string();

        drop(entry);

        if let Some(total) = self.counters.get(TOTAL_KEY) {
            total.counter.record();
        }
    }

    /// Drop a deployment's series (e.g. the deployment was deleted). Without
    /// this, the entry lingers forever with all-zero buckets and renders a
    /// ghost series on the stats chart.
    pub fn remove(&self, deployment_id: &str) {
        self.counters.remove(deployment_id);
    }

    /// Snapshot all deployments: returns Vec of
    /// (deployment_id, model_name, snapshot_data).
    /// First entry is always `_total`, rest sorted by deployment_id.
    pub fn snapshot_all(&self) -> Vec<(String, String, Vec<(String, u64)>)> {
        let mut result = Vec::new();

        if let Some(total) = self.counters.get(TOTAL_KEY) {
            result.push((
                TOTAL_KEY.to_string(),
                TOTAL_KEY.to_string(),
                total.counter.snapshot(),
            ));
        }

        let mut deps: Vec<String> = self
            .counters
            .iter()
            .filter(|e| e.key() != TOTAL_KEY)
            .map(|e| e.key().to_string())
            .collect();
        deps.sort();

        for dep in deps {
            if let Some((counter, model)) = self
                .counters
                .get(&dep)
                .map(|e| (e.counter.clone(), e.model.clone()))
            {
                result.push((dep, model, counter.snapshot()));
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_all_labels_by_recorded_model() {
        let t = RequestRateTracker::new();
        t.record("dep-1", "model-a");
        t.record("dep-2", "model-b");

        let all = t.snapshot_all();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].0, "_total");
        let (id1, m1, _) = &all[1];
        let (id2, m2, _) = &all[2];
        assert_eq!((id1.as_str(), m1.as_str()), ("dep-1", "model-a"));
        assert_eq!((id2.as_str(), m2.as_str()), ("dep-2", "model-b"));
    }

    #[test]
    fn rename_updates_label_on_next_record() {
        let t = RequestRateTracker::new();
        t.record("dep-1", "old-name");
        t.record("dep-1", "new-name");

        let all = t.snapshot_all();
        assert_eq!(all[1].1, "new-name");
    }

    #[test]
    fn remove_drops_entry() {
        let t = RequestRateTracker::new();
        t.record("dep-1", "model-a");
        t.remove("dep-1");

        let all = t.snapshot_all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].0, "_total");
    }
}
