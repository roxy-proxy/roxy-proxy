//! Which exchanges a layer runs on: its `when`, judged on the request as
//! it reaches the layer, and its `sample`.

use roxy_http::layer::{from_layer_request, to_layer_request};
use roxy_wasm::{LayerError, LayerRequest};
use ulid::Ulid;

use super::ws::{join_upgrade_stream, split_upgrade_stream};
use super::{AddonMode, AddonSpec, StackError, StackFlow, emit_stack_error};
use crate::view::ProxyView;

/// Whether layer `index` runs on `req`: its `when` matches the request
/// as it reaches the layer, and `sample` picks the exchange. The request
/// comes back for the layer, or for the layer below when it is skipped.
///
/// A `when` sees the request re-validated as the core would, so a layer
/// above that passed on something invalid fails here, attributed to it.
pub(super) fn selects(
    st: &StackFlow,
    index: usize,
    addon: &AddonSpec,
    req: LayerRequest,
) -> Result<(bool, LayerRequest), StackError> {
    let Some(when) = &addon.when else {
        return Ok((sampled(st.flow, index, addon.sample), req));
    };
    let snap = &st.snap;
    let (req, stream) = split_upgrade_stream(st, req);
    let creq = match from_layer_request(req, st.client_meta.clone(), &snap.limits, &snap.flags) {
        Ok(r) => r,
        Err(e) => {
            // A request no layer passed on is the client's, already
            // canonical.
            let above = &snap.addons[st.passed_on_by(index).unwrap_or(0)].name;
            st.fail(above, LayerError::InvalidRequest(e.to_string()));
            return Err(LayerError::InvalidRequest(e.to_string()).into());
        }
    };
    let mut facts = st.facts();
    facts.request = Some(crate::pipeline::request_facts(&creq));
    let view = ProxyView::new(
        &facts,
        &*st.shared.metrics,
        &*st.shared.state,
        &snap.address_lists,
    );
    let matched = when.matches(&view, &st.tags());
    let metric_err = view.take_metric_error();
    drop(view);
    match matched {
        Ok(m) => Ok((
            m && sampled(st.flow, index, addon.sample),
            join_upgrade_stream(to_layer_request(creq), stream),
        )),
        Err(reason) => {
            let err = StackError::Condition {
                code: crate::pipeline::fail_closed_code(&reason, metric_err.as_ref()),
                reason: reason.to_string(),
            };
            if addon.mode == AddonMode::Enforce {
                return Err(err);
            }
            // An observer cannot affect traffic, so neither can its `when`.
            emit_stack_error(st, &addon.name, &err, AddonMode::Observe);
            Ok((false, join_upgrade_stream(to_layer_request(creq), stream)))
        }
    }
}

/// Whether `sample` picks this exchange for layer `index`. The draw comes
/// from the flow id's random bits, so it is reproducible from the log, and
/// is mixed with the index so two sampled layers draw independently.
fn sampled(flow: Ulid, index: usize, sample: Option<f64>) -> bool {
    let Some(p) = sample else {
        return true;
    };
    // splitmix64's finaliser: every input bit reaches the top 32.
    let low = u64::try_from(flow.random() & u128::from(u64::MAX)).unwrap_or(0);
    let mut z = low ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^= z >> 31;
    let draw = u32::try_from(z >> 32).unwrap_or(u32::MAX);
    f64::from(draw) < p * 4_294_967_296.0
}

#[cfg(test)]
mod tests {
    use super::sampled;
    use ulid::Ulid;

    #[test]
    fn sampling_is_deterministic_and_proportional() {
        let flows: Vec<Ulid> = (0..10_000).map(|_| Ulid::generate()).collect();
        assert!(flows.iter().all(|&f| sampled(f, 0, None)));
        assert!(flows.iter().all(|&f| sampled(f, 3, Some(1.0))));
        for p in [0.01, 0.25, 0.9] {
            let hits = flows.iter().filter(|&&f| sampled(f, 0, Some(p))).count();
            #[allow(clippy::cast_precision_loss)]
            let share = hits as f64 / flows.len() as f64;
            assert!((share - p).abs() < 0.03, "p {p}: {share}");
        }
        let f = flows[0];
        assert_eq!(sampled(f, 1, Some(0.5)), sampled(f, 1, Some(0.5)));
        // Two layers draw independently.
        let both = flows
            .iter()
            .filter(|&&f| sampled(f, 0, Some(0.5)) && sampled(f, 1, Some(0.5)))
            .count();
        assert!((2000..3000).contains(&both), "{both}");
    }
}
