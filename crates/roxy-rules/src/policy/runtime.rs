//! The head decision and watching evaluation over a compiled [`Policy`],
//! plus the runtime side of [`MetricDef`] and [`Condition`].

use super::{
    CAction, Condition, MetricDef, Part, Policy, WatchAction, WatchState, is_header_value,
};
use crate::diag::RuleId;
use crate::eval::{
    Decision, Deny, Effect, EvalContext, FailClosedReason, Outcome, PendingState, Scope,
    WatchEffect, WatchOutcome,
};
use crate::types::Reads;
use crate::view::FlowView;

impl MetricDef {
    /// Whether a flow passes this metric's `where` filter (absent = always).
    /// `Err` if the filter needs an unavailable input; the proxy must then
    /// fail the flow closed rather than skip counting it.
    pub fn matches(&self, view: &dyn FlowView) -> Result<bool, FailClosedReason> {
        self.filter
            .as_ref()
            .map_or(Ok(true), |p| Scope::new(view, &[], &()).check(p))
    }
}

impl Condition {
    /// Whether a flow matches. `tags` are visible as `tag["x"]`. `Err` if
    /// evaluation reaches an unavailable input; the caller must then fail
    /// the flow closed, never treat it as a mismatch.
    pub fn matches(&self, view: &dyn FlowView, tags: &[String]) -> Result<bool, FailClosedReason> {
        Scope::new(view, tags, &()).check(&self.pred)
    }
}

/// Keep only the effects that still apply when the request is refused.
fn refused_effects(effects: &mut Vec<Effect>) {
    effects.retain(|e| matches!(e, Effect::Log { .. } | Effect::SetState { .. }));
}

/// Keep only the effects that still apply when the exchange is stopped.
fn stopped_effects(effects: &mut Vec<WatchEffect>) {
    effects.retain(|e| matches!(e, WatchEffect::Log { .. } | WatchEffect::SetState { .. }));
}

impl Policy {
    /// The head decision: the forwarding decision at the request
    /// head.
    ///
    /// Every rule that takes part in it ([`RuleKind::at_head`]) is
    /// evaluated, top to bottom; rules that read a watched value are
    /// skipped (not false). The decision does not depend on order:
    ///
    /// * if any matching rule denies, the request is denied
    ///   (`terminal_rule` = the first matching deny in list order);
    /// * else if any matching rule allows, it is allowed (`terminal_rule` =
    ///   the first matching allow, whose options — `upgrade`, `private_ok`
    ///   — are the only ones granted; options are never merged);
    /// * else it is denied (`terminal_rule` = `_default`).
    ///
    /// Tags set by a matching rule are visible to the rules below it, and
    /// `state["k"]` sees earlier `set_state` effects. Effects of every
    /// matching rule are returned in list order when the request is
    /// allowed; when it is denied only `log` and `set_state` remain (tags
    /// are in [`Outcome::tags`]).
    ///
    /// Fail closed: if evaluating *any* head rule reaches a metric
    /// the view reports unavailable, an address list it cannot answer for,
    /// a missing value under an operator that cannot answer for `null`, an
    /// uninspectable body, or a `set_header` secret that cannot be resolved,
    /// the result is [`Decision::fail_closed`] (503, close) with
    /// `terminal_rule = "_fail_closed"`, whatever else matched.
    ///
    /// Allocation: nothing is allocated for rules that do not match, except
    /// what the view itself returns (e.g. `header.all`).
    pub fn evaluate_head(&self, view: &dyn FlowView, ctx: &EvalContext<'_>) -> Outcome {
        let mut tags: Vec<String> = ctx.initial_tags.to_vec();
        let mut effects: Vec<Effect> = Vec::new();
        let mut matched: Vec<RuleId> = Vec::new();
        let mut deny: Option<(usize, &Decision)> = None;
        let mut allow: Option<(usize, &Decision)> = None;
        for &i in &self.head {
            let rule = &self.rules[i];
            let hit = match &rule.when {
                None => Ok(true),
                Some(p) => Scope::new(view, &tags, &effects).check(p),
            };
            match hit {
                Ok(true) => {}
                Ok(false) => continue,
                Err(reason) => return self.fail(reason, matched, effects, tags),
            }
            matched.push(rule.id.clone());
            for action in &rule.head {
                match action {
                    CAction::Effect(e) => effects.push(e.clone()),
                    CAction::Tag(t) => {
                        if !tags.contains(t) {
                            tags.push(t.clone());
                        }
                    }
                    CAction::SetHeader { name, parts } => match render(parts, ctx) {
                        Ok(value) => effects.push(Effect::SetHeader {
                            name: name.clone(),
                            value,
                        }),
                        Err(reason) => return self.fail(reason, matched, effects, tags),
                    },
                    CAction::Terminal(d @ Decision::Allow(_)) => {
                        allow.get_or_insert((i, d));
                    }
                    CAction::Terminal(d @ Decision::Deny(_)) => {
                        deny.get_or_insert((i, d));
                    }
                }
            }
        }
        let (decision, terminal_rule) = match (deny, allow) {
            // Deny wins; otherwise the first matching allow.
            (Some((i, d)), _) | (None, Some((i, d))) => (d.clone(), self.rules[i].id.clone()),
            (None, None) => (Decision::default_deny(), self.default_id.clone()),
        };
        if !decision.is_allow() {
            refused_effects(&mut effects);
        }
        Outcome {
            decision,
            matched,
            terminal_rule,
            fail_closed_reason: None,
            effects,
            tags,
        }
    }

    fn fail(
        &self,
        reason: FailClosedReason,
        matched: Vec<RuleId>,
        mut effects: Vec<Effect>,
        tags: Vec<String>,
    ) -> Outcome {
        refused_effects(&mut effects);
        Outcome {
            decision: Decision::fail_closed(),
            matched,
            terminal_rule: self.fail_closed_id.clone(),
            fail_closed_reason: Some(reason),
            effects,
            tags,
        }
    }

    /// Per-exchange watching state, starting from the tags the head
    /// decision produced.
    pub fn watch_state(&self, head_tags: &[String]) -> WatchState {
        WatchState {
            fired: vec![false; self.watching.len()],
            tags: head_tags.to_vec(),
            stopped: false,
        }
    }

    /// Whether an event changing `changed` can re-check any watching rule.
    /// One mask test; callers use it to skip per-chunk work entirely.
    pub fn watches(&self, changed: Reads) -> bool {
        self.watch_triggers.intersects(changed)
    }

    /// Re-check the watching rules after a value changed.
    ///
    /// `changed` is what just became known or changed (e.g.
    /// [`Reads::BODY_BYTES`] for a request body chunk, plus
    /// [`Reads::METRIC_REQUEST_BYTES`] if this exchange's bytes were just
    /// added to such a metric); `known` is every watched field known so far
    /// (a rule is only checked once everything it reads is known). Rules
    /// whose triggers intersect `changed` are checked top to bottom; the
    /// first matching deny stops the exchange. A watching rule's
    /// non-terminal effects apply once, the first time it matches; it is not
    /// checked again after that.
    ///
    /// Returns `None` when nothing matched (no allocation in that case:
    /// the steady-state per-chunk path). `Some` with `stop` set means the
    /// exchange must stop: a matching deny, or any fail-closed input (an
    /// error never lets the exchange continue). After a stop every call
    /// returns `None`.
    pub fn evaluate_watching(
        &self,
        changed: Reads,
        known: Reads,
        st: &mut WatchState,
        view: &dyn FlowView,
    ) -> Option<WatchOutcome> {
        if st.stopped || !self.watch_triggers.intersects(changed) {
            return None;
        }
        let mut out: Option<WatchOutcome> = None;
        for (k, &i) in self.watching.iter().enumerate() {
            let rule = &self.rules[i];
            if st.fired[k]
                || !rule.shape.triggers.intersects(changed)
                || !rule.shape.fields.is_subset(known)
            {
                continue;
            }
            let pending: &dyn PendingState = out.as_ref().map_or(&(), |o| &o.effects);
            let hit = match &rule.when {
                None => Ok(true),
                Some(p) => Scope::new(view, &st.tags, pending).check(p),
            };
            let o = out.get_or_insert_with(WatchOutcome::default);
            match hit {
                Ok(true) => {}
                Ok(false) => continue,
                Err(reason) => {
                    return Some(self.watch_stop(st, o, None, Some(reason)));
                }
            }
            st.fired[k] = true;
            o.matched.push(rule.id.clone());
            for action in &rule.watching {
                match action {
                    WatchAction::Effect(e) => o.effects.push(e.clone()),
                    WatchAction::Tag(t) => {
                        if !st.tags.contains(t) {
                            st.tags.push(t.clone());
                            o.tags.push(t.clone());
                        }
                    }
                    WatchAction::Deny(d) => {
                        return Some(self.watch_stop(
                            st,
                            o,
                            Some((rule.id.clone(), d.clone())),
                            None,
                        ));
                    }
                }
            }
        }
        out.filter(|o| !o.matched.is_empty())
    }

    fn watch_stop(
        &self,
        st: &mut WatchState,
        o: &mut WatchOutcome,
        deny: Option<(RuleId, Deny)>,
        reason: Option<FailClosedReason>,
    ) -> WatchOutcome {
        st.stopped = true;
        let mut o = std::mem::take(o);
        stopped_effects(&mut o.effects);
        match (deny, reason) {
            (Some((id, d)), _) => {
                o.stop = Some(d);
                o.terminal_rule = Some(id);
            }
            (None, reason) => {
                o.stop = Some(Deny::fail_closed());
                o.terminal_rule = Some(self.fail_closed_id.clone());
                o.fail_closed_reason = reason;
            }
        }
        o
    }
}

/// Substitute secrets into a `set_header` value and validate the result.
fn render(parts: &[Part], ctx: &EvalContext<'_>) -> Result<String, FailClosedReason> {
    let mut out = String::new();
    for part in parts {
        match part {
            Part::Lit(s) => out.push_str(s),
            Part::Secret(name) => {
                let value = (ctx.secrets)(name)
                    .ok_or_else(|| FailClosedReason::SecretMissing(name.clone()))?;
                if !is_header_value(&value) {
                    return Err(FailClosedReason::SecretInvalid(name.clone()));
                }
                out.push_str(&value);
            }
        }
    }
    Ok(out)
}
