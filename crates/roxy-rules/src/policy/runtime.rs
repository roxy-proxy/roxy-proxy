//! The admission decision and in-flight evaluation over a compiled [`Policy`],
//! plus the runtime side of [`MetricDef`] and [`Condition`].

use super::{
    CAction, Condition, InFlightAction, InFlightState, MetricDef, Part, Policy, SignSpec,
    is_header_value,
};
use crate::diag::RuleId;
use crate::eval::{
    AwsSigV4, Credential, Decision, Deny, Effect, EvalContext, FailClosedReason, InFlightEffect,
    InFlightOutcome, Outcome, PendingState, Scope, SetHeaderValue,
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
fn stopped_effects(effects: &mut Vec<InFlightEffect>) {
    effects.retain(|e| {
        matches!(
            e,
            InFlightEffect::Log { .. } | InFlightEffect::SetState { .. }
        )
    });
}

impl Policy {
    /// The admission decision: the forwarding decision, made before the
    /// request goes upstream.
    ///
    /// Every rule that takes part in it
    /// ([`RuleKind::at_admission`](super::RuleKind::at_admission)) is
    /// evaluated, top to bottom; rules that read an in-flight field are
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
    /// Fail closed: if evaluating *any* admission rule reaches a metric
    /// the view reports unavailable, an address list it cannot answer for,
    /// a missing value under an operator that cannot answer for `null`, an
    /// uninspectable body, or a `set_header` secret that cannot be resolved,
    /// the result is [`Decision::fail_closed`] (503, close) with
    /// `terminal_rule = "_fail_closed"`, whatever else matched.
    ///
    /// Allocation: nothing is allocated for rules that do not match, except
    /// what the view itself returns (e.g. `header.all`).
    pub fn evaluate_admission(&self, view: &dyn FlowView, ctx: &EvalContext<'_>) -> Outcome {
        let mut tags: Vec<String> = ctx.initial_tags.to_vec();
        let mut effects: Vec<Effect> = Vec::new();
        let mut matched: Vec<RuleId> = Vec::new();
        let mut deny: Option<(usize, Decision)> = None;
        let mut allow: Option<(usize, &Decision)> = None;
        let mut quarantine: Option<RuleId> = None;
        for &i in &self.admission {
            let rule = &self.rules[i];
            let hit = match &rule.when {
                None => Ok(true),
                Some(p) => Scope::new(view, &tags, &effects).check(p),
            };
            match hit {
                Ok(true) => {}
                Ok(false) => continue,
                Err(reason) => return self.fail(reason, matched, effects, tags, quarantine),
            }
            matched.push(rule.id.clone());
            if rule.quarantines {
                quarantine.get_or_insert_with(|| rule.id.clone());
            }
            for action in &rule.admission {
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
                        Err(reason) => {
                            return self.fail(reason, matched, effects, tags, quarantine);
                        }
                    },
                    CAction::Sign(spec) => match resolve_sign(spec, ctx) {
                        Ok(s) => effects.push(Effect::Sign(s)),
                        Err(reason) => {
                            return self.fail(reason, matched, effects, tags, quarantine);
                        }
                    },
                    CAction::Terminal(d @ Decision::Allow(_)) => {
                        allow.get_or_insert((i, d));
                    }
                    CAction::Terminal(d @ Decision::Deny(_)) => {
                        deny.get_or_insert_with(|| (i, d.clone()));
                    }
                }
            }
        }
        let (decision, terminal_rule) = match (deny, allow) {
            // Deny wins; otherwise the first matching allow.
            (Some((i, d)), _) => (d, self.rules[i].id.clone()),
            (None, Some((i, d))) => (d.clone(), self.rules[i].id.clone()),
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
            quarantine,
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
        quarantine: Option<RuleId>,
    ) -> Outcome {
        refused_effects(&mut effects);
        Outcome {
            decision: Decision::fail_closed(),
            matched,
            terminal_rule: self.fail_closed_id.clone(),
            fail_closed_reason: Some(reason),
            quarantine,
            effects,
            tags,
        }
    }

    /// Per-exchange in-flight state.
    pub fn in_flight_state(&self) -> InFlightState {
        InFlightState {
            fired: vec![false; self.in_flight.len()],
            stopped: false,
        }
    }

    /// Whether an event changing `changed` can re-check any in-flight rule.
    /// One mask test; callers use it to skip per-chunk work entirely.
    pub fn triggers_on(&self, changed: Reads) -> bool {
        self.in_flight_triggers.intersects(changed)
    }

    /// Re-check the in-flight rules after a value changed.
    ///
    /// `changed` is what just became known or changed (e.g.
    /// [`Reads::BODY_BYTES`] for a request body chunk, plus
    /// [`Reads::METRIC_REQUEST_BYTES`] if this exchange's bytes were just
    /// added to such a metric); `known` is every in-flight field known so far
    /// (a rule is only checked once everything it reads is known). Rules
    /// whose triggers intersect `changed` are checked top to bottom, every
    /// one of them even after a deny matched, as at admission: the `log` and
    /// `set_state` effects of every matching rule apply, the first matching
    /// deny in list order is the terminal rule, and an unavailable input
    /// anywhere in the pass fails closed over a deny. An in-flight rule's
    /// non-terminal effects apply once, the first time it matches; it is not
    /// checked again after that.
    ///
    /// `tags` is the flow's tag set, which the caller owns so that whatever
    /// else tags the flow between two evaluations (an addon, say) is seen by
    /// the next one: `tag[..]` reads it and a `tag` action adds to it.
    ///
    /// Returns `None` when nothing matched (no allocation in that case:
    /// the steady-state per-chunk path). `Some` with `stop` set means the
    /// exchange must stop: a matching deny, or any fail-closed input (an
    /// error never lets the exchange continue). After a stop every call
    /// returns `None`.
    pub fn evaluate_in_flight(
        &self,
        changed: Reads,
        known: Reads,
        st: &mut InFlightState,
        tags: &mut Vec<String>,
        view: &dyn FlowView,
    ) -> Option<InFlightOutcome> {
        if st.stopped || !self.in_flight_triggers.intersects(changed) {
            return None;
        }
        let mut out: Option<InFlightOutcome> = None;
        let mut deny: Option<(RuleId, Deny)> = None;
        for (k, &i) in self.in_flight.iter().enumerate() {
            let rule = &self.rules[i];
            if st.fired[k]
                || !rule.shape.triggers.intersects(changed)
                || !rule.shape.fields.is_subset(known)
            {
                continue;
            }
            let pending: &dyn PendingState = out.as_ref().map_or(&(), |o| &o.effects);
            // An in-flight rule reads something, so it has a `when`; a rule
            // without one would match, which can only add denies.
            let hit = match &rule.when {
                None => Ok(true),
                Some(p) => Scope::new(view, tags, pending).check(p),
            };
            match hit {
                Ok(true) => {}
                Ok(false) => continue,
                Err(reason) => {
                    return Some(self.in_flight_stop(st, out, None, Some(reason)));
                }
            }
            let o = out.get_or_insert_with(InFlightOutcome::default);
            st.fired[k] = true;
            o.matched.push(rule.id.clone());
            if rule.quarantines {
                o.quarantine.get_or_insert_with(|| rule.id.clone());
            }
            for action in &rule.in_flight {
                match action {
                    InFlightAction::Effect(e) => o.effects.push(e.clone()),
                    InFlightAction::Tag(t) => {
                        if !tags.contains(t) {
                            tags.push(t.clone());
                            o.tags.push(t.clone());
                        }
                    }
                    InFlightAction::Deny(d) => {
                        if deny.is_none() {
                            deny = Some((rule.id.clone(), d.clone()));
                        }
                    }
                }
            }
        }
        if deny.is_some() {
            return Some(self.in_flight_stop(st, out, deny, None));
        }
        out.filter(|o| !o.matched.is_empty())
    }

    fn in_flight_stop(
        &self,
        st: &mut InFlightState,
        o: Option<InFlightOutcome>,
        deny: Option<(RuleId, Deny)>,
        reason: Option<FailClosedReason>,
    ) -> InFlightOutcome {
        st.stopped = true;
        let mut o = o.unwrap_or_default();
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
fn render(parts: &[Part], ctx: &EvalContext<'_>) -> Result<SetHeaderValue, FailClosedReason> {
    let (out, from_secret) = render_text(parts, ctx)?;
    Ok(if from_secret {
        SetHeaderValue::from_secret(out)
    } else {
        SetHeaderValue::literal(out)
    })
}

/// Substitute secrets into a template. Every secret must be a valid header
/// value: the rendered text goes into a request header, or (a signing key)
/// into a signature that does. Also returns whether a secret was used.
fn render_text(parts: &[Part], ctx: &EvalContext<'_>) -> Result<(String, bool), FailClosedReason> {
    let mut out = String::new();
    let mut from_secret = false;
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
                from_secret = true;
            }
        }
    }
    Ok((out, from_secret))
}

/// Resolve the credentials of a `sign: aws_sigv4` action.
fn resolve_sign(spec: &SignSpec, ctx: &EvalContext<'_>) -> Result<AwsSigV4, FailClosedReason> {
    let credential = |parts: &[Part]| render_text(parts, ctx).map(|(v, _)| Credential::new(v));
    Ok(AwsSigV4 {
        service: spec.service.clone(),
        region: spec.region.clone(),
        access_key_id: credential(&spec.access_key_id)?,
        secret_access_key: credential(&spec.secret_access_key)?,
        session_token: spec.session_token.as_deref().map(credential).transpose()?,
        unsigned_payload: spec.unsigned_payload,
    })
}
