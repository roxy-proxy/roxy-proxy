//! Renaming the layer-owned names an expression refers to.
//!
//! An expression names a metric (`metric.id`) or an address list (`@name`)
//! by the id its layer gave it; the rendered config needs the namespaced
//! id. The expression is parsed, the references are renamed in the tree
//! and the tree is printed back: the printer emits canonical source that
//! parses to the same tree, so this cannot change what the rule means. An
//! expression that names nothing is kept as written.

use roxy_rules::ast::{Expr, Lit, LitNode, Node, Operand};

/// Which kind of name a reference uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Metric,
    AddressList,
}

/// What [`rewrite`] found in an expression.
#[derive(Debug, Default)]
pub(crate) struct Rewritten {
    /// The expression with every reference renamed.
    pub text: String,
    /// The tags it reads (`tag["x"]`), in order of first appearance.
    pub tags: Vec<String>,
}

/// Parses `src`, renames every metric and address-list reference through
/// `rename` and returns the result with the tags the expression reads. An
/// expression that does not parse is returned as the engine's diagnostic;
/// `rename` returning `Err` aborts with that error.
pub(crate) fn rewrite<E>(
    src: &str,
    mut rename: impl FnMut(Kind, &str) -> Result<String, E>,
) -> Result<Result<Rewritten, roxy_rules::Diagnostic>, E> {
    let mut node = match roxy_rules::parse(src) {
        Ok(n) => n,
        Err(d) => return Ok(Err(d)),
    };
    let mut out = Rewritten::default();
    let mut changed = false;
    walk(&mut node, &mut |operand| {
        match operand {
            Operand::Field(f) => {
                let path: Vec<&str> = f.path.iter().map(String::as_str).collect();
                match (path.as_slice(), &f.index) {
                    (["metric", id], None) => {
                        let renamed = rename(Kind::Metric, id)?;
                        changed |= renamed != *id;
                        f.path[1] = renamed;
                    }
                    (["tag"], Some(t)) if !out.tags.contains(t) => out.tags.push(t.clone()),
                    _ => {}
                }
            }
            Operand::Lit(l) => rename_lists(l, &mut rename, &mut changed)?,
        }
        Ok(())
    })?;
    out.text = if changed {
        node.to_string()
    } else {
        src.to_owned()
    };
    Ok(Ok(out))
}

fn rename_lists<E>(
    l: &mut LitNode,
    rename: &mut impl FnMut(Kind, &str) -> Result<String, E>,
    changed: &mut bool,
) -> Result<(), E> {
    match &mut l.lit {
        Lit::AddressList(name) => {
            let renamed = rename(Kind::AddressList, name)?;
            *changed |= renamed != *name;
            *name = renamed;
        }
        Lit::List(items) => {
            for item in items {
                rename_lists(item, rename, changed)?;
            }
        }
        Lit::Str(_)
        | Lit::Int(..)
        | Lit::Bool(_)
        | Lit::Ip(_)
        | Lit::Cidr(_)
        | Lit::Method(_)
        | Lit::Null => {}
    }
    Ok(())
}

/// Visits every operand of the tree.
fn walk<E>(node: &mut Node, f: &mut impl FnMut(&mut Operand) -> Result<(), E>) -> Result<(), E> {
    match &mut node.expr {
        Expr::Or(a, b) | Expr::And(a, b) => {
            walk(a, f)?;
            walk(b, f)
        }
        Expr::Not(a) => walk(a, f),
        Expr::Cmp { lhs, rhs, .. } => {
            f(lhs)?;
            f(rhs)
        }
        Expr::Pred(o) => f(o),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix() -> impl FnMut(Kind, &str) -> Result<String, std::convert::Infallible> {
        |_, name| Ok(format!("org__{name}"))
    }

    #[test]
    fn renames_metrics_and_lists_and_collects_tags() {
        let src = r#"metric.rate > 10 and client.ip in @internal and tag["a"] and not tag["b"]"#;
        let out = rewrite(src, prefix()).unwrap().unwrap();
        assert_eq!(
            out.text,
            r#"metric.org__rate > 10 and client.ip in @org__internal and tag["a"] and not tag["b"]"#
        );
        assert_eq!(out.tags, ["a", "b"]);
    }

    #[test]
    fn untouched_expression_keeps_its_text() {
        let src = "host  under   \"github.com\"";
        let out = rewrite(src, prefix()).unwrap().unwrap();
        assert_eq!(out.text, src);
    }

    #[test]
    fn parse_errors_come_back_as_diagnostics() {
        assert!(rewrite("host under", prefix()).unwrap().is_err());
    }
}
