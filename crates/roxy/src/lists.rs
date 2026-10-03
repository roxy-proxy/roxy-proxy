//! Loading `address_lists:` (docs/upstream.md#address-lists) for `roxy check`, startup,
//! every reload and `roxy rule test`.
//!
//! Fail closed: any list that cannot be read or parsed is an error for the
//! whole load. Callers never substitute an empty list, so a broken list can
//! only ever stop roxy from starting or keep the previous snapshot (with
//! the previous lists) running.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use roxy_proxy::addrlist::{self, AddressList, AddressLists};

use crate::config::{self, AddressListSource, Config};

/// Reads at most `max_bytes` of `path` as UTF-8 text.
fn read_capped(path: &Path, max_bytes: u64) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let len = file
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?
        .len();
    let too_big = |n: u64| {
        format!(
            "{}: address list file is {n} bytes, over limits.max_address_list_bytes \
             ({max_bytes} bytes)",
            path.display()
        )
    };
    if len > max_bytes {
        return Err(too_big(len));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    // The file may grow between `metadata` and `read`.
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        return Err(too_big(bytes.len() as u64));
    }
    String::from_utf8(bytes).map_err(|e| {
        format!(
            "{}: address list file is not valid UTF-8 (byte {})",
            path.display(),
            e.utf8_error().valid_up_to()
        )
    })
}

/// Loads and compiles one list. `index` is its position under
/// `address_lists` (for inline error paths). Errors read
/// `<file>:<line>: address list <name>: "<entry>" <reason>`.
pub fn load_one(
    index: usize,
    list: &config::AddressList,
    max_bytes: u64,
) -> Result<AddressList, String> {
    match &list.source {
        AddressListSource::File(path) => {
            let text = read_capped(path, max_bytes)?;
            AddressList::parse(&list.name, &text).map_err(|e| {
                format!(
                    "{}:{}: address list {}: {:?} {}",
                    path.display(),
                    e.line,
                    e.list,
                    e.entry,
                    e.reason
                )
            })
        }
        AddressListSource::Inline(entries) => {
            let mut nets = Vec::with_capacity(entries.len());
            for (j, e) in entries.iter().enumerate() {
                let net = addrlist::parse_entry(e).map_err(|reason| {
                    format!(
                        "address_lists[{index}].inline[{j}]: address list {}: {:?} {reason}",
                        list.name,
                        e.trim()
                    )
                })?;
                nets.push(net);
            }
            Ok(AddressList::from_nets(&list.name, nets))
        }
    }
}

/// Loads every list in `config`. Every failure is reported; any failure
/// fails the whole load.
pub fn load_all(config: &Config) -> Result<AddressLists, Vec<String>> {
    let max = config.limits.max_address_list_bytes.as_u64();
    let mut lists = AddressLists::new();
    let mut errors = Vec::new();
    for (i, spec) in config.address_lists.iter().enumerate() {
        match load_one(i, spec, max) {
            Ok(list) => {
                lists.insert(spec.name.clone(), Arc::new(list));
            }
            Err(e) => errors.push(e),
        }
    }
    if errors.is_empty() {
        Ok(lists)
    } else {
        Err(errors)
    }
}

/// Every list file the config names (for the reload watcher).
pub fn files(config: &Config) -> Vec<PathBuf> {
    config
        .address_lists
        .iter()
        .filter_map(|l| match &l.source {
            AddressListSource::File(p) => Some(p.clone()),
            AddressListSource::Inline(_) => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(yaml: &str) -> Config {
        Config::from_yaml(yaml).unwrap()
    }

    #[test]
    fn loads_files_and_inline_lists() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("b.txt");
        std::fs::write(&f, "# feed\n203.0.113.0/24\n203.0.113.7\n\n2001:db8::/32\n").unwrap();
        let c = config(&format!(
            "version: 1\naddress_lists:\n  - {{ name: b, file: {:?} }}\n  \
             - {{ name: i, inline: [10.0.0.0/8, 10.1.0.0/16, \"::1\"] }}\n",
            f.to_str().unwrap()
        ));
        let lists = load_all(&c).unwrap();
        assert_eq!(lists["b"].len(), 2);
        assert_eq!(lists["i"].len(), 2);
        assert!(lists["b"].contains("203.0.113.9".parse().unwrap()));
        assert_eq!(files(&c), [f]);
    }

    #[test]
    fn errors_name_file_and_line_and_fail_the_whole_load() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("bad.txt");
        std::fs::write(&bad, "1.2.3.0/24\n# c\n10.0.0.1/8\n").unwrap();
        let good = dir.path().join("good.txt");
        std::fs::write(&good, "1.2.3.4\n").unwrap();
        let c = config(&format!(
            "version: 1\naddress_lists:\n  - {{ name: good, file: {:?} }}\n  \
             - {{ name: bad, file: {:?} }}\n  - {{ name: gone, file: /surely/not/here }}\n  \
             - {{ name: inl, inline: [1.2.3.4, 10.0.0.1/8] }}\n",
            good.to_str().unwrap(),
            bad.to_str().unwrap()
        ));
        let errs = load_all(&c).unwrap_err();
        assert_eq!(errs.len(), 3, "{errs:#?}");
        assert!(
            errs[0].starts_with(&format!(
                "{}:3: address list bad: \"10.0.0.1/8\" has host bits set",
                bad.display()
            )),
            "{}",
            errs[0]
        );
        assert!(errs[1].starts_with("/surely/not/here: "), "{}", errs[1]);
        assert!(
            errs[2].starts_with("address_lists[3].inline[1]: address list inl"),
            "{}",
            errs[2]
        );
    }

    #[test]
    fn size_cap() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("big.txt");
        std::fs::write(&f, "10.0.0.0/8\n".repeat(20)).unwrap();
        let c = config(&format!(
            "version: 1\nlimits: {{ max_address_list_bytes: 100 }}\n\
             address_lists: [{{ name: big, file: {:?} }}]\n",
            f.to_str().unwrap()
        ));
        let errs = load_all(&c).unwrap_err();
        assert!(
            errs[0].contains("over limits.max_address_list_bytes"),
            "{errs:?}"
        );
        std::fs::write(&f, [0xff, 0xfe, b'\n']).unwrap();
        let errs = load_all(&c).unwrap_err();
        assert!(errs[0].contains("not valid UTF-8"), "{errs:?}");
    }
}
