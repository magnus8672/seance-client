//! Which tab an Agent Bridge call acts on.

use crate::settings::SavedHost;

pub const MAX_TARGET_LEN: usize = 256;

pub struct TabInfo {
    pub id: u32,
    pub host: String,
    pub port: u16,
    pub active: bool,
    pub pinned: bool,
}

/// Tabs an agent may address: the ones the operator shared (pinned) or, when
/// none are shared, the tab being viewed. Only these tabs keep streaming, so
/// any other tab's framebuffer would be stale anyway.
pub fn addressable(tabs: &[TabInfo]) -> Vec<&TabInfo> {
    let shared = tabs.iter().any(|t| t.pinned);
    tabs.iter()
        .filter(|t| if shared { t.pinned } else { t.active })
        .collect()
}

/// The saved-host name for an address when it has one, else `host:port`.
pub fn label(host: &str, port: u16, saved: &[SavedHost]) -> String {
    saved
        .iter()
        .find(|s| s.port == port && s.host.eq_ignore_ascii_case(host) && !s.name.is_empty())
        .map(|s| s.name.clone())
        .unwrap_or_else(|| format!("{host}:{port}"))
}

/// Resolve a call's `target` to a tab id. Only identifiers the operator
/// controls are matched (tab id, saved-host name, the address they connected
/// to), never the RFB desktop name, which the VNC server chooses and could use
/// to impersonate another host.
pub fn resolve(tabs: &[TabInfo], saved: &[SavedHost], target: Option<&str>) -> Result<u32, String> {
    let open = addressable(tabs);
    let Some(target) = target.map(str::trim).filter(|t| !t.is_empty()) else {
        return match open.as_slice() {
            [] => Err(
                "no session is shared with agents: open a host and share its tab in the Agent Bridge panel"
                    .into(),
            ),
            [only] => Ok(only.id),
            _ => Err(
                "several sessions are shared with agents; pass `target` (see list_targets)".into(),
            ),
        };
    };
    if target.len() > MAX_TARGET_LEN {
        return Err(format!("target is longer than {MAX_TARGET_LEN} characters"));
    }

    let found = if target.bytes().all(|b| b.is_ascii_digit()) {
        let id = target.parse::<u32>().ok();
        filter(&open, |t| Some(t.id) == id)
    } else {
        let named: Vec<(&str, u16)> = saved
            .iter()
            .filter(|s| s.name.eq_ignore_ascii_case(target))
            .map(|s| (s.host.as_str(), s.port))
            .collect();
        let by_name = filter(&open, |t| {
            named
                .iter()
                .any(|(h, p)| *p == t.port && h.eq_ignore_ascii_case(&t.host))
        });
        let by_addr = match target.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(p) => filter(&open, |t| t.port == p && t.host.eq_ignore_ascii_case(h)),
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        };
        let by_host = filter(&open, |t| t.host.eq_ignore_ascii_case(target));
        [by_name, by_addr, by_host]
            .into_iter()
            .find(|m| !m.is_empty())
            .unwrap_or_default()
    };

    match found.as_slice() {
        [] => Err(format!(
            "no session shared with agents matches `{target}`; call list_targets, or ask the operator to share it"
        )),
        [only] => Ok(only.id),
        many => Err(format!(
            "`{target}` matches {} shared sessions; pass a tab id from list_targets",
            many.len()
        )),
    }
}

fn filter<'a>(open: &[&'a TabInfo], f: impl Fn(&TabInfo) -> bool) -> Vec<&'a TabInfo> {
    open.iter().copied().filter(|t| f(t)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tab(id: u32, host: &str, port: u16, active: bool, pinned: bool) -> TabInfo {
        TabInfo {
            id,
            host: host.into(),
            port,
            active,
            pinned,
        }
    }

    fn saved(name: &str, host: &str, port: u16) -> SavedHost {
        SavedHost {
            name: name.into(),
            host: host.into(),
            port,
            username: None,
            has_password: false,
            group: None,
        }
    }

    fn lab() -> Vec<SavedHost> {
        vec![
            saved("AGENT01", "192.0.2.10", 5900),
            saved("AGENT02", "192.0.2.11", 5900),
        ]
    }

    #[test]
    fn no_pins_follows_the_active_tab_only() {
        let tabs = [
            tab(1, "192.0.2.10", 5900, true, false),
            tab(2, "192.0.2.11", 5900, false, false),
        ];
        assert_eq!(resolve(&tabs, &lab(), None), Ok(1));
        assert_eq!(resolve(&tabs, &lab(), Some("agent01")), Ok(1));
        assert!(resolve(&tabs, &lab(), Some("AGENT02")).is_err());
        assert!(resolve(&tabs, &lab(), Some("2")).is_err());
    }

    #[test]
    fn one_pin_is_the_default_target() {
        let tabs = [
            tab(1, "192.0.2.10", 5900, true, false),
            tab(2, "192.0.2.11", 5900, false, true),
        ];
        assert_eq!(resolve(&tabs, &lab(), None), Ok(2));
        assert!(resolve(&tabs, &lab(), Some("AGENT01")).is_err());
    }

    #[test]
    fn several_pins_need_an_explicit_target() {
        let tabs = [
            tab(1, "192.0.2.10", 5900, true, true),
            tab(2, "192.0.2.11", 5900, false, true),
        ];
        let err = resolve(&tabs, &lab(), None).unwrap_err();
        assert!(err.contains("pass `target`"));
        assert_eq!(resolve(&tabs, &lab(), Some("agent02")), Ok(2));
        assert_eq!(resolve(&tabs, &lab(), Some("192.0.2.11:5900")), Ok(2));
        assert_eq!(resolve(&tabs, &lab(), Some("192.0.2.10")), Ok(1));
        assert_eq!(resolve(&tabs, &lab(), Some(" 2 ")), Ok(2));
    }

    #[test]
    fn the_same_host_twice_is_ambiguous_until_a_tab_id_is_given() {
        let tabs = [
            tab(1, "192.0.2.10", 5900, true, true),
            tab(2, "192.0.2.10", 5900, false, true),
        ];
        let err = resolve(&tabs, &lab(), Some("AGENT01")).unwrap_err();
        assert!(err.contains("matches 2"));
        assert_eq!(resolve(&tabs, &lab(), Some("2")), Ok(2));
    }

    #[test]
    fn saved_name_wins_over_a_host_with_the_same_text() {
        let tabs = [
            tab(1, "dc02", 5900, false, true),
            tab(2, "192.0.2.12", 5900, true, true),
        ];
        let saved = [saved("dc02", "192.0.2.12", 5900)];
        assert_eq!(resolve(&tabs, &saved, Some("DC02")), Ok(2));
    }

    #[test]
    fn unknown_and_oversized_targets_are_refused_without_listing_tabs() {
        let tabs = [tab(1, "192.0.2.10", 5900, true, true)];
        let err = resolve(&tabs, &lab(), Some("nope")).unwrap_err();
        assert!(!err.contains("192.0.2.10") && !err.contains("AGENT01"));
        assert!(resolve(&tabs, &lab(), Some(&"x".repeat(MAX_TARGET_LEN + 1))).is_err());
    }

    #[test]
    fn nothing_open_is_an_error() {
        assert!(resolve(&[], &lab(), None).is_err());
    }

    #[test]
    fn label_prefers_the_saved_name() {
        assert_eq!(label("192.0.2.10", 5900, &lab()), "AGENT01");
        assert_eq!(label("192.0.2.13", 5900, &lab()), "192.0.2.13:5900");
    }
}
