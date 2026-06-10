use anyhow::{Result, bail};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn render_placeholders(template: &str, replacements: &[(&str, &str)]) -> Result<String> {
    let mut replacements_by_key = BTreeMap::new();
    for (key, value) in replacements {
        if key.is_empty() {
            bail!("placeholder replacement key must not be empty");
        }
        if key.contains("@@") {
            bail!("placeholder replacement key must not include delimiters: {key}");
        }
        if replacements_by_key.insert(*key, *value).is_some() {
            bail!("duplicate placeholder replacement: {key}");
        }
    }

    let mut rendered = String::with_capacity(template.len());
    let mut used_keys = BTreeSet::new();
    let mut offset = 0;
    while let Some(relative_start) = template[offset..].find("@@") {
        let start = offset + relative_start;
        rendered.push_str(&template[offset..start]);
        let key_start = start + 2;
        let Some(relative_end) = template[key_start..].find("@@") else {
            bail!("unclosed placeholder starting at byte {start}");
        };
        let key_end = key_start + relative_end;
        let key = &template[key_start..key_end];
        let Some(replacement) = replacements_by_key.get(key) else {
            bail!("missing replacement for placeholder @@{key}@@");
        };
        rendered.push_str(replacement);
        used_keys.insert(key);
        offset = key_end + 2;
    }
    rendered.push_str(&template[offset..]);

    let unused_keys = replacements_by_key
        .keys()
        .copied()
        .filter(|key| !used_keys.contains(key))
        .collect::<Vec<_>>();
    if !unused_keys.is_empty() {
        bail!(
            "unused placeholder replacements: {}",
            unused_keys.join(", ")
        );
    }

    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::render_placeholders;

    #[test]
    fn render_placeholders_replaces_each_template_token_once() {
        let rendered =
            render_placeholders("alpha @@ONE@@ beta @@TWO@@", &[("ONE", "1"), ("TWO", "2")])
                .expect("render placeholders");

        assert_eq!(rendered, "alpha 1 beta 2");
    }

    #[test]
    fn render_placeholders_does_not_rescan_replacement_values() {
        let rendered =
            render_placeholders("alpha @@ONE@@", &[("ONE", "@@TWO@@")]).expect("render value");

        assert_eq!(rendered, "alpha @@TWO@@");
    }

    #[test]
    fn render_placeholders_errors_on_missing_template_key() {
        let err = render_placeholders("@@MISSING@@", &[]).expect_err("missing key must fail");

        assert_eq!(
            err.to_string(),
            "missing replacement for placeholder @@MISSING@@"
        );
    }

    #[test]
    fn render_placeholders_errors_on_unused_replacement_key() {
        let err = render_placeholders("plain text", &[("EXTRA", "value")]).expect_err("unused key");

        assert_eq!(err.to_string(), "unused placeholder replacements: EXTRA");
    }

    #[test]
    fn render_placeholders_errors_on_unclosed_template_key() {
        let err =
            render_placeholders("plain @@BROKEN", &[("BROKEN", "value")]).expect_err("unclosed");

        assert_eq!(err.to_string(), "unclosed placeholder starting at byte 6");
    }
}
