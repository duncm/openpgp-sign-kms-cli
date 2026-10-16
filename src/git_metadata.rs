//! Opt-in audit context from bounded Git headers; never changes the signed bytes.
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

const HEADER_LIMIT: usize = 64 * 1024;

struct Metadata {
    kind: &'static str,
    fields: Vec<String>,
}

fn object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn encode(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            result.push(char::from(byte));
        } else {
            result.push_str(&format!("%{byte:02X}"));
        }
    }
    result
}

fn recognize(prefix: &[u8]) -> Option<Metadata> {
    let end = prefix.windows(2).position(|w| w == b"\n\n")?;
    let text = std::str::from_utf8(&prefix[..end]).ok()?;
    let mut headers: Vec<(&str, &str)> = Vec::new();
    for line in text.split('\n') {
        if line.starts_with(' ') {
            // Git's multiline signatures/mergetags are opaque. A continued identity
            // or object field is not an ordinary Git header we can safely identify.
            let previous = headers.last()?.0;
            if matches!(
                previous,
                "tree" | "parent" | "object" | "type" | "tag" | "author" | "committer" | "tagger"
            ) {
                return None;
            }
            continue;
        }
        let (name, value) = line.split_once(' ')?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.is_empty()
            || value.chars().any(char::is_control)
        {
            return None;
        }
        headers.push((name, value));
    }
    let one = |name| {
        let mut values = headers.iter().filter(|h| h.0 == name).map(|h| h.1);
        let value = values.next()?;
        values.next().is_none().then_some(value)
    };
    match headers.first()?.0 {
        "tree" => {
            let tree = one("tree")?;
            if !object_id(tree)
                || one("author").is_none()
                || one("committer").is_none()
                || headers
                    .iter()
                    .any(|h| matches!(h.0, "object" | "type" | "tag"))
            {
                return None;
            }
            let mut fields = vec![format!("tree={tree}")];
            for (_, parent) in headers.iter().filter(|h| h.0 == "parent") {
                if !object_id(parent) || parent.len() != tree.len() {
                    return None;
                }
                fields.push(format!("parent={parent}"));
            }
            Some(Metadata {
                kind: "commit",
                fields,
            })
        }
        "object" => {
            let object = one("object")?;
            let kind = one("type")?;
            let tag = one("tag")?;
            if !object_id(object)
                || !matches!(kind, "commit" | "tree" | "blob" | "tag")
                || headers
                    .iter()
                    .any(|h| matches!(h.0, "tree" | "parent" | "author" | "committer"))
            {
                return None;
            }
            Some(Metadata {
                kind: "tag",
                fields: vec![
                    format!("target_id={object}"),
                    format!("target_type={kind}"),
                    format!("tag={}", encode(tag)),
                ],
            })
        }
        _ => None,
    }
}

/// Replay unrecognized input directly. Spool recognized input to hash all bytes
/// before the KMS request; only the first 64 KiB are considered as headers.
pub fn prepare(
    mut input: Box<dyn Read>,
    description: Option<&str>,
) -> Result<(Box<dyn Read>, String)> {
    crate::provider::user_agent(description)?;
    let mut prefix = Vec::new();
    input
        .by_ref()
        .take(HEADER_LIMIT as u64)
        .read_to_end(&mut prefix)?;
    let Some(metadata) = recognize(&prefix) else {
        return Ok((
            Box::new(Cursor::new(prefix).chain(input)),
            description.unwrap_or_default().to_owned(),
        ));
    };
    let mut spool = tempfile::tempfile().context("spooling Git signing input")?;
    let mut hash = Sha256::new();
    let mut source = Cursor::new(prefix).chain(input);
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        spool.write_all(&buffer[..count])?;
    }
    spool.seek(SeekFrom::Start(0))?;
    let mut description = description.unwrap_or_default().to_owned();
    if !description.is_empty() {
        description.push('\n');
    }
    description.push_str(&format!(
        "git_type={} payload_sha256={}",
        metadata.kind,
        hex::encode(hash.finalize())
    ));
    crate::provider::user_agent(Some(&description))
        .context("explicit description leaves no room for Git payload digest; shorten it or disable Git metadata")?;
    for field in metadata.fields {
        let candidate = format!("{description} {field}");
        if crate::provider::user_agent(Some(&candidate)).is_ok() {
            description = candidate;
        }
    }
    Ok((Box::new(spool), description))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn commit(width: usize, parents: usize) -> String {
        let mut text = format!("tree {}\n", "a".repeat(width));
        for _ in 0..parents {
            text.push_str(&format!("parent {}\n", "b".repeat(width)));
        }
        text + "author Private Person <private@example.com> 1 +0000\ncommitter Private Person <private@example.com> 1 +0000\ngpgsig opaque\n continuation\n\nPrivate message\n"
    }
    fn enrich(bytes: Vec<u8>, description: Option<&str>) -> Result<String> {
        let (mut input, result) = prepare(Box::new(Cursor::new(bytes.clone())), description)?;
        let mut replay = Vec::new();
        input.read_to_end(&mut replay)?;
        assert_eq!(replay, bytes);
        Ok(result)
    }
    #[test]
    fn commits_and_exact_payload_hash() {
        for width in [40, 64] {
            for parents in [0, 1, 2] {
                let mut bytes = commit(width, parents).into_bytes();
                bytes.extend([0, 255]); // Body need not be UTF-8.
                let expected = hex::encode(Sha256::digest(&bytes));
                let result = enrich(bytes, Some("release ✓")).unwrap();
                assert!(result.starts_with("release ✓\ngit_type=commit "));
                assert!(result.contains(&format!("payload_sha256={expected}")));
                assert_eq!(result.matches("parent=").count(), parents);
                assert!(!result.contains("Private") && !result.contains("private@example.com"));
            }
        }
    }
    #[test]
    fn tags_escape_values() {
        let input = format!(
            "object {}\ntype commit\ntag release/✓\ntagger Identity\n\nMessage",
            "a".repeat(40)
        );
        let result = enrich(input.into_bytes(), None).unwrap();
        assert!(result.contains("git_type=tag"));
        assert!(result.contains("target_type=commit"));
        assert!(result.contains("tag=release%2F%E2%9C%93"));
    }
    #[test]
    fn bounded_and_unrecognized_inputs_pass_through() {
        for bytes in [
            vec![],
            b"ordinary input\n".to_vec(),
            vec![b'x'; HEADER_LIMIT + 100],
            commit(40, 1).replace("tree a", "tree z").into_bytes(),
            commit(40, 0)
                .replace("\nauthor", "\n continuation\nauthor")
                .into_bytes(),
            commit(40, 0)
                .replace("\ncommitter", "\ntree duplicate\ncommitter")
                .into_bytes(),
        ] {
            assert_eq!(enrich(bytes, Some("audit")).unwrap(), "audit");
        }
    }
    #[test]
    fn budget_preserves_description_and_digest() {
        let input = commit(64, 100).into_bytes();
        let result = enrich(input.clone(), Some(&"x".repeat(600))).unwrap();
        assert!(result.starts_with(&"x".repeat(600)));
        assert!(result.contains("payload_sha256="));
        assert!(result.matches("parent=").count() < 100);
        assert!(crate::provider::user_agent(Some(&result)).unwrap().len() <= 1024);
        assert!(enrich(input, Some(&"x".repeat(730))).is_err());
    }
    #[test]
    fn large_body_is_preserved() {
        let mut input = commit(40, 0).into_bytes();
        input.extend(vec![42; 2 * 1024 * 1024]);
        assert!(enrich(input, None).unwrap().contains("git_type=commit"));
    }
}
