use regex::Regex;
use std::sync::OnceLock;

fn patterns() -> &'static [(Regex, &'static str)] {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    PATTERNS
        .get_or_init(|| {
            vec![
                (
                    Regex::new(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+")
                        .expect("regex bearer"),
                    "$1[REDACTED]",
                ),
                (
                    Regex::new(r"(?i)\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b")
                        .expect("regex jwt"),
                    "[REDACTED_JWT]",
                ),
                (
                    Regex::new(
                        r#"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|enrollment[_-]?key)(\s*[=:]\s*)([^\s,;]+|\"[^\"]*\"|'[^']*')"#,
                    )
                    .expect("regex secret"),
                    "$1$2[REDACTED]",
                ),
                (
                    Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
                        .expect("regex private key"),
                    "[REDACTED_PRIVATE_KEY]",
                ),
            ]
        })
        .as_slice()
}

pub fn redact_sensitive(input: &str) -> String {
    patterns()
        .iter()
        .fold(input.to_string(), |value, (pattern, replacement)| {
            pattern.replace_all(&value, *replacement).into_owned()
        })
}

pub fn redact_json_sensitive(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                let normalized = key.to_ascii_lowercase();
                if [
                    "password",
                    "passwd",
                    "secret",
                    "token",
                    "api_key",
                    "apikey",
                    "private_key",
                ]
                .iter()
                .any(|needle| normalized.contains(needle))
                {
                    *value = serde_json::Value::String("[REDACTED]".to_string());
                } else {
                    redact_json_sensitive(value);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                redact_json_sensitive(value);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{redact_json_sensitive, redact_sensitive};

    #[test]
    fn redacta_credenciales_antes_del_journal() {
        let raw = "Authorization: Bearer secreto token=abc123 password: \"hola\" eyJaaaaaaaa.bbbbbbbb.cccccccc";
        let redacted = redact_sensitive(raw);
        assert!(!redacted.contains("secreto"));
        assert!(!redacted.contains("abc123"));
        assert!(!redacted.contains("hola"));
        assert!(!redacted.contains("eyJaaaaaaaa"));
    }

    #[test]
    fn redacta_json_recursivo_sin_romper_su_forma() {
        let mut value = serde_json::json!({
            "publicEndpoint": "https://node",
            "nested": { "accessToken": "secreto" }
        });
        redact_json_sensitive(&mut value);
        assert_eq!(value["publicEndpoint"], "https://node");
        assert_eq!(value["nested"]["accessToken"], "[REDACTED]");
    }
}
