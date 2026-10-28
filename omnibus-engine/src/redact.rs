//! Strips secrets from text that is about to be stored or logged.
//!
//! Provider errors from the HTTP client include the request URL, and ComicVine (and some indexers) take the API key
//! as a query parameter, so a failed call used to write the key into the JobLog table, which the admin UI shows and
//! every backup carries. Every JobLog message passes through `secrets`.

use regex::Regex;
use std::sync::OnceLock;

fn pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(api_?key|apikey|token|access_token|password|passwd|secret|auth)=([^&\s\)\]\x22']+)")
            .expect("valid redaction pattern")
    })
}

/// `text` with the value of every `key=value` pair whose name looks like a credential replaced by `<redacted>`.
pub fn secrets(text: &str) -> String {
    pattern().replace_all(text, "$1=<redacted>").into_owned()
}

#[cfg(test)]
mod tests {
    use super::secrets;

    #[test]
    fn comicvine_url_key_is_removed() {
        let msg = "Discover sync failed: reqwest::Error { kind: Status(502), url: \"https://comicvine.gamespot.com/api/issues/?api_key=0123456789abcdef&format=json\" }";
        let out = secrets(msg);
        assert!(!out.contains("0123456789abcdef"));
        assert!(out.contains("api_key=<redacted>&format=json"));
    }

    #[test]
    fn other_credential_names_and_plain_text() {
        assert_eq!(secrets("apikey=abc token=def x=1"), "apikey=<redacted> token=<redacted> x=1");
        assert_eq!(secrets("(https://x/?apiKey=SECRET)"), "(https://x/?apiKey=<redacted>)");
        assert_eq!(secrets("Successfully synced 39 issues"), "Successfully synced 39 issues");
    }
}
