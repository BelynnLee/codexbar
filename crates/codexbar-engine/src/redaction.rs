use regex::Regex;
use std::sync::OnceLock;

const MASK: &str = "<redacted>";

pub fn redact(value: &str) -> String {
    let mut spans = Vec::new();
    collect_assignment_spans(value, &mut spans);
    collect_auth_scheme_spans(value, &mut spans);
    collect_query_spans(value, &mut spans);
    let precise_spans = spans.clone();
    collect_generic_pattern_spans(&generic_patterns().jwt, value, &precise_spans, &mut spans);
    collect_generic_pattern_spans(
        &generic_patterns().api_key,
        value,
        &precise_spans,
        &mut spans,
    );
    collect_generic_pattern_spans(&generic_patterns().email, value, &precise_spans, &mut spans);
    render_redacted(value, spans)
}

#[derive(Debug, Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
}

impl Span {
    const fn new(start: usize, end: usize) -> Option<Self> {
        if start < end {
            Some(Self { start, end })
        } else {
            None
        }
    }
}

struct GenericPatterns {
    jwt: Regex,
    api_key: Regex,
    email: Regex,
}

fn generic_patterns() -> &'static GenericPatterns {
    static PATTERNS: OnceLock<GenericPatterns> = OnceLock::new();
    PATTERNS.get_or_init(|| GenericPatterns {
        jwt: Regex::new(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
            .expect("valid JWT redaction regex"),
        api_key: Regex::new(r"\bsk-[A-Za-z0-9_-]{6,}\b").expect("valid API key redaction regex"),
        email: Regex::new(
            r"\b[A-Za-z0-9.!#$%&'*+/=?^_\x60{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b",
        )
        .expect("valid email redaction regex"),
    })
}

fn collect_generic_pattern_spans(
    pattern: &Regex,
    value: &str,
    precise_spans: &[Span],
    spans: &mut Vec<Span>,
) {
    spans.extend(pattern.find_iter(value).filter_map(|matched| {
        let candidate = Span {
            start: matched.start(),
            end: matched.end(),
        };
        (!precise_spans
            .iter()
            .any(|precise| spans_overlap(candidate, *precise)))
        .then_some(candidate)
    }));
}

const fn spans_overlap(left: Span, right: Span) -> bool {
    left.start < right.end && right.start < left.end
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretKind {
    Header,
    Named,
    Email,
}

struct ParsedKey {
    normalized: String,
    after: usize,
    quoted: bool,
}

fn collect_assignment_spans(value: &str, spans: &mut Vec<Span>) {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let Some(key) = parse_key_at(value, index) else {
            index += 1;
            continue;
        };
        let key_start = index;
        index = key.after.max(index + 1);
        let mut cursor = skip_horizontal(bytes, key.after);
        if !matches!(bytes.get(cursor), Some(b':' | b'=')) {
            continue;
        }
        cursor += 1;
        cursor = skip_horizontal(bytes, cursor);

        let Some(kind) = classify_normalized_key(&key.normalized) else {
            continue;
        };
        if let Some(span) = parse_assignment_value(value, cursor, key_start, key.quoted, kind) {
            spans.push(span);
        }
    }
}

fn parse_assignment_value(
    value: &str,
    start: usize,
    key_start: usize,
    key_quoted: bool,
    kind: SecretKind,
) -> Option<Span> {
    let bytes = value.as_bytes();
    if let Some(quoted) = parse_quoted(bytes, start) {
        return Span::new(quoted.content_start, quoted.content_end);
    }
    if start >= bytes.len() || matches!(bytes[start], b'\r' | b'\n' | b',' | b'&') {
        return None;
    }

    let line_header =
        kind == SecretKind::Header && !key_quoted && starts_header_line(bytes, key_start);
    let mut end = if line_header {
        find_header_value_end(value, start)
    } else {
        find_structured_value_end(value, start)
    };
    while end > start && is_horizontal(bytes[end - 1]) {
        end -= 1;
    }
    Span::new(start, end)
}

fn collect_auth_scheme_spans(value: &str, spans: &mut Vec<Span>) {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let scheme_len = if matches_ascii_word(bytes, index, b"bearer") {
            6
        } else if matches_ascii_word(bytes, index, b"basic") {
            5
        } else {
            index += 1;
            continue;
        };
        let after_scheme = index + scheme_len;
        let value_start = skip_horizontal(bytes, after_scheme);
        if value_start == after_scheme {
            index += scheme_len;
            continue;
        }
        if let Some(quoted) = parse_quoted(bytes, value_start) {
            if let Some(span) = Span::new(quoted.content_start, quoted.content_end) {
                spans.push(span);
            }
            index = quoted.after;
            continue;
        }
        if let Some(content_start) = quoted_content_start(bytes, value_start) {
            let line_end = find_line_end(bytes, content_start);
            if let Some(span) = Span::new(content_start, line_end) {
                spans.push(span);
            }
            index = line_end.max(index + scheme_len);
            continue;
        }

        let mut end = value_start;
        while end < bytes.len()
            && !matches!(
                bytes[end],
                b' ' | b'\t'
                    | b'\r'
                    | b'\n'
                    | b','
                    | b';'
                    | b'}'
                    | b']'
                    | b'&'
                    | b'"'
                    | b'\''
                    | b'\\'
            )
        {
            end += 1;
        }
        if let Some(span) = Span::new(value_start, end) {
            spans.push(span);
        }
        index = end.max(index + scheme_len);
    }
}

fn collect_query_spans(value: &str, spans: &mut Vec<Span>) {
    let bytes = value.as_bytes();
    let mut search = 0;
    while let Some(relative) = bytes[search..].iter().position(|byte| *byte == b'?') {
        let mut cursor = search + relative + 1;
        while cursor < bytes.len() && !is_query_end(bytes[cursor]) {
            let key_start = cursor;
            while cursor < bytes.len()
                && !matches!(bytes[cursor], b'=' | b'&')
                && !is_query_end(bytes[cursor])
            {
                cursor += 1;
            }
            if bytes.get(cursor) != Some(&b'=') {
                if bytes.get(cursor) == Some(&b'&') {
                    cursor += 1;
                    continue;
                }
                break;
            }

            let key = &value[key_start..cursor];
            cursor += 1;
            let value_start = cursor;
            while cursor < bytes.len() && bytes[cursor] != b'&' && !is_query_end(bytes[cursor]) {
                cursor += 1;
            }
            let decoded_value = percent_decode(&value[value_start..cursor]);
            if (classify_key(key).is_some() || looks_sensitive_value(&decoded_value))
                && value_start < cursor
            {
                spans.push(Span {
                    start: value_start,
                    end: cursor,
                });
            }
            if bytes.get(cursor) == Some(&b'&') {
                cursor += 1;
            }
        }
        search = cursor.max(search + relative + 1);
    }
}

fn looks_sensitive_value(value: &str) -> bool {
    let patterns = generic_patterns();
    patterns.email.is_match(value)
        || patterns.jwt.is_match(value)
        || patterns.api_key.is_match(value)
        || contains_auth_scheme(value)
}

fn contains_auth_scheme(value: &str) -> bool {
    let mut spans = Vec::new();
    collect_auth_scheme_spans(value, &mut spans);
    !spans.is_empty()
}

fn render_redacted(value: &str, mut spans: Vec<Span>) -> String {
    if spans.is_empty() {
        return value.to_owned();
    }
    spans.sort_unstable_by_key(|span| (span.start, span.end));
    let mut merged: Vec<Span> = Vec::with_capacity(spans.len());
    for span in spans {
        if let Some(previous) = merged.last_mut() {
            if span.start <= previous.end {
                previous.end = previous.end.max(span.end);
                continue;
            }
        }
        merged.push(span);
    }

    let mut output = String::with_capacity(value.len());
    let mut cursor = 0;
    for span in merged {
        output.push_str(&value[cursor..span.start]);
        output.push_str(MASK);
        cursor = span.end;
    }
    output.push_str(&value[cursor..]);
    output
}

#[derive(Debug, Clone, Copy)]
struct QuotedValue {
    content_start: usize,
    content_end: usize,
    after: usize,
}

fn parse_quoted(bytes: &[u8], start: usize) -> Option<QuotedValue> {
    match bytes.get(start) {
        Some(quote @ (b'"' | b'\'')) => parse_direct_quoted(bytes, start, *quote),
        Some(b'\\') => {
            let quote = *bytes.get(start + 1)?;
            if !matches!(quote, b'"' | b'\'') {
                return None;
            }
            parse_backslash_quoted(bytes, start, quote)
        }
        _ => None,
    }
}

fn quoted_content_start(bytes: &[u8], start: usize) -> Option<usize> {
    match bytes.get(start) {
        Some(b'"' | b'\'') => Some(start + 1),
        Some(b'\\') if matches!(bytes.get(start + 1), Some(b'"' | b'\'')) => Some(start + 2),
        _ => None,
    }
}

fn parse_direct_quoted(bytes: &[u8], start: usize, quote: u8) -> Option<QuotedValue> {
    let mut cursor = start + 1;
    while cursor < bytes.len() {
        if matches!(bytes[cursor], b'\r' | b'\n') {
            return None;
        }
        if bytes[cursor] == quote && !is_backslash_escaped(bytes, cursor) {
            return Some(QuotedValue {
                content_start: start + 1,
                content_end: cursor,
                after: cursor + 1,
            });
        }
        cursor += 1;
    }
    None
}

fn parse_backslash_quoted(bytes: &[u8], start: usize, quote: u8) -> Option<QuotedValue> {
    let mut cursor = start + 2;
    while cursor + 1 < bytes.len() {
        if matches!(bytes[cursor], b'\r' | b'\n') {
            return None;
        }
        if bytes[cursor] == b'\\' && bytes[cursor + 1] == quote {
            let preceding = preceding_backslashes(bytes, cursor + 1);
            if preceding == 1 {
                return Some(QuotedValue {
                    content_start: start + 2,
                    content_end: cursor,
                    after: cursor + 2,
                });
            }
        }
        cursor += 1;
    }
    None
}

fn is_backslash_escaped(bytes: &[u8], index: usize) -> bool {
    preceding_backslashes(bytes, index) % 2 == 1
}

fn preceding_backslashes(bytes: &[u8], index: usize) -> usize {
    let mut count = 0;
    let mut cursor = index;
    while cursor > 0 && bytes[cursor - 1] == b'\\' {
        count += 1;
        cursor -= 1;
    }
    count
}

fn parse_key_at(value: &str, start: usize) -> Option<ParsedKey> {
    let bytes = value.as_bytes();
    if start > 0 && is_key_byte(bytes[start - 1]) {
        return None;
    }
    if let Some(quoted) = parse_quoted(bytes, start) {
        return Some(ParsedKey {
            normalized: normalize_key(&value[quoted.content_start..quoted.content_end]),
            after: quoted.after,
            quoted: true,
        });
    }
    if !bytes.get(start).is_some_and(|byte| is_key_byte(*byte)) {
        return None;
    }
    let mut end = start;
    while end < bytes.len() && is_key_byte(bytes[end]) {
        end += 1;
    }
    Some(ParsedKey {
        normalized: normalize_key(&value[start..end]),
        after: end,
        quoted: false,
    })
}

fn normalize_key(value: &str) -> String {
    let mut unescaped = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\\'
            && characters
                .peek()
                .is_some_and(|next| matches!(next, '"' | '\'' | '\\'))
        {
            if let Some(next) = characters.next() {
                unescaped.push(next);
            }
        } else {
            unescaped.push(character);
        }
    }
    percent_decode(&unescaped).to_ascii_lowercase()
}

fn classify_key(value: &str) -> Option<SecretKind> {
    let normalized = normalize_key(value);
    classify_normalized_key(&normalized)
}

fn classify_normalized_key(normalized: &str) -> Option<SecretKind> {
    if matches!(
        normalized,
        "authorization"
            | "proxy-authorization"
            | "proxy_authorization"
            | "x-api-key"
            | "x_api_key"
            | "api-key"
            | "cookie"
            | "set-cookie"
    ) {
        return Some(SecretKind::Header);
    }
    if matches!(normalized, "email" | "e-mail" | "mail") {
        return Some(SecretKind::Email);
    }
    if matches!(
        normalized,
        "token"
            | "apikey"
            | "api_key"
            | "access_token"
            | "refresh_token"
            | "id_token"
            | "auth_token"
            | "bearer_token"
            | "password"
            | "client_secret"
            | "secret"
            | "sid"
            | "session"
            | "sessionid"
            | "session_id"
            | "session_token"
            | "auth"
            | "__host-auth"
    ) || [
        "_api_key", "-api-key", "_token", "-token", "_secret", "-secret",
    ]
    .iter()
    .any(|suffix| normalized.ends_with(suffix))
    {
        return Some(SecretKind::Named);
    }
    None
}

fn find_structured_value_end(value: &str, start: usize) -> usize {
    let bytes = value.as_bytes();
    let mut cursor = start;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\r' | b'\n' | b',' | b'&' | b'#' => return cursor,
            b';' if looks_like_assignment(value, skip_horizontal(bytes, cursor + 1)) => {
                return cursor;
            }
            b' ' | b'\t' => {
                let next = skip_horizontal(bytes, cursor);
                if looks_like_assignment(value, next) {
                    return cursor;
                }
                cursor = next;
                continue;
            }
            b'}' | b']' | b')' if is_structural_closing(bytes, cursor) => return cursor,
            _ => cursor += 1,
        }
    }
    cursor
}

fn looks_like_assignment(value: &str, start: usize) -> bool {
    let Some(key) = parse_key_at(value, start) else {
        return false;
    };
    let cursor = skip_horizontal(value.as_bytes(), key.after);
    matches!(value.as_bytes().get(cursor), Some(b':' | b'='))
}

fn starts_header_line(bytes: &[u8], key_start: usize) -> bool {
    let line_start = bytes[..key_start]
        .iter()
        .rposition(|byte| matches!(byte, b'\r' | b'\n'))
        .map_or(0, |index| index + 1);
    bytes[line_start..key_start]
        .iter()
        .all(|byte| is_horizontal(*byte))
}

fn find_line_end(bytes: &[u8], start: usize) -> usize {
    bytes[start..]
        .iter()
        .position(|byte| matches!(byte, b'\r' | b'\n'))
        .map_or(bytes.len(), |relative| start + relative)
}

fn find_header_value_end(value: &str, start: usize) -> usize {
    let bytes = value.as_bytes();
    let line_end = find_line_end(bytes, start);
    let mut cursor = start;
    while cursor < line_end {
        if bytes[cursor] == b','
            && looks_like_colon_field(value, skip_horizontal(bytes, cursor + 1))
        {
            return cursor;
        }
        cursor += 1;
    }
    line_end
}

fn looks_like_colon_field(value: &str, start: usize) -> bool {
    let Some(key) = parse_key_at(value, start) else {
        return false;
    };
    let cursor = skip_horizontal(value.as_bytes(), key.after);
    value.as_bytes().get(cursor) == Some(&b':')
}

fn is_structural_closing(bytes: &[u8], index: usize) -> bool {
    let Some(next) = bytes.get(index + 1) else {
        return true;
    };
    next.is_ascii_whitespace() || matches!(next, b',' | b'}' | b']' | b')')
}

fn matches_ascii_word(bytes: &[u8], start: usize, word: &[u8]) -> bool {
    let end = start.saturating_add(word.len());
    end <= bytes.len()
        && bytes[start..end].eq_ignore_ascii_case(word)
        && (start == 0 || !is_key_byte(bytes[start - 1]))
        && bytes.get(end).is_some_and(|byte| is_horizontal(*byte))
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor] == b'%' && cursor + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[cursor + 1]), hex_value(bytes[cursor + 2]))
            {
                decoded.push((high << 4) | low);
                cursor += 3;
                continue;
            }
        }
        decoded.push(bytes[cursor]);
        cursor += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

const fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

const fn is_key_byte(value: u8) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, b'_' | b'-' | b'%')
}

const fn is_horizontal(value: u8) -> bool {
    matches!(value, b' ' | b'\t')
}

fn skip_horizontal(bytes: &[u8], mut cursor: usize) -> usize {
    while cursor < bytes.len() && is_horizontal(bytes[cursor]) {
        cursor += 1;
    }
    cursor
}

const fn is_query_end(value: u8) -> bool {
    matches!(
        value,
        b' ' | b'\t' | b'\r' | b'\n' | b'#' | b'"' | b'\'' | b'\\' | b'}' | b']'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_redacts_exact(input: &str, expected: &str, secret_segments: &[&str]) {
        let actual = redact(input);
        assert_eq!(actual, expected);
        for segment in secret_segments {
            assert!(
                !actual.contains(segment),
                "redacted output retained secret segment {segment:?}: {actual:?}"
            );
        }
    }

    #[test]
    fn masks_bearer_cookie_jwt_api_key_and_email() {
        let value = "Authorization: Bearer abc.def.ghi\nCookie: sid=secret\nuser@example.com sk-test-secret";

        let redacted = redact(value);

        assert!(!redacted.contains("abc.def.ghi"));
        assert!(!redacted.contains("sid=secret"));
        assert!(!redacted.contains("user@example.com"));
        assert!(!redacted.contains("sk-test-secret"));
    }

    #[test]
    fn masks_standalone_jwt_like_values_before_generic_patterns() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmaXh0dXJlIn0.c2lnbmF0dXJl";

        let redacted = redact(&format!("token payload: {jwt}"));

        assert!(!redacted.contains(jwt));
    }

    #[test]
    fn masks_sensitive_header_values_case_insensitively() {
        let value = "authorization: Basic dXNlcjpwYXNz\nX-Api-Key: secret-value\nSet-Cookie: session=secret; Path=/";

        let redacted = redact(value);

        assert!(!redacted.contains("dXNlcjpwYXNz"));
        assert!(!redacted.contains("secret-value"));
        assert!(!redacted.contains("session=secret"));
        assert!(redacted.contains("authorization:"));
        assert!(redacted.contains("X-Api-Key:"));
    }

    #[test]
    fn masks_sensitive_headers_embedded_in_diagnostic_prefixes() {
        let value =
            "headers={authorization: Basic dXNlcjpwYXNz}\nheaders={Cookie: custom=secret-value}";

        let redacted = redact(value);

        assert!(!redacted.contains("dXNlcjpwYXNz"));
        assert!(!redacted.contains("custom=secret-value"));
        assert!(redacted.contains("headers={authorization:"));
        assert!(redacted.contains("headers={Cookie:"));
    }

    #[test]
    fn masks_sensitive_query_parameters_but_preserves_safe_parameters() {
        let value = concat!(
            "GET https://example.invalid/usage?api_key=secret-key",
            "&access_token=secret-token&token=bare-secret&page=2&mode=summary",
        );

        let redacted = redact(value);

        assert!(!redacted.contains("secret-key"));
        assert!(!redacted.contains("secret-token"));
        assert!(!redacted.contains("bare-secret"));
        assert!(redacted.contains("page=2"));
        assert!(redacted.contains("mode=summary"));
    }

    #[test]
    fn masks_cookie_assignments_outside_a_cookie_header() {
        let value = "request failed with sid=secret-value; theme=dark";

        let redacted = redact(value);

        assert!(!redacted.contains("secret-value"));
        assert!(redacted.contains("theme=dark"));
    }

    #[test]
    fn leaves_legitimate_non_sensitive_diagnostics_unchanged() {
        let value = concat!(
            "Refresh completed for OpenRouter: 42% used; reset in 9 minutes. ",
            "GET /usage?page=2&mode=summary Content-Type: application/json ",
            "api.example.com v1.2.3",
        );

        assert_eq!(redact(value), value);
    }

    #[test]
    fn redaction_never_consumes_a_non_sensitive_following_line() {
        let value = "Authorization:\nRefresh completed\ntoken:\nNo credential supplied";

        let redacted = redact(value);

        assert!(redacted.contains("\nRefresh completed\n"));
        assert!(redacted.contains("\nNo credential supplied"));
    }

    #[test]
    fn masks_double_quoted_json_authorization_value() {
        assert_redacts_exact(
            r#"{"Authorization":"Basic dXNlcjpwYXNz"}"#,
            r#"{"Authorization":"<redacted>"}"#,
            &["dXNl", "cGFz"],
        );
    }

    #[test]
    fn masks_double_quoted_json_api_key_value() {
        assert_redacts_exact(
            r#"{"X-Api-Key":"alpha-secret"}"#,
            r#"{"X-Api-Key":"<redacted>"}"#,
            &["alpha", "secret"],
        );
    }

    #[test]
    fn masks_double_quoted_json_cookie_value() {
        assert_redacts_exact(
            r#"{"Cookie":"custom=alpha-secret"}"#,
            r#"{"Cookie":"<redacted>"}"#,
            &["custom", "alpha", "secret"],
        );
    }

    #[test]
    fn masks_quoted_bearer_and_basic_values() {
        assert_redacts_exact(
            r#"Bearer "alpha.secret" Basic 'beta;omega'"#,
            r#"Bearer "<redacted>" Basic '<redacted>'"#,
            &["alpha", "secret", "beta", "omega"],
        );
    }

    #[test]
    fn masks_percent_encoded_query_keys_values_and_email() {
        assert_redacts_exact(
            "GET /?access%5Ftoken=alpha%2Ebeta&%65mail=user%40example.invalid&page=2",
            "GET /?access%5Ftoken=<redacted>&%65mail=<redacted>&page=2",
            &["alpha", "beta", "user", "example"],
        );
    }

    #[test]
    fn masks_exact_api_key_query_name() {
        assert_redacts_exact(
            "GET /?api_key=secret-key&page=2",
            "GET /?api_key=<redacted>&page=2",
            &["secret"],
        );
    }

    #[test]
    fn detects_percent_encoded_authorization_under_safe_query_keys() {
        assert_redacts_exact(
            "GET /?first=Bearer%20alpha.secret&second=Basic%20beta%3D%3D&mode=summary",
            "GET /?first=<redacted>&second=<redacted>&mode=summary",
            &["alpha", "secret", "beta"],
        );
    }

    #[test]
    fn detects_percent_encoded_email_under_a_safe_query_key() {
        assert_redacts_exact(
            "GET /?contact=user%40example.invalid&mode=summary",
            "GET /?contact=<redacted>&mode=summary",
            &["user", "example"],
        );
    }

    #[test]
    fn percent_decodes_query_keys_only_once_for_classification() {
        let value = "GET /?access%255Ftoken=alpha%2Ebeta&mode=summary";
        assert_eq!(redact(value), value);
    }

    #[test]
    fn masks_complete_escape_aware_single_and_double_quoted_secrets() {
        assert_redacts_exact(
            r#"token='alpha\'omega;tail' password="bravo\"charlie;delta""#,
            r#"token='<redacted>' password="<redacted>""#,
            &["alpha", "omega", "tail", "bravo", "charlie", "delta"],
        );
    }

    #[test]
    fn masks_cookie_value_containing_closing_brace_as_data() {
        assert_redacts_exact(
            "Cookie: custom=alpha}omega",
            "Cookie: <redacted>",
            &["custom", "alpha", "omega"],
        );
    }

    #[test]
    fn bearer_and_basic_never_cross_lf_or_crlf() {
        let value = "Bearer \nRefresh completed\nBasic \r\nStatus safe";
        assert_eq!(redact(value), value);
    }

    #[test]
    fn standalone_double_quoted_bearer_masks_to_lf() {
        assert_redacts_exact(
            "Bearer \"alpha.secret\nRefresh completed\"\nStatus safe",
            "Bearer \"<redacted>\nRefresh completed\"\nStatus safe",
            &["alpha", "secret"],
        );
    }

    #[test]
    fn standalone_single_quoted_basic_masks_to_crlf() {
        assert_redacts_exact(
            "Basic 'beta-secret\r\nRefresh completed'\r\nStatus safe",
            "Basic '<redacted>\r\nRefresh completed'\r\nStatus safe",
            &["beta", "secret"],
        );
    }

    #[test]
    fn standalone_backslash_double_quoted_bearer_masks_to_crlf() {
        let input = concat!(
            r#"Bearer \"gamma.secret"#,
            "\r\n",
            r#"Refresh completed\""#,
            "\r\nStatus safe",
        );
        let expected = concat!(
            r#"Bearer \"<redacted>"#,
            "\r\n",
            r#"Refresh completed\""#,
            "\r\nStatus safe",
        );
        assert_redacts_exact(input, expected, &["gamma", "secret"]);
    }

    #[test]
    fn standalone_backslash_single_quoted_basic_masks_to_lf() {
        let input = concat!(
            r#"Basic \'delta-secret"#,
            "\n",
            r#"Refresh completed\'"#,
            "\nStatus safe",
        );
        let expected = concat!(
            r#"Basic \'<redacted>"#,
            "\n",
            r#"Refresh completed\'"#,
            "\nStatus safe",
        );
        assert_redacts_exact(input, expected, &["delta", "secret"]);
    }

    #[test]
    fn direct_quoted_assignment_stops_before_lf() {
        assert_redacts_exact(
            "token=\"alpha\nRefresh completed\"\nStatus safe",
            "token=<redacted>\nRefresh completed\"\nStatus safe",
            &["alpha"],
        );
    }

    #[test]
    fn direct_quoted_header_stops_before_crlf() {
        assert_redacts_exact(
            "Authorization: \"Basic alpha\r\nRefresh completed\"\r\nStatus safe",
            "Authorization: <redacted>\r\nRefresh completed\"\r\nStatus safe",
            &["Basic", "alpha"],
        );
    }

    #[test]
    fn backslash_quoted_json_assignment_stops_before_lf() {
        let input = concat!(
            r#"{\"token\":\"alpha"#,
            "\n",
            r#"Refresh completed\"}"#,
            "\nStatus safe",
        );
        let expected = concat!(
            r#"{\"token\":<redacted>"#,
            "\n",
            r#"Refresh completed\"}"#,
            "\nStatus safe",
        );
        assert_redacts_exact(input, expected, &["alpha"]);
    }

    #[test]
    fn masks_only_sensitive_values_in_one_diagnostic_map() {
        let input = concat!(
            "headers={Authorization: Basic alpha, Content-Type: application/json, ",
            "X-Api-Key: beta, Empty-Token: \"\", Cookie: custom=gamma}",
        );
        let expected = concat!(
            "headers={Authorization: <redacted>, Content-Type: application/json, ",
            "X-Api-Key: <redacted>, Empty-Token: \"\", Cookie: <redacted>}",
        );
        assert_redacts_exact(input, expected, &["alpha", "beta", "custom", "gamma"]);
    }

    #[test]
    fn masks_only_sensitive_values_on_an_unwrapped_header_line() {
        let input = concat!(
            "Authorization: Basic alpha, Content-Type: application/json, ",
            "X-Api-Key: beta",
        );
        let expected = concat!(
            "Authorization: <redacted>, Content-Type: application/json, ",
            "X-Api-Key: <redacted>",
        );
        assert_redacts_exact(input, expected, &["alpha", "beta"]);
    }

    #[test]
    fn precise_assignment_span_preserves_key_before_raw_email() {
        assert_redacts_exact(
            "token=user@example.invalid next=完成",
            "token=<redacted> next=完成",
            &["user", "example"],
        );
    }

    #[test]
    fn precise_query_span_preserves_safe_key_and_utf8_context_before_raw_email() {
        assert_redacts_exact(
            "诊断 GET /?contact=user@example.invalid&mode=完成",
            "诊断 GET /?contact=<redacted>&mode=完成",
            &["user", "example"],
        );
    }

    #[test]
    fn standalone_email_keeps_equals_in_legal_local_part_redactable() {
        assert_redacts_exact(
            "owner foo=bar@example.invalid safe",
            "owner <redacted> safe",
            &["foo", "bar", "example"],
        );
    }

    #[test]
    fn masks_mixed_case_single_quoted_and_escaped_structured_fields() {
        let input = concat!(
            r#"{"aUtHoRiZaTiOn":"Bearer alpha","Content-Type":"application/json","#,
            r#"'x-API-key':'beta','Token':'gamma;omega',"Email":"user@example.invalid"}"#,
        );
        let expected = concat!(
            r#"{"aUtHoRiZaTiOn":"<redacted>","Content-Type":"application/json","#,
            r#"'x-API-key':'<redacted>','Token':'<redacted>',"Email":"<redacted>"}"#,
        );
        assert_redacts_exact(
            input,
            expected,
            &["alpha", "beta", "gamma", "omega", "user", "example"],
        );
    }

    #[test]
    fn masks_backslash_escaped_json_header_values() {
        assert_redacts_exact(
            r#"{\"Authorization\":\"Basic alpha-secret\",\"Content-Type\":\"application/json\"}"#,
            r#"{\"Authorization\":\"<redacted>\",\"Content-Type\":\"application/json\"}"#,
            &["alpha", "secret"],
        );
    }
}
