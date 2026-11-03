//! The one token syntax of format v2 (spec 214 *Tokens*).
//!
//! `${name}` is replaced by a value and `${name:-text}` by the value or `text` when it is
//! unset; `$$` is a literal `$`, which makes `$${name}` a literal `${name}`. Any other `$`
//! is itself. A default runs to the first `}` and is taken as written: it holds no
//! tokens and no escapes.
//!
//! The same syntax is resolved in two passes — build time by `orc build`, run time by the
//! runtime — so this module only parses and substitutes; which names a pass fills is the
//! caller's business.

use std::collections::BTreeMap;

/// One piece of a parsed string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Piece<'a> {
    /// Text copied through. `raw` is the source as written (an escape is still `$$`),
    /// `text` what it reads as once unescaped.
    Text { raw: &'a str, text: &'a str },
    /// A `${…}` token.
    Token(Token<'a>),
}

/// A `${name}` or `${name:-default}` token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token<'a> {
    /// The token as written, `${` to `}`.
    pub raw: &'a str,
    pub name: &'a str,
    /// The text after `:-`, when the token carries a default. `Some("")` for `${name:-}`.
    pub default: Option<&'a str>,
}

/// Why a string is not valid token syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// A `${` with no `}` after it.
    Unclosed { at: String },
    /// `${}` or `${:-x}`.
    EmptyName { token: String },
    /// A name holding anything but ASCII letters, digits and `_`.
    BadName { token: String },
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unclosed { at } => write!(formatter, "`{at}` opens a token that is never closed"),
            Self::EmptyName { token } => write!(formatter, "`{token}` names nothing"),
            Self::BadName { token } => write!(
                formatter,
                "`{token}` is not a token name: names are ASCII letters, digits and `_`"
            ),
        }
    }
}

impl std::error::Error for TokenError {}

/// Whether `name` is a valid token name.
#[must_use]
pub fn is_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Splits a string into text and tokens.
///
/// # Errors
///
/// An unclosed `${`, an empty name, or a name outside the token alphabet.
pub fn parse(input: &str) -> Result<Vec<Piece<'_>>, TokenError> {
    let mut pieces = Vec::new();
    let bytes = input.as_bytes();
    let mut text_start = 0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'$' {
            index += 1;
            continue;
        }
        match bytes.get(index + 1) {
            Some(b'$') => {
                push_text(&mut pieces, &input[text_start..index]);
                pieces.push(Piece::Text {
                    raw: &input[index..index + 2],
                    text: &input[index + 1..index + 2],
                });
                index += 2;
                text_start = index;
            }
            Some(b'{') => {
                push_text(&mut pieces, &input[text_start..index]);
                let Some(close) = input[index + 2..].find('}') else {
                    return Err(TokenError::Unclosed {
                        at: input[index..].to_owned(),
                    });
                };
                let end = index + 2 + close;
                let raw = &input[index..=end];
                let inner = &input[index + 2..end];
                let (name, default) = match inner.split_once(":-") {
                    Some((name, default)) => (name, Some(default)),
                    None => (inner, None),
                };
                if name.is_empty() {
                    return Err(TokenError::EmptyName {
                        token: raw.to_owned(),
                    });
                }
                if !is_name(name) {
                    return Err(TokenError::BadName {
                        token: raw.to_owned(),
                    });
                }
                pieces.push(Piece::Token(Token { raw, name, default }));
                index = end + 1;
                text_start = index;
            }
            _ => index += 1,
        }
    }
    push_text(&mut pieces, &input[text_start..]);
    Ok(pieces)
}

fn push_text<'a>(pieces: &mut Vec<Piece<'a>>, text: &'a str) {
    if !text.is_empty() {
        pieces.push(Piece::Text { raw: text, text });
    }
}

/// The tokens a string names, in order.
///
/// # Errors
///
/// As [`parse`].
pub fn tokens(input: &str) -> Result<Vec<Token<'_>>, TokenError> {
    Ok(parse(input)?
        .into_iter()
        .filter_map(|piece| match piece {
            Piece::Token(token) => Some(token),
            Piece::Text { .. } => None,
        })
        .collect())
}

/// Writes `value` so that a later pass reads it back as exactly `value`: every `$`
/// doubled. Used when a build-time value lands in a field the runtime resolves again.
#[must_use]
pub fn escape(value: &str) -> String {
    value.replace('$', "$$")
}

/// Resolves one element: every token by `lookup`, every escape to what it stands for.
///
/// `Ok(None)` when the element names a value that is unset and carries no default — the
/// element is dropped whole, never sent with a hole in it. A value is inserted as is;
/// nothing it holds is read as a token, split, or joined to a neighbour.
///
/// # Errors
///
/// As [`parse`].
pub fn substitute<'v>(
    element: &str,
    lookup: impl Fn(&str) -> Option<&'v str>,
) -> Result<Option<String>, TokenError> {
    let mut out = String::with_capacity(element.len());
    for piece in parse(element)? {
        match piece {
            Piece::Text { text, .. } => out.push_str(text),
            Piece::Token(token) => match lookup(token.name).or(token.default) {
                Some(value) => out.push_str(value),
                None => return Ok(None),
            },
        }
    }
    Ok(Some(out))
}

/// Resolves an argv list against `values`: each element becomes exactly one argument or,
/// when it names an unset value with no default, none at all.
///
/// # Errors
///
/// The first element whose syntax is invalid, as [`parse`].
pub fn substitute_argv(
    argv: &[String],
    values: &BTreeMap<String, String>,
) -> Result<Vec<Option<String>>, TokenError> {
    argv.iter()
        .map(|element| substitute(element, |name| values.get(name).map(String::as_str)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn resolve(element: &str, pairs: &[(&str, &str)]) -> Option<String> {
        let values = values(pairs);
        substitute(element, |name| values.get(name).map(String::as_str)).expect("valid syntax")
    }

    #[test]
    fn a_token_is_replaced_by_its_value() {
        assert_eq!(
            resolve("--url=${url}", &[("url", "https://x")]).as_deref(),
            Some("--url=https://x")
        );
        assert_eq!(
            resolve("${a}-${b}", &[("a", "1"), ("b", "2")]).as_deref(),
            Some("1-2")
        );
    }

    #[test]
    fn a_default_stands_in_for_an_unset_value_only() {
        assert_eq!(
            resolve("--pool=${pool:-main}", &[]).as_deref(),
            Some("--pool=main")
        );
        assert_eq!(
            resolve("--pool=${pool:-main}", &[("pool", "ci")]).as_deref(),
            Some("--pool=ci")
        );
        // `${name:-}` is the empty string, not a dropped element.
        assert_eq!(resolve("--pool=${pool:-}", &[]).as_deref(), Some("--pool="));
        // A set but empty value is a value; the default does not replace it.
        assert_eq!(
            resolve("${pool:-main}", &[("pool", "")]).as_deref(),
            Some("")
        );
    }

    #[test]
    fn an_element_naming_an_unset_value_is_dropped_whole() {
        assert_eq!(resolve("--pool=${pool}", &[]), None);
        assert_eq!(resolve("--name=${a}-${b}", &[("a", "x")]), None);
        assert_eq!(resolve("--name=${a}-${b}", &[("b", "y")]), None);
        let argv = [
            "./run".to_owned(),
            "--pool=${pool}".to_owned(),
            "--x".to_owned(),
        ];
        assert_eq!(
            substitute_argv(&argv, &BTreeMap::new()).expect("syntax"),
            [Some("./run".to_owned()), None, Some("--x".to_owned())]
        );
    }

    #[test]
    fn dollar_dollar_is_a_literal_dollar() {
        assert_eq!(
            resolve("$${url}", &[("url", "x")]).as_deref(),
            Some("${url}")
        );
        assert_eq!(resolve("cost: $$5", &[]).as_deref(), Some("cost: $5"));
        assert_eq!(resolve("$$$$", &[]).as_deref(), Some("$$"));
        // `$$` then a token: the escape is consumed first, the token still resolves.
        assert_eq!(resolve("$$${a}", &[("a", "1")]).as_deref(), Some("$1"));
        // A lone `$` is itself: PowerShell's `$env:X` passes through.
        assert_eq!(resolve("$env:PATH", &[]).as_deref(), Some("$env:PATH"));
        assert_eq!(resolve("a$", &[]).as_deref(), Some("a$"));
    }

    #[test]
    fn substitution_never_splits_or_joins_elements() {
        let argv = ["--a=${a}".to_owned(), "${b}".to_owned()];
        let values = values(&[("a", "x y  z"), ("b", "\"q\" --c=1\n")]);
        assert_eq!(
            substitute_argv(&argv, &values).expect("syntax"),
            [
                Some("--a=x y  z".to_owned()),
                Some("\"q\" --c=1\n".to_owned())
            ]
        );
    }

    #[test]
    fn a_value_is_never_read_as_a_token() {
        assert_eq!(
            resolve("${a}", &[("a", "${b}"), ("b", "no")]).as_deref(),
            Some("${b}")
        );
        assert_eq!(resolve("${a}", &[("a", "$$")]).as_deref(), Some("$$"));
    }

    #[test]
    fn escape_round_trips_through_substitution() {
        for value in ["plain", "a$b", "${x}", "$$", "$"] {
            assert_eq!(
                resolve(&escape(value), &[("x", "no")]).as_deref(),
                Some(value)
            );
        }
    }

    #[test]
    fn malformed_tokens_are_refused() {
        assert!(matches!(parse("--a=${a"), Err(TokenError::Unclosed { .. })));
        assert!(matches!(parse("${}"), Err(TokenError::EmptyName { .. })));
        assert!(matches!(parse("${:-x}"), Err(TokenError::EmptyName { .. })));
        assert!(matches!(parse("${a-b}"), Err(TokenError::BadName { .. })));
        assert!(matches!(parse("${a b}"), Err(TokenError::BadName { .. })));
        // Braces alone are text in v2.
        assert_eq!(resolve("{os}", &[]).as_deref(), Some("{os}"));
    }

    #[test]
    fn tokens_lists_names_and_defaults() {
        let found = tokens("${a}x${b:-1}$${c}").expect("syntax");
        assert_eq!(
            found
                .iter()
                .map(|token| (token.name, token.default))
                .collect::<Vec<_>>(),
            [("a", None), ("b", Some("1"))]
        );
    }
}
