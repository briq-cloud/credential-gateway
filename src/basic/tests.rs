use super::*;
use crate::rewrite::{Replacer, Stream};

fn secret() -> Secret {
    Secret {
        name: "TOKEN".into(),
        placeholder: "opaque_placeholder".into(),
        value: "p:é~??/tail".into(),
        hosts: vec!["localhost".into()],
        locations: vec!["header".into()],
    }
}
fn headers(bytes: &[u8]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_bytes(bytes).unwrap(),
    );
    headers
}
fn basic(pair: &[u8]) -> HeaderMap {
    headers(format!("Basic {}", STANDARD.encode(pair)).as_bytes())
}
fn parsed(pair: &[u8]) -> Parsed {
    match parse(&basic(pair), &Budget::new(16 * 1024 * 1024)) {
        Ok(Some(parsed)) => parsed,
        _ => panic!("valid fixture failed"),
    }
}
fn selected(parsed: &Parsed, secrets: &[Secret]) -> Result<(Option<usize>, usize), Refusal> {
    let mut selection = parsed.selection();
    for (index, secret) in secrets.iter().enumerate() {
        parsed.inspect(&mut selection, index, secret);
    }
    parsed.finish(selection)
}

#[test]
fn canonical_input_bounds_and_fixed_error_classifications() {
    let budget = Budget::new(16 * 1024 * 1024);
    for input in [
        "Basic",
        "Basic ",
        "Basic  dTpw",
        "Basic\tdTpw",
        "Basic dTpw ",
        "Basic dTpw, Bearer x",
        "Basic dTpw=",
        "Basic dTpw==",
        "Basic dTpw\t",
        "Basic dTo_",
        "Basic dTo-",
        "Basic dTo",
        "Basic dTp=",
        "Basic dQ==",
    ] {
        assert!(
            parse(&headers(input.as_bytes()), &budget).is_err(),
            "accepted malformed fixture"
        );
        assert_eq!(budget.used(), 0);
    }
    let too_large = format!("Basic {}", "A".repeat(TOKEN_LIMIT + 1));
    assert!(matches!(
        parse(&headers(too_large.as_bytes()), &budget),
        Err(Refusal::TooLarge)
    ));
    for pair in [
        b":password".to_vec(),
        b"user name:password".to_vec(),
        b"u\n:password".to_vec(),
        b"u:p\x00".to_vec(),
        [vec![b'u'; USER_LIMIT + 1], b":p".to_vec()].concat(),
    ] {
        assert!(parse(&basic(&pair), &budget).is_err());
    }
    let ordinary = headers(b"bAsIc dTpw");
    assert!(matches!(parse(&ordinary, &budget), Ok(Some(_))));
    for reason in [
        Refusal::Invalid,
        Refusal::Unsupported,
        Refusal::TooLarge,
        Refusal::Capacity,
    ] {
        assert!(!reason.message().contains("user"));
        assert!(!reason.message().contains("password"));
    }
}

#[test]
fn duplicate_fields_and_connection_nomination_are_unambiguous_refusals() {
    let budget = Budget::new(16 * 1024 * 1024);
    for first in ["Basic dTpw", "Bearer unrelated"] {
        let mut fields = headers(first.as_bytes());
        fields.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic dTpw"),
        );
        assert!(parse(&fields, &budget).is_err());
    }
    let mut fields = basic(b"u:p");
    fields.append(
        header::CONNECTION,
        HeaderValue::from_static("keep-alive, AUTHORIZATION"),
    );
    assert!(parse(&fields, &budget).is_err());
    assert_eq!(budget.used(), 0);
}

#[test]
fn public_username_exact_password_and_one_definition_only() {
    let secret = secret();
    for pair in [
        "opaque_placeholder:p",
        "u:prefix-opaque_placeholder",
        "u:opaque_placeholder-suffix",
        "opaque_placeholder:opaque_placeholder",
        "u:opaque_placeholder:opaque_placeholder",
    ] {
        let parsed = parsed(pair.as_bytes());
        assert!(matches!(
            selected(&parsed, std::slice::from_ref(&secret)),
            Err(Refusal::Unsupported)
        ));
    }
    let parsed = parsed(b"u:opaque_placeholder");
    assert!(matches!(
        selected(&parsed, &[secret.clone(), secret.clone()]),
        Err(Refusal::Unsupported)
    ));
    for value in ["", "secret\n", "secret\x7f", &"x".repeat(PAIR_LIMIT)] {
        let mut bad = secret.clone();
        bad.value = value.into();
        assert!(selected(&parsed, &[bad]).is_err());
    }
    let mut no_header = secret.clone();
    no_header.locations = vec!["body".into()];
    assert!(matches!(selected(&parsed, &[no_header]), Ok((None, 0))));
    assert!(matches!(selected(&parsed, &[]), Ok((None, 0))));
    assert!(matches!(selected(&parsed, &[secret]), Ok((Some(0), _))));
}

#[test]
fn four_finite_aliases_share_one_longest_match_streamer_at_every_boundary() {
    let secret = secret();
    for username in ["a", "ab", "abc"] {
        let old = format!("{username}:{}", secret.placeholder);
        let new = format!("{username}:{}", secret.value);
        let parsed = parsed(old.as_bytes());
        assert!(selected(&parsed, std::slice::from_ref(&secret)).is_ok());
        let replacement = parsed
            .replacement(&secret)
            .unwrap_or_else(|_| panic!("valid shape"));
        assert_eq!(
            replacement.value.as_bytes(),
            format!("Basic {}", STANDARD.encode(&new)).as_bytes()
        );
        assert!(replacement.aliases.len() <= 4);
        let raw = (
            secret.value.as_bytes().to_vec(),
            secret.placeholder.as_bytes().to_vec(),
        );
        let mut pairs = replacement.aliases.clone();
        pairs.push(raw);
        // A shorter raw secret-like literal inside an encoded alias must not corrupt it.
        pairs.push((replacement.aliases[0].0[..2].to_vec(), b"short".to_vec()));
        let matcher = Arc::new(Replacer::new(&pairs).unwrap().unwrap());
        for (from, to) in &replacement.aliases {
            let input = [b"{\"auth\":\"".as_slice(), from, b"\"}"].concat();
            let expected = [b"{\"auth\":\"".as_slice(), to, b"\"}"].concat();
            for at in 0..=input.len() {
                let mut stream = Stream::new(matcher.clone());
                let mut output = stream.push(&input[..at]);
                output.extend(stream.push(&input[at..]));
                output.extend(stream.finish());
                assert_eq!(output, expected, "alias boundary {at}");
            }
        }
    }
}

#[test]
fn parser_scratch_and_alias_estimates_fail_closed_and_release_last_owner() {
    let request = basic(b"u:opaque_placeholder");
    let too_small = Budget::new(SCRATCH - 1);
    assert!(matches!(
        parse(&request, &too_small),
        Err(Refusal::Capacity)
    ));
    assert_eq!(too_small.used(), 0);
    let budget = Budget::new(SCRATCH);
    let parsed = parse(&request, &budget).ok().flatten().unwrap();
    assert_eq!(budget.used(), SCRATCH);
    assert!(matches!(parse(&request, &budget), Err(Refusal::Capacity)));
    drop(parsed);
    assert_eq!(budget.used(), 0);
    assert!(crate::budget::basic_aliases(usize::MAX, 1).is_none());
    assert!(crate::budget::basic_aliases(1, usize::MAX).is_none());
    assert!(crate::budget::basic_aliases(PAIR_LIMIT, PAIR_LIMIT).unwrap() > 4 * TOKEN_LIMIT * 128);
}
