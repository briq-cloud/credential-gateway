//! Bounded origin Basic authentication. No arbitrary encoded payloads or credential caches.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use http::{HeaderMap, HeaderValue, StatusCode, header};

use crate::budget::{Budget, Reservation};
use crate::config::Secret;

const TOKEN_LIMIT: usize = 8 * 1024;
const PAIR_LIMIT: usize = 6 * 1024;
const USER_LIMIT: usize = 256;
const SCRATCH: usize = 64 * 1024;

/// Only fixed classifications cross the proxy's logging/error boundary.
#[derive(Clone, Copy)]
pub(crate) enum Refusal {
    Invalid,
    Unsupported,
    TooLarge,
    Capacity,
}
impl Refusal {
    pub(crate) fn status(self) -> StatusCode {
        match self {
            Self::TooLarge => StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            Self::Capacity => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::BAD_REQUEST,
        }
    }
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Invalid => "credential gateway: invalid Basic authentication\n",
            Self::Unsupported => "credential gateway: unsupported Basic credential shape\n",
            Self::TooLarge => "credential gateway: Basic authentication exceeds limits\n",
            Self::Capacity => "credential gateway capacity exceeded\n",
        }
    }
}

pub(crate) struct Parsed {
    decoded: Vec<u8>,
    colon: usize,
    _scratch: Arc<Reservation>,
}

pub(crate) fn parse(headers: &HeaderMap, budget: &Arc<Budget>) -> Result<Option<Parsed>, Refusal> {
    let mut fields = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = fields.next() else {
        return Ok(None);
    };
    let basic = |value: &HeaderValue| {
        value
            .as_bytes()
            .split(|b| b.is_ascii_whitespace())
            .next()
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case(b"Basic"))
    };
    if !basic(value) && !headers.get_all(header::AUTHORIZATION).iter().any(basic) {
        return Ok(None);
    }
    if fields.next().is_some() {
        return Err(Refusal::Invalid);
    }
    if headers.get_all(header::CONNECTION).iter().any(|value| {
        value
            .as_bytes()
            .split(|b| *b == b',')
            .any(|field| field.trim_ascii().eq_ignore_ascii_case(b"authorization"))
    }) {
        return Err(Refusal::Invalid);
    }
    let bytes = value.as_bytes();
    if bytes.len() < 7 || !bytes[..5].eq_ignore_ascii_case(b"Basic") || bytes[5] != b' ' {
        return Err(Refusal::Invalid);
    }
    let token = &bytes[6..];
    if token.len() > TOKEN_LIMIT {
        return Err(Refusal::TooLarge);
    }
    let scratch = budget.reserve(SCRATCH).ok_or(Refusal::Capacity)?;
    let decoded = STANDARD.decode(token).map_err(|_| Refusal::Invalid)?;
    if decoded.len() > PAIR_LIMIT {
        return Err(Refusal::TooLarge);
    }
    if STANDARD.encode(&decoded).as_bytes() != token {
        return Err(Refusal::Invalid);
    }
    let colon = decoded
        .iter()
        .position(|b| *b == b':')
        .ok_or(Refusal::Invalid)?;
    if colon == 0
        || colon > USER_LIMIT
        || decoded[..colon].iter().any(|b| !(b'!'..=b'~').contains(b))
        || decoded.iter().any(u8::is_ascii_control)
    {
        return Err(Refusal::Unsupported);
    }
    Ok(Some(Parsed {
        decoded,
        colon,
        _scratch: scratch,
    }))
}

pub(crate) struct Selection {
    index: Option<usize>,
    count: usize,
    invalid: bool,
    pair_len: usize,
}

impl Parsed {
    pub(crate) fn selection(&self) -> Selection {
        Selection {
            index: None,
            count: 0,
            invalid: false,
            pair_len: 0,
        }
    }
    pub(crate) fn inspect(&self, selected: &mut Selection, index: usize, secret: &Secret) {
        if !secret.allows("header") || secret.placeholder.is_empty() {
            return;
        }
        let placeholder = secret.placeholder.as_bytes();
        let contains = |bytes: &[u8]| {
            bytes
                .windows(placeholder.len())
                .any(|part| part == placeholder)
        };
        if contains(&self.decoded[..self.colon]) {
            selected.invalid = true;
        }
        let password = &self.decoded[self.colon + 1..];
        if !contains(password) {
            return;
        }
        selected.count += 1;
        if password != placeholder {
            selected.invalid = true;
            return;
        }
        selected.index = Some(index);
        selected.pair_len = self
            .colon
            .checked_add(1)
            .and_then(|length| length.checked_add(secret.value.len()))
            .unwrap_or(usize::MAX);
        if secret.value.is_empty()
            || secret.value.as_bytes().iter().any(u8::is_ascii_control)
            || selected.pair_len > PAIR_LIMIT
        {
            selected.invalid = true;
        }
    }
    pub(crate) fn finish(&self, selection: Selection) -> Result<(Option<usize>, usize), Refusal> {
        if selection.invalid || selection.count > 1 {
            return Err(Refusal::Unsupported);
        }
        let extra = match selection.index {
            Some(_) => crate::budget::basic_aliases(selection.pair_len, self.decoded.len())
                .ok_or(Refusal::Capacity)?,
            None => 0,
        };
        Ok((selection.index, extra))
    }

    /// Called only after the exact config generation and all alias allocations are admitted.
    pub(crate) fn replacement(&self, secret: &Secret) -> Result<Replacement, Refusal> {
        let mut pair = Vec::with_capacity(self.colon + 1 + secret.value.len());
        pair.extend_from_slice(&self.decoded[..self.colon + 1]);
        pair.extend_from_slice(secret.value.as_bytes());
        let mut aliases: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(4);
        for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
            let from = engine.encode(&pair).into_bytes();
            if aliases.iter().any(|(existing, _)| *existing == from) {
                continue;
            }
            aliases.push((from, engine.encode(&self.decoded).into_bytes()));
        }
        let mut header = b"Basic ".to_vec();
        header.extend_from_slice(&aliases[0].0);
        let value = HeaderValue::from_bytes(&header).map_err(|_| Refusal::Invalid)?;
        Ok(Replacement { value, aliases })
    }
}

pub(crate) struct Replacement {
    pub(crate) value: HeaderValue,
    pub(crate) aliases: Vec<(Vec<u8>, Vec<u8>)>,
}

#[cfg(test)]
mod tests;
