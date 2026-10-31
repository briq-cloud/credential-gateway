//! Intercepted HTTPS requests, admission and request-local response scrubbing.

use super::*;
use crate::basic::{self, Refusal};

impl Gateway {
    pub(super) async fn intercept(
        &self,
        req: Request<Incoming>,
        host: &str,
        port: u16,
        briq: Option<&str>,
        upstream: &Client<HttpsConnector<HttpConnector>, Body>,
    ) -> Result<Response<Body>, BoxError> {
        // The request must address the CONNECT host: a Host naming another site on the same
        // address (a shared CDN) would carry the real value there. An absolute-form target is
        // refused too.
        let req_host = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|h| strip_port(h).to_ascii_lowercase());
        if req_host.is_some_and(|h| h != host.to_ascii_lowercase()) || req.uri().scheme().is_some()
        {
            return Ok(text(
                StatusCode::BAD_REQUEST,
                &format!("briq credential gateway: the request must address {host}\n"),
            ));
        }
        let parsed = match basic::parse(req.headers(), &self.rewrite_budget) {
            Ok(parsed) => parsed,
            Err(reason) => return Ok(text(reason.status(), reason.message())),
        };
        let protect_basic = parsed.is_some();
        let mut selection = parsed.as_ref().map(|parsed| parsed.selection());
        let mut audit_charge = Events::estimate(briq, host, req.method().as_str());
        let (secrets, (reservation, audit, basic_index)) =
            match self.config.for_host_with(host, briq, |secrets| {
                let mut index = 0;
                let mut selected = secrets.inspect(|secret| {
                    audit_charge.name(&secret.name);
                    if let (Some(parsed), Some(selection)) = (&parsed, &mut selection) {
                        parsed.inspect(selection, index, secret);
                    }
                    index += 1;
                });
                let base = estimate(&mut selected).ok_or(Refusal::Capacity)?;
                let (basic_index, extra) = match (&parsed, selection.take()) {
                    (Some(parsed), Some(selection)) => parsed.finish(selection)?,
                    _ => (None, 0),
                };
                let reservation = base
                    .checked_add(extra)
                    .and_then(|bytes| self.rewrite_budget.reserve(bytes))
                    .ok_or(Refusal::Capacity)?;
                let audit = self
                    .events
                    .admit_estimated(briq, host, req.method().as_str(), audit_charge)
                    .map_err(|_| Refusal::Capacity)?;
                Ok::<_, Refusal>((reservation, audit, basic_index))
            }) {
                Ok(admitted) => admitted,
                Err(reason) => return Ok(text(reason.status(), reason.message())),
            };
        let (parts, body) = req.into_parts();
        let mut headers = forward_headers(&parts.headers);
        headers.insert(header::HOST, HeaderValue::from_str(&bracketed(host))?);
        // Scrubbing reads the response: ask for it uncompressed.
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );

        let replacement = match (&parsed, basic_index) {
            (Some(parsed), Some(index)) => match parsed.replacement(&secrets[index]) {
                Ok(replacement) => Some(replacement),
                Err(reason) => return Ok(text(reason.status(), reason.message())),
            },
            _ => None,
        };
        let mut used: Vec<String> = basic_index
            .into_iter()
            .map(|index| secrets[index].name.clone())
            .collect();
        // Build the one combined response matcher before any credential can be forwarded.
        // It retains exactly this request's config/aliases even if the next request rotates.
        // A complete emitted alias wins an equal literal rule as well as shorter ones.
        let pairs: Vec<(&[u8], &[u8])> = replacement
            .iter()
            .flat_map(|replacement| {
                replacement
                    .aliases
                    .iter()
                    .map(|(from, to)| (from.as_slice(), to.as_slice()))
            })
            .chain(
                secrets
                    .iter()
                    .map(|secret| (secret.value.as_bytes(), secret.placeholder.as_bytes())),
            )
            .collect();
        let scrub = match Replacer::new(&pairs) {
            Ok(replacer) => replacer.map(Arc::new),
            Err(_) => {
                return Ok(text(
                    Refusal::Capacity.status(),
                    Refusal::Capacity.message(),
                ));
            }
        };
        drop(pairs);
        if let Some(replacement) = replacement {
            headers.insert(header::AUTHORIZATION, replacement.value);
        }
        drop(parsed);

        // Headers: every secret that allows them.
        let in_headers: Vec<&Secret> = secrets.iter().filter(|s| s.allows("header")).collect();
        if let Some(r) = replacer(&in_headers, |s| (&s.placeholder, &s.value))? {
            let hits = match rewrite_headers_except_basic(&mut headers, &r, protect_basic) {
                Ok(hits) => hits,
                Err(_) => {
                    return Ok(text(
                        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                        "rewritten request headers exceed 64 KiB or contain invalid values\n",
                    ));
                }
            };
            used.extend(names(&in_headers, &hits));
        }

        // The body, for the secrets that allow it: held up to `max_body` to keep its length,
        // rewritten as it streams past that. Without such a secret it goes on untouched.
        let in_body: Vec<&Secret> = secrets.iter().filter(|s| s.allows("body")).collect();
        let mut body_hits = None;
        let mut held = None;
        let body: Body = match replacer(&in_body, |s| (&s.placeholder, &s.value))? {
            None => boxed(body),
            Some(r) => {
                let r = Arc::new(r);
                let (head, rest) = match self.held.clone().try_acquire_owned() {
                    Ok(permit) => {
                        held = Some(Arc::new(permit));
                        read_up_to(body, self.opts.max_body).await?
                    }
                    // As many bodies held as allowed: this one streams from its first byte.
                    Err(_) => (BytesMut::new(), Some(body)),
                };
                match rest {
                    None if r.replaced_len(&head, self.opts.max_body).is_some() => {
                        let (out, hits) = r.replace_all(&head);
                        used.extend(names(&in_body, &hits));
                        // A request that had no body (a GET) is sent without one.
                        let had_body = !out.is_empty()
                            || parts.headers.contains_key(header::CONTENT_LENGTH)
                            || parts.headers.contains_key(header::TRANSFER_ENCODING);
                        if had_body {
                            headers.insert(header::CONTENT_LENGTH, out.len().into());
                        }
                        full(out)
                    }
                    None => {
                        // The input fits, but substitutions would exceed the output budget.
                        headers.remove(header::CONTENT_LENGTH);
                        let stream = Stream::new(r);
                        body_hits = Some(stream.hits());
                        Rewrite::new(full(head.freeze()), stream).boxed_unsync()
                    }
                    Some(rest) => {
                        headers.remove(header::CONTENT_LENGTH);
                        let stream = Stream::new(r);
                        body_hits = Some(stream.hits());
                        let chained = StreamBody::new(
                            futures_util::stream::once(async move {
                                Ok::<_, BoxError>(Frame::data(head.freeze()))
                            })
                            .chain(TryStreamExt::map_err(BodyStream::new(rest), BoxError::from)),
                        );
                        Rewrite::new(chained, stream).boxed_unsync()
                    }
                }
            }
        };

        if let Some(audit) = &audit {
            audit.used(used);
            if let Some(hits) = &body_hits {
                audit.body(
                    hits.clone(),
                    in_body.iter().map(|secret| secret.name.as_str()),
                );
            }
        }
        let port = self.opts.upstream_port.unwrap_or(port);
        let path = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let mut up = Request::builder()
            .method(parts.method.clone())
            .uri(Uri::try_from(format!(
                "https://{}:{port}{path}",
                bracketed(host)
            ))?)
            .body(Retained::new(body, (reservation.clone(), held, audit.clone())).boxed_unsync())?;
        *up.headers_mut() = headers;
        if let Some(audit) = &audit {
            audit.arm();
        }
        let res = upstream.request(up).await;
        // A request that failed after forwarding began still carried the values.
        let code = res
            .as_ref()
            .map_or(502, |response| response.status().as_u16());
        if let Some(audit) = &audit {
            audit.finish(code);
        }
        let res = res?;

        // Keep the already-admitted matcher, including the exact credential we emitted.
        let Some(scrub) = scrub else {
            let (p, b) = res.into_parts();
            let mut out = Response::new(boxed(b));
            *out.status_mut() = p.status;
            *out.headers_mut() = forward_headers(&p.headers);
            return Ok(out);
        };
        let (parts_res, body) = res.into_parts();
        // Read original metadata: hop-by-hop filtering must not hide a coded body.
        let encoding = match response_encoding(&parts_res.headers) {
            Ok(encoding) => encoding,
            Err(_) => return Ok(encoding_refusal()),
        };
        let mut out = Response::builder()
            .status(parts_res.status)
            .body(Empty::new().map_err(never).boxed_unsync())?;
        let mut headers = forward_headers(&parts_res.headers);
        rewrite_headers(&mut headers, &scrub)?;
        let st = parts_res.status;
        if parts.method == Method::HEAD
            || st.is_informational()
            || st == StatusCode::NO_CONTENT
            || st == StatusCode::NOT_MODIFIED
        {
            *out.headers_mut() = headers;
            return Ok(out);
        }
        // The length changes with what is replaced: the body goes out chunked.
        headers.remove(header::CONTENT_LENGTH);
        if encoding.is_none() {
            headers.remove(header::CONTENT_ENCODING);
        }
        let body: Body = match encoding {
            None => boxed(body),
            // Asked for none, got a compressed body: read it to scrub it, or refuse it. A real
            // value never goes on unread.
            Some(enc) => match decoded(body, &enc).await {
                Some(b) => {
                    headers.remove(header::CONTENT_ENCODING);
                    b
                }
                None => return Ok(encoding_refusal()),
            },
        };
        *out.headers_mut() = headers;
        *out.body_mut() =
            Retained::new(Rewrite::new(body, Stream::new(scrub)), reservation).boxed_unsync();
        Ok(out)
    }
}
