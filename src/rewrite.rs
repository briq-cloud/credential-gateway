//! Replacing strings in bytes: placeholders with real values on the way out, real values with
//! placeholders on the way back. Bodies are rewritten as they stream: a chunk is passed on at once,
//! except for a tail that could be the start of a string, kept back until the next chunk or the
//! end says. The gateway holds less than the longest string per body, whatever its size, and a
//! streamed response (server-sent events) arrives as the destination writes it.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};

use aho_corasick::{AhoCorasick, MatchKind};
use bytes::Bytes;
use http_body::{Body, Frame};
use pin_project_lite::pin_project;

use crate::BoxError;

/// Each `from` replaced by its `to`, leftmost first, the longest at a position.
pub struct Replacer {
    ac: AhoCorasick,
    from: Vec<Vec<u8>>,
    to: Vec<Vec<u8>>,
    longest: usize,
}

impl Replacer {
    /// `None` when there is nothing to look for (empty strings are left out).
    pub fn new<F: AsRef<[u8]>, T: AsRef<[u8]>>(pairs: &[(F, T)]) -> Option<Self> {
        let pairs: Vec<_> = pairs
            .iter()
            .filter(|(f, _)| !f.as_ref().is_empty())
            .collect();
        if pairs.is_empty() {
            return None;
        }
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(pairs.iter().map(|(f, _)| f.as_ref()))
            .ok()?;
        Some(Self {
            ac,
            from: pairs.iter().map(|(f, _)| f.as_ref().to_vec()).collect(),
            to: pairs.iter().map(|(_, t)| t.as_ref().to_vec()).collect(),
            longest: pairs
                .iter()
                .map(|(f, _)| f.as_ref().len())
                .max()
                .unwrap_or(1),
        })
    }

    pub fn patterns(&self) -> usize {
        self.to.len()
    }

    /// The whole input replaced, and which patterns matched.
    pub fn replace_all(&self, input: &[u8]) -> (Vec<u8>, Vec<bool>) {
        let mut hits = vec![false; self.to.len()];
        let mut out = Vec::with_capacity(input.len());
        let mut pos = 0;
        for m in self.ac.find_iter(input) {
            out.extend_from_slice(&input[pos..m.start()]);
            out.extend_from_slice(&self.to[m.pattern().as_usize()]);
            hits[m.pattern().as_usize()] = true;
            pos = m.end();
        }
        out.extend_from_slice(&input[pos..]);
        (out, hits)
    }

    /// The first position from `start` where what is left of `buf` could be the start of a
    /// string (or is one a longer string could continue); `buf.len()` when there is none.
    fn held_from(&self, buf: &[u8], start: usize) -> usize {
        (start..buf.len())
            .find(|&i| self.from.iter().any(|f| f.starts_with(&buf[i..])))
            .unwrap_or(buf.len())
    }
}

/// Which patterns of a `Replacer` a stream has matched so far, readable while it runs.
#[derive(Clone)]
pub struct Hits(Arc<Vec<AtomicBool>>);

impl Hits {
    pub fn new(n: usize) -> Self {
        Self(Arc::new((0..n).map(|_| AtomicBool::new(false)).collect()))
    }
    pub fn get(&self, i: usize) -> bool {
        self.0[i].load(Ordering::Relaxed)
    }
    fn set(&self, i: usize) {
        self.0[i].store(true, Ordering::Relaxed);
    }
}

/// A `Replacer` over a stream of chunks. What could be the start of a match split across two
/// chunks is kept back (`longest - 1` bytes at most) until the next chunk or the end says.
pub struct Stream {
    r: Arc<Replacer>,
    carry: Vec<u8>,
    hits: Hits,
}

impl Stream {
    pub fn new(r: Arc<Replacer>) -> Self {
        let hits = Hits::new(r.patterns());
        Self {
            r,
            carry: Vec::new(),
            hits,
        }
    }

    pub fn hits(&self) -> Hits {
        self.hits.clone()
    }

    /// What can be passed on after `chunk`.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(chunk);
        // A match starting before `cut` fits in `buf` whole, so it is already decided. Past it, a
        // match is decided when it starts before the held tail: from there, every string that
        // could match is in `buf` or has already failed.
        let cut = buf.len().saturating_sub(self.r.longest - 1);
        let mut out = Vec::with_capacity(buf.len());
        let mut pos = 0;
        // Only moves forward as `pos` does, so it is looked for again only once `pos` passes it.
        let mut held = self.r.held_from(&buf, cut);
        for m in self.r.ac.find_iter(&buf) {
            if pos > held {
                held = self.r.held_from(&buf, pos);
            }
            if m.start() >= held {
                break;
            }
            out.extend_from_slice(&buf[pos..m.start()]);
            out.extend_from_slice(&self.r.to[m.pattern().as_usize()]);
            self.hits.set(m.pattern().as_usize());
            pos = m.end();
        }
        if pos > held {
            held = self.r.held_from(&buf, pos);
        }
        out.extend_from_slice(&buf[pos..held]);
        self.carry = buf[held..].to_vec();
        out
    }

    /// What is left at the end.
    pub fn finish(&mut self) -> Vec<u8> {
        let rest = std::mem::take(&mut self.carry);
        let (out, hits) = self.r.replace_all(&rest);
        for (i, h) in hits.into_iter().enumerate() {
            if h {
                self.hits.set(i);
            }
        }
        out
    }
}

pin_project! {
    /// A body with a `Stream` applied to its data. Trailers are dropped: they are not read.
    pub struct Rewrite<B> {
        #[pin]
        inner: B,
        stream: Stream,
        finished: bool,
    }
}

impl<B> Rewrite<B> {
    pub fn new(inner: B, stream: Stream) -> Self {
        Self {
            inner,
            stream,
            finished: false,
        }
    }
}

impl<B> Body for Rewrite<B>
where
    B: Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let mut this = self.project();
        loop {
            if *this.finished {
                return Poll::Ready(None);
            }
            match ready!(this.inner.as_mut().poll_frame(cx)) {
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => {
                        let out = this.stream.push(&data);
                        if !out.is_empty() {
                            return Poll::Ready(Some(Ok(Frame::data(out.into()))));
                        }
                    }
                    Err(frame) => {
                        *this.finished = true;
                        drop(frame);
                        let out = this.stream.finish();
                        if !out.is_empty() {
                            return Poll::Ready(Some(Ok(Frame::data(out.into()))));
                        }
                    }
                },
                Some(Err(e)) => return Poll::Ready(Some(Err(e.into()))),
                None => {
                    *this.finished = true;
                    let out = this.stream.finish();
                    if !out.is_empty() {
                        return Poll::Ready(Some(Ok(Frame::data(out.into()))));
                    }
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replacer() -> Arc<Replacer> {
        Arc::new(
            Replacer::new(&[
                ("real-secret-VALUE", "briq_secret_aaaa"),
                ("short", "S"),
                ("real-secret-VALUE-longer", "briq_secret_bbbb"),
            ])
            .unwrap(),
        )
    }

    #[test]
    fn replaces_all_and_says_which() {
        let (out, hits) = replacer().replace_all(b"a real-secret-VALUE b short c");
        assert_eq!(out, b"a briq_secret_aaaa b S c");
        assert_eq!(hits, vec![true, true, false]);
        let (out, _) = replacer().replace_all(b"real-secret-VALUE-longer!");
        assert_eq!(out, b"briq_secret_bbbb!", "the longest at a position");
    }

    /// Every way of cutting the input in two, three and one-byte chunks gives what a whole
    /// replacement gives.
    #[test]
    fn a_stream_matches_the_whole_replacement_however_it_is_cut() {
        let input: &[u8] = b"xx real-secret-VALUE yy shortshort real-secret-VALUE-longer zz \
            real-secret-VALUE-long real-secret-VALUEshort real-secret-VALUE sho";
        let (want, _) = replacer().replace_all(input);
        let run = |cuts: &[usize]| {
            let mut s = Stream::new(replacer());
            let mut out = Vec::new();
            let mut prev = 0;
            for &c in cuts.iter().chain(std::iter::once(&input.len())) {
                out.extend(s.push(&input[prev..c]));
                prev = c;
            }
            out.extend(s.finish());
            (out, s.hits())
        };
        for a in 0..=input.len() {
            assert_eq!(run(&[a]).0, want, "cut at {a}");
            for b in a..=input.len() {
                assert_eq!(run(&[a, b]).0, want, "cuts at {a}, {b}");
            }
        }
        let ones: Vec<usize> = (1..input.len()).collect();
        let (out, hits) = run(&ones);
        assert_eq!(out, want, "one byte at a time");
        assert!(hits.get(0) && hits.get(1) && hits.get(2));
    }

    #[test]
    fn holds_back_only_what_could_start_a_string() {
        let mut s = Stream::new(replacer());
        assert_eq!(
            s.push(&[b'a'; 100]),
            vec![b'a'; 100],
            "nothing that could start one"
        );
        assert_eq!(s.push(b"data: one\n\n"), b"data: one\n\n");
        assert_eq!(
            s.push(b"xx real-sec"),
            b"xx ",
            "the start of a string waits"
        );
        assert_eq!(
            s.push(b"ret-VALUE"),
            b"",
            "a longer string could still follow"
        );
        assert_eq!(s.push(b" yy sho"), b"briq_secret_aaaa yy ");
        assert_eq!(s.finish(), b"sho");
    }
}
