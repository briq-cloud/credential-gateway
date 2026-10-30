//! Keep a reservation with a body and its emitted data, including Hyper's pending writes.
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::task::{Context, Poll};

pin_project! {
    pub(crate) struct Retained<B, G> {
        #[pin]
        body: B,
        guard: G,
    }
}
impl<B, G> Retained<B, G> {
    pub(crate) fn new(body: B, guard: G) -> Self {
        Self { body, guard }
    }
}
struct Data<G> {
    bytes: Bytes,
    _guard: G,
}
impl<G> AsRef<[u8]> for Data<G> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl<B: Body<Data = Bytes>, G: Clone + Send + Sync + 'static> Body for Retained<B, G> {
    type Data = Bytes;
    type Error = B::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        let this = self.project();
        this.body.poll_frame(cx).map(|frame| {
            frame.map(|result| {
                result.map(|frame| {
                    frame.map_data(|bytes| {
                        Bytes::from_owner(Data {
                            bytes,
                            _guard: this.guard.clone(),
                        })
                    })
                })
            })
        })
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::Budget;
    use http_body_util::{BodyExt, Full};
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    #[tokio::test]
    async fn early_response_and_buffered_writes_keep_upload_reservations() {
        let budget = Budget::new(10);
        let held = Arc::new(Semaphore::new(1));
        let reservation = budget.reserve(10).unwrap();
        let buffer = Arc::new(held.clone().try_acquire_owned().unwrap());
        let mut upload = Retained::new(
            Full::new(Bytes::from_static(b"upload")),
            (reservation.clone(), buffer),
        );
        let response = Retained::new(
            Full::new(Bytes::from_static(b"early response")),
            reservation,
        );
        // The response can finish while Hyper still owns the outgoing upload body.
        drop(response);
        assert!(budget.reserve(1).is_none());
        assert!(held.clone().try_acquire_owned().is_err());
        let pending_write = upload.frame().await.unwrap().unwrap().into_data().unwrap();
        drop(upload);
        // Even dropping the body cannot release a frame awaiting a socket write.
        assert!(budget.reserve(1).is_none());
        assert!(held.clone().try_acquire_owned().is_err());
        assert_eq!(&pending_write[..], b"upload");
        drop(pending_write);
        assert!(budget.reserve(10).is_some());
        assert!(held.try_acquire_owned().is_ok());
    }
}
