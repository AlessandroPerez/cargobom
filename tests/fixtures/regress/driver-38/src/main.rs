use sha2::{Digest, Sha256, Sha384, Sha512};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

trait Stream {
    type Item;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>>;
    fn size_hint(&self) -> usize;
}

struct Unfold<T, F, Fut> {
    state: Option<T>,
    f: F,
    fut: Option<Pin<Box<Fut>>>,
}

fn unfold<T, F, Fut, It>(init: T, f: F) -> Unfold<T, F, Fut>
where
    F: FnMut(T) -> Fut,
    Fut: Future<Output = Option<(It, T)>>,
{
    Unfold {
        state: Some(init),
        f,
        fut: None,
    }
}

impl<T, F, Fut, It> Stream for Unfold<T, F, Fut>
where
    T: Unpin,
    F: FnMut(T) -> Fut + Unpin,
    Fut: Future<Output = Option<(It, T)>>,
{
    type Item = It;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<It>> {
        let this = &mut *self;
        if let Some(state) = this.state.take() {
            this.fut = Some(Box::pin((this.f)(state)));
        }
        let Some(fut) = this.fut.as_mut() else {
            return Poll::Ready(None);
        };
        match fut.as_mut().poll(cx) {
            Poll::Ready(Some((item, next))) => {
                this.state = Some(next);
                this.fut = None;
                Poll::Ready(Some(item))
            }
            Poll::Ready(None) => {
                this.fut = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    // only the object calls it
    fn size_hint(&self) -> usize {
        Sha384::digest(b"hint").len()
    }
}

struct Graph(Vec<u8>);

impl Graph {
    async fn next_node(&mut self) -> Option<u8> {
        let b = self.0.pop()?;
        Some(Sha256::digest([b])[0])
    }

    fn stream(self) -> impl Stream<Item = u8> {
        unfold(self, async |mut state| match state.next_node().await {
            Some(node) => Some((node, state)),
            None => None,
        })
    }
}

type Dispatched<'a> = Pin<Box<dyn Future<Output = usize> + 'a>>;

trait Dispatch {
    fn call<'a>(self: Box<Self>, input: &'a mut Vec<u8>) -> Dispatched<'a>
    where
        Self: 'a;
}

struct DispatchFn<F>(F);

impl<F> Dispatch for DispatchFn<F>
where
    F: AsyncFnOnce(&mut Vec<u8>) -> usize,
{
    fn call<'a>(self: Box<Self>, input: &'a mut Vec<u8>) -> Dispatched<'a>
    where
        Self: 'a,
    {
        Box::pin((self.0)(input))
    }
}

fn main() {
    let input = std::env::args().nth(1).unwrap_or_default().into_bytes();
    let mut cx = Context::from_waker(Waker::noop());
    let mut s: Pin<Box<dyn Stream<Item = u8>>> = Box::pin(Graph(input.clone()).stream());
    let mut n = s.size_hint();
    while let Poll::Ready(Some(b)) = s.as_mut().poll_next(&mut cx) {
        n += b as usize;
    }
    let d: Box<dyn Dispatch> = Box::new(DispatchFn(async |v: &mut Vec<u8>| {
        v.push(1);
        Sha512::digest(&v).len()
    }));
    let mut v = input;
    let mut fut = d.call(&mut v);
    if let Poll::Ready(k) = fut.as_mut().poll(&mut cx) {
        n += k;
    }
    println!("{n}");
}
