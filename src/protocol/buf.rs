use std::ops::Deref;

pub struct Buffer {
    vec: Vec<u8>
}

pub enum Buf<'a> {
    Empty(&'a mut Vec<u8>, &'a [u8]),
    Some(&'a mut Vec<u8>),
}

impl Buffer {
    pub fn new() -> Buffer {
        Buffer {
            vec: Vec::new(),
        }
    }

    pub fn buf<'a, 'b: 'a>(&'a mut self, more: &'b [u8]) -> Buf<'a> {
        if self.vec.is_empty() {
            Buf::Empty(&mut self.vec, more)
        } else {
            self.vec.extend_from_slice(more);
            Buf::Some(&mut self.vec)
        }
    }

    pub fn clear(&mut self) {
        self.vec.clear()
    }

    pub fn len(&self) -> usize {
        self.vec.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vec.is_empty()
    }
}

impl<'a> Buf<'a> {
    pub fn keep(&mut self, n: usize) {
        match *self {
            Buf::Empty(ref mut vec, more) => {
                let n = more.len() - n;
                vec.extend_from_slice(&more[n..]);
            },
            Buf::Some(ref mut vec) => {
                let n = vec.len() - n;
                vec.drain(..n);
            },
        }
    }
}

impl<'a> Deref for Buf<'a> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match *self {
            Buf::Empty(_, more) => more,
            Buf::Some(ref vec)  => &vec[..],
        }
    }
}
