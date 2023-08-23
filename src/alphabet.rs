use crate::error::Error;
use crate::result::Result;

struct Letter {
    val: char,
    pos: usize,
}

pub struct Alphabet {
    by_pos: Vec<char>,
    by_ltr: Vec<Letter>,
}

impl Alphabet {
    fn build_by_ltr(by_pos: &Vec<char>) -> Vec<Letter> {
        let mut by_ltr = Vec::<Letter>::with_capacity(by_pos.len());

        for c in by_pos {
            by_ltr.push(Letter {
                val: *c,
                pos: by_ltr.len(),
            });
        }

        by_ltr.sort_by_key(|l| l.val);

        by_ltr
    }

    pub fn new(s: &str) -> Alphabet {
        let mut by_pos = Vec::<char>::new();

        s.chars().for_each(|c| by_pos.push(c));

        Alphabet {
            by_ltr: Self::build_by_ltr(&by_pos),
            by_pos: by_pos,
        }
    }

    pub fn len(&self) -> usize {
        self.by_pos.len()
    }

    pub fn truncate(&mut self, len: usize) {
        if len < self.by_pos.len() {
            self.by_pos.truncate(len);
            self.by_ltr = Self::build_by_ltr(&self.by_pos);
        }
    }

    pub fn ltr(&self, c: char) -> Result<usize> {
        match self.by_ltr.binary_search_by_key(&c, |l| l.val) {
            Ok(i) => Ok(self.by_ltr[i].pos),
            Err(_) => Err(Error::new("letter not found in alphabet")),
        }
    }

    pub fn pos(&self, i: usize) -> Result<char> {
        Ok(self.by_pos[i])
    }
}
