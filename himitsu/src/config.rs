use crate::scanners::Scanner;



pub struct HimitsuConfiguration {
    pub scanner: Scanner,
}

impl HimitsuConfiguration {
    pub fn default() -> Self {
        Self {
            scanner: Scanner::default(),
        }
    }
}
