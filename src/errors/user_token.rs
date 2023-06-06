use std::fmt::{Display, Formatter};

use super::server::Err;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct NoCookieError;

impl Display for NoCookieError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str("Missing SECRET_HASH")
    }
}

impl Err for NoCookieError {}
