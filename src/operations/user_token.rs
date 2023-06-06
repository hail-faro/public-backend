use actix_web::cookie::Cookie;

#[derive(Debug, Clone)]
pub enum UserToken<'a> {
    String(String),
    Cookie(Cookie<'a>),
}

impl From<String> for UserToken<'_> {
    fn from(token: String) -> Self {
        UserToken::String(token)
    }
}

impl From<&str> for UserToken<'_> {
    fn from(token: &str) -> Self {
        UserToken::String(token.into())
    }
}

impl<'a> From<Cookie<'a>> for UserToken<'a> {
    fn from(token: Cookie<'a>) -> Self {
        UserToken::Cookie(token)
    }
}

impl Into<String> for UserToken<'_> {
    fn into(self) -> String {
        if let UserToken::String(t) = self {
            return t;
        } else {
            return "".into();
        }
    }
}
impl<'a> Into<Cookie<'a>> for UserToken<'a> {
    fn into(self) -> Cookie<'a> {
        if let UserToken::Cookie(t) = self {
            return t;
        } else {
            Cookie::build("", "").finish()
        }
    }
}
