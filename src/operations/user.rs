use crate::errors::server::ServerError;
use crate::operations::user_token::UserToken;
use actix_web::{
    cookie::{
        time::{Duration, OffsetDateTime},
        Cookie, SameSite,
    },
    HttpRequest, HttpResponse,
};
use aws_sdk_cognitoidentityprovider::types::AuthenticationResultType;
use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct UserLoginRequest {
    pub email: String,
    pub password: String,
}

impl UserLoginRequest {
    pub fn package_data(&self) -> HashMap<String, String> {
        HashMap::from([
            ("USERNAME".into(), self.email.clone()),
            ("PASSWORD".into(), self.password.clone()),
        ])
    }
}

#[derive(Debug, Clone)]
pub struct UserAuthCredentials<'a> {
    message: String,
    pub tokens: HashMap<&'a str, UserToken<'a>>,
    expires_in: i32,
    domain: Option<HeaderValue>,
}

impl From<HttpRequest> for UserAuthCredentials<'_> {
    fn from(req: HttpRequest) -> Self {
        let mut user_auth_credentials = UserAuthCredentials::new("".into(), 0, None);

        // let foo = req.cookie("id_token").unwrap().max_age();
        // println!("{:?}", foo);

        user_auth_credentials.tokens.insert(
            "access_token",
            UserToken::Cookie(req.cookie("access_token").unwrap()),
        );
        user_auth_credentials.tokens.insert(
            "refresh_token",
            UserToken::Cookie(req.cookie("refresh_token").unwrap()),
        );
        user_auth_credentials.tokens.insert(
            "id_token",
            UserToken::Cookie(req.cookie("id_token").unwrap()),
        );

        user_auth_credentials.domain = req.head().headers.get("host").cloned();

        user_auth_credentials
    }
}

impl UserAuthCredentials<'_> {
    pub fn new(message: String, expires_in: i32, domain: Option<HeaderValue>) -> Self {
        UserAuthCredentials {
            message: message,
            tokens: HashMap::new(),
            expires_in: expires_in,
            domain: domain,
        }
    }

    pub fn build(
        auth_data: AuthenticationResultType,
        domain: Option<HeaderValue>,
    ) -> UserAuthCredentials<'static> {
        let mut res = UserAuthCredentials::new("Logged In".into(), auth_data.expires_in, domain);
        if let Some(access_token) = auth_data.access_token() {
            res.tokens.insert("access_token", access_token.into());
        }
        if let Some(id_token) = auth_data.id_token() {
            res.tokens.insert("id_token", id_token.into());
        }
        if let Some(refresh_token) = auth_data.refresh_token() {
            res.tokens.insert("refresh_token", refresh_token.into());
        }
        res.clone()
    }

    // pub fn set_tokens(&mut self, tokens: HashMap<String, Token>) {
    //     &mut self.tokens = &mut tokens.clone();
    // }

    pub fn cookify(&mut self) {
        let mut new_tokens: HashMap<&str, UserToken> = HashMap::new();
        for (k, v) in self.tokens.iter_mut() {
            if let UserToken::String(token) = v {
                let age = Duration::seconds(self.expires_in.into());
                let cookie = Cookie::build(*k, token.clone())
                    .max_age(age)
                    .expires(OffsetDateTime::now_utc().checked_add(age))
                    .same_site(SameSite::Lax)
                    .path("/")
                    .http_only(true)
                    .domain("0.0.0.0")
                    .finish();

                // println!("{:?}", cookie);

                new_tokens.insert(&k, UserToken::Cookie(cookie));
            } else {
                new_tokens.insert(&k, v.clone());
            }
        }
        self.tokens = new_tokens;
    }

    pub fn response(&self) -> Result<HttpResponse, ServerError> {
        let mut res = HttpResponse::Ok().body(self.message.clone());

        for (_k, v) in &self.tokens {
            if let UserToken::Cookie(cookie) = v {
                res.add_cookie(cookie)?;
            }
        }

        Ok(res)
    }

    // pub fn validate(&self) -> Result<HttpResponse, ServerError> {
    //     let foo = self;
    // }
}

#[derive(Debug, Serialize, Deserialize)]
struct UserClaim {
    sub: String,
    company: String,
    exp: usize,
}
