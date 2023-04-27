use std::{
    fmt::{Debug, Display, Result},
    sync::Arc,
};

use actix_web::{HttpResponse, ResponseError};
use reqwest::StatusCode;

pub trait Err {}

impl Debug for dyn Err {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", "Err")
    }
}

impl Display for dyn Err {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result {
        write!(f, "{}", "Err")
    }
}

#[derive(Debug)]
pub struct ServerError {
    pub cause: String,
    pub message: String,
    pub err: Arc<dyn Err>,
    pub status_code: u16,
}

impl Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result {
        write!(f, "{}", self)
    }
}

impl ServerError {
    pub fn new(c: Option<String>, m: Option<String>, e: Arc<dyn Err>, n: u16) -> Self {
        let cause = c.unwrap_or_else(|| "Unknown Cause".into());
        let message = m.unwrap_or_else(|| "An error has occurred".into());

        ServerError {
            cause,
            message,
            err: e,
            status_code: n,
        }
    }
}

impl ResponseError for ServerError {
    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        match self.status_code {
            401 => HttpResponse::build(StatusCode::from_u16(self.status_code).unwrap())
                .append_header(("WWW-Authenticate", "Basic"))
                .body(self.message.clone()),

            _ => HttpResponse::build(StatusCode::from_u16(self.status_code).unwrap())
                .body(self.message.clone()),
        }
    }
}
