use super::server::{Err, ServerError};
use actix_web::error::HttpError;
use aws_sdk_cognitoidentityprovider;
use aws_sdk_cognitoidentityprovider::error::SdkError;
use hmac::digest::InvalidLength;
use jsonwebtokens::error::Error as JwtError;
use jsonwebtokens_cognito::Error as JwksError;
use std::env::VarError;
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::sync::Arc;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct SecretHashError;

impl Display for SecretHashError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str("Missing SECRET_HASH")
    }
}

impl Err for SecretHashError {}

#[derive(Debug)]
pub enum LoginError<E: Error> {
    VarError(VarError),
    InvalidLength(InvalidLength),
    SdkError(E),
    HttpError(HttpError),
    JwksError(JwksError),
    JwtError(JwtError),
    SecretHashError(SecretHashError),
}

impl<E: Error> Err for LoginError<E> {}

impl From<VarError> for ServerError {
    fn from(e: VarError) -> Self {
        let err: LoginError<VarError> = LoginError::VarError(e.clone());
        match e {
            VarError::NotPresent => ServerError::new(
                Some("Env variable not found".into()),
                Some("Internal Server Error".into()),
                Arc::new(err),
                500,
            ),
            VarError::NotUnicode(..) => ServerError::new(
                Some("Non-Unicode in env variable".into()),
                Some("Internal Server Error".into()),
                Arc::new(err),
                500,
            ),
            // _ => ServerError::new(None, None, Arc::new(err), 500),
        }
    }
}

impl From<InvalidLength> for ServerError {
    fn from(e: InvalidLength) -> Self {
        let err: LoginError<InvalidLength> = LoginError::InvalidLength(e.clone());
        match e {
            InvalidLength => ServerError::new(
                Some("Non-Unicode in env variable".into()),
                Some("Internal Server Error".into()),
                Arc::new(err),
                500,
            ),
            // _ => ServerError::new(None, None, Arc::new(err), 500),
        }
    }
}

impl From<HttpError> for ServerError {
    fn from(e: HttpError) -> Self {
        ServerError::new(
            Some("Cookie Failed to Set".into()),
            Some("There was a problem setting credentials".into()),
            Arc::new(LoginError::HttpError::<HttpError>(e)),
            500,
        )
    }
}

impl From<JwksError> for ServerError {
    fn from(e: JwksError) -> Self {
        println!("{:?}", e);
        match e {
            JwksError::NoKeyID(..) => ServerError::new(
                Some("The token header didn't have a 'kid' key ID value".into()),
                Some("Internal Server Error".into()),
                Arc::new(LoginError::JwksError::<JwksError>(e)),
                500,
            ),
            JwksError::InvalidSignature(..) => ServerError::new(
                Some("The token's signature is invalid".into()),
                Some("Internal Server Error".into()),
                Arc::new(LoginError::JwksError::<JwksError>(e)),
                500,
            ),
            JwksError::TokenExpiredAt(..) => ServerError::new(
                Some("The token expired at this time (unix epoch timestamp)".into()),
                Some("Internal Server Error".into()),
                Arc::new(LoginError::JwksError::<JwksError>(e)),
                500,
            ),
            JwksError::MalformedToken(..) => ServerError::new(
                Some("Any of: header.payload.signature split error, json parser error, header or claim validation error".into()),
                Some("Unauthorized".into()),
                Arc::new(LoginError::JwksError::<JwksError>(e)),
                401,
            ),
            JwksError::NetworkError(..) => ServerError::new(
                Some("Failed to fetch remote jwks key set".into()),
                Some("Internal Server Error".into()),
                Arc::new(LoginError::JwksError::<JwksError>(e)),
                500,
            ),
            JwksError::CacheMiss(..) => ServerError::new(
                Some("Failed because the required Algorithm/key wasn't cached".into()),
                Some("Internal Server Error".into()),
                Arc::new(LoginError::JwksError::<JwksError>(e)),
                500,
            ),
            _ => ServerError::new(
                None,
                None,
                Arc::new(LoginError::JwksError::<JwksError>(e)),
                500,
            ),
        }
    }
}

impl From<JwtError> for ServerError {
    fn from(e: JwtError) -> Self {
        // let err: LoginError<JwtError> = LoginError::JwtError(e);
        match e {
            JwtError::AlgorithmMismatch(..) => ServerError::new(
                Some("Alg found in the token header didn't match the given algorithm".into()),
                Some("Internal Server Error".into()),
                Arc::new(LoginError::JwtError::<JwtError>(e)),
                500,
            ),
            JwtError::InvalidInput(..) => ServerError::new(
                Some("Invalid key data, malformed data for encoding, or base864/utf8 decode/encode errors".into()),
                Some("Internal Server Error".into()),
                Arc::new(LoginError::JwtError::<JwtError>(e)),
                500,
            ),
            JwtError::InvalidSignature(..) => ServerError::new(
                Some("Token's signature was not validated".into()),
                Some("Internal Server Error".into()),
                Arc::new(LoginError::JwtError::<JwtError>(e)),
                500,
            ),
            JwtError::MalformedToken(..) => ServerError::new(
                Some("Header.payload.signature split error, json parser error, or header or claim validation error".into()),
                Some("Internal Server Error".into()),
                Arc::new(LoginError::JwtError::<JwtError>(e)),
                500,
            ),

            JwtError::TokenExpiredAt(..) => ServerError::new(
                Some("Token expired at this time ".into()),
                Some("Internal Server Error".into()),
                Arc::new(LoginError::JwtError::<JwtError>(e)),
                500,
            ),
            _ => ServerError::new(
                None,
                None,
                Arc::new(LoginError::JwtError::<JwtError>(e)),
                500,
            ),
        }
    }
}

impl<E: Error + 'static> From<SdkError<E>> for ServerError {
    fn from(e: SdkError<E>) -> Self {
        match e {
            SdkError::ConstructionFailure(..) => ServerError::new(
                Some("Env variable not found".into()),
                Some("Internal Server Error".into()),
                Arc::new(LoginError::SdkError(e)),
                500,
            ),
            SdkError::DispatchFailure(..) => ServerError::new(
                Some("Non-Unicode in env variable".into()),
                Some("Internal Server Error".into()),
                Arc::new(LoginError::SdkError(e)),
                500,
            ),
            SdkError::ResponseError(..) => ServerError::new(
                Some("Non-Unicode in env variable".into()),
                Some("Internal Server Error".into()),
                Arc::new(LoginError::SdkError(e)),
                500,
            ),
            SdkError::ServiceError(..) => ServerError::new(
                Some("Non-Unicode in env variable".into()),
                Some("Internal Server Error".into()),
                Arc::new(LoginError::SdkError(e)),
                500,
            ),
            SdkError::TimeoutError(..) => ServerError::new(
                Some("Non-Unicode in env variable".into()),
                Some("Internal Server Error".into()),
                Arc::new(LoginError::SdkError(e)),
                500,
            ),
            _ => ServerError::new(None, None, Arc::new(LoginError::SdkError(e)), 500),
        }
    }
}
