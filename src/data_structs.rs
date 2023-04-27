use aws_sdk_cognitoidentityprovider::types::AuthFlowType;
use dotenv;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct UserRegisterRequest {
    first_name: String,
    last_name: String,
    age: String,
    email: String,
}
impl UserRegisterRequest {
    pub async fn register_user(&self) -> Result<UserRegisterResponse, reqwest::Error> {
        let mut res = UserRegisterResponse::new("".into());

        return Ok(res);
    }
}

////////////////////////////////////////////////////////////////////////
#[derive(Debug, Deserialize)]
struct UserRegisterResponse {
    message: String,
}

impl UserRegisterResponse {
    fn new(message: String) -> Self {
        UserRegisterResponse { message }
    }
}

////////////////////////////////////////////////////////////////////////
#[derive(Debug, Deserialize)]
pub struct UserLoginRequest {
    pub email: String,
    pub password: String,
    // auth_flow: AuthFlowType,
}

impl UserLoginRequest {
    pub async fn login_user(&self) -> Result<UserLoginResponse, reqwest::Error> {
        let mut res = UserLoginResponse::new("".into(), "".into(), "".into(), "".into(), 0);

        return Ok(res);
    }
}

////////////////////////////////////////////////////////////////////////
#[derive(Debug, Deserialize)]
struct UserLoginResponse {
    message: String,
    access_token: String,
    id_token: String,
    refresh_token: String,
    expires_in: u64,
}

impl UserLoginResponse {
    fn new(
        message: String,
        access_token: String,
        id_token: String,
        refresh_token: String,
        expires_in: u64,
    ) -> Self {
        UserLoginResponse {
            message,
            access_token,
            id_token,
            refresh_token,
            expires_in,
        }
    }
}

////////////////////////////////////////////////////////////////////////
//
// #[derive(Debug, Serialize)]
// enum AuthFlow {
//     AdminUserPasswordAuth,
// }

// pub async fn validate_token(client: &Client, token: &str) -> Result<bool, reqwest::Error> {}
