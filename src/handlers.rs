use crate::operations::auth::AuthCredentials;
use crate::operations::user::{UserAuthCredentials, UserLoginRequest};
use crate::operations::user_token::UserToken;
use crate::{errors::server::ServerError, operations::auth::AuthClient};
use actix_web::{web, HttpRequest, HttpResponse};
use dotenv::dotenv;
use jsonwebtokens_cognito::KeySet;
use std::env::{self};

pub async fn login_user_handler(
    req: HttpRequest,
    params: web::Form<UserLoginRequest>,
) -> Result<HttpResponse, ServerError> {
    // gather variables
    dotenv().ok();
    let config = aws_config::load_from_env().await;

    let secret: Option<String> = env::var("COGNITO_SECRET").ok();
    let client_id: Option<String> = env::var("APP_CLIENT_ID").ok();
    let user_pool_id: Option<String> = env::var("USER_POOL_ID").ok();

    // println!("{:?}\n{:?}\n{:?}\n", secret, client_id, user_pool_id);

    let mut credentials = AuthCredentials::prepare(
        secret.clone(),
        client_id.clone(),
        user_pool_id.clone(),
        "ADMIN_USER_PASSWORD_AUTH",
    );

    credentials.set_hash();
    let updater = format!("{}{}", params.email, client_id.clone().unwrap());
    credentials.update_hash(updater.as_bytes());
    credentials.set_encoding();

    let mut auth_output = AuthClient::new(credentials, &config);
    auth_output.prepare();

    let user_credentials = params.package_data();

    let authentication_result = auth_output.auth(user_credentials).await;

    let authentication_result: aws_sdk_cognitoidentityprovider::types::AuthenticationResultType =
        authentication_result?.clone();

    let mut user_login_res =
        UserAuthCredentials::build(authentication_result, req.headers().get("host").cloned());

    user_login_res.cookify();

    let res = user_login_res.response();
    println!("Res: {:?}", res);

    res
}

pub async fn authorize_user_handler(req: HttpRequest) -> Result<HttpResponse, ServerError> {
    let client_id: Option<String> = env::var("APP_CLIENT_ID").ok();

    let user_auth_credentials: UserAuthCredentials = req.into();
    let access_token = user_auth_credentials.tokens.get("access_token");
    if let Some(UserToken::Cookie(token)) = access_token {
        if let (Some(region), Some(user_pool_id)) = (
            env::var("COGNITO_REGION").ok(),
            env::var("USER_POOL_ID").ok(),
        ) {
            let keyset = KeySet::new(region, user_pool_id)?;
            keyset.prefetch_jwks().await?;

            let verifier = keyset
                .new_access_token_verifier(&[&client_id.unwrap()])
                .build()?;

            let foo = keyset.verify(&token.value(), &verifier).await?;

            println!("{:?}", foo);
        }
    }

    let res = HttpResponse::Unauthorized().finish();

    Ok(res)
}
