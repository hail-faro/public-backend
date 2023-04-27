use crate::data_structs;
use crate::errors::server::ServerError;
use actix_web::{
    cookie::{time::Duration, Cookie},
    web, HttpRequest, HttpResponse, Responder,
};
use aws_sdk_cognitoidentityprovider::config::{Credentials, Region};
use base64::{engine::general_purpose, Engine};
use dotenv::dotenv;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    collections::HashMap,
    env::{self},
};
type HmacSha256 = Hmac<Sha256>;

// pub async fn register_user_handler(
//     client: web::Data<Client>,
// ) -> Result<impl Responder, ServerError> {
// }

pub async fn login_user_handler(
    _req: HttpRequest,
    params: web::Form<data_structs::UserLoginRequest>,
) -> Result<impl Responder, ServerError> {
    dotenv().ok();
    let secret: String = env::var("COGNITO_SECRET").unwrap_or("".into());
    let client_id: String = env::var("APP_CLIENT_ID").unwrap_or("".into());
    let user_pool_id: String = env::var("USER_POOL_ID").unwrap_or("".into());
    let auth_flow = "ADMIN_USER_PASSWORD_AUTH".into();
    // let region = env::var("COGNITO_REGION").unwrap_or("".into());
    // let access_key_id = env::var("AWS_ACCESS_KEY_ID").unwrap_or("".into());
    // let secret_access_key = env::var("AWS_SECRET_ACCESS_KEY").unwrap_or("".into());

    let config = aws_config::load_from_env().await;
    // .region(Region::new(region))
    // .credentials_provider(Credentials::new(
    //     access_key_id,
    //     secret_access_key,
    //     Some("WebIdentityToken".into()),
    //     None,
    //     "Environment",
    // ))
    // .load()
    // .await;
    // println!("{:?}", client_id);

    let updater: String = format!("{}{}", params.email, client_id);

    let mut hash: HmacSha256 = HmacSha256::new_from_slice(secret.as_bytes())?;
    hash.update(updater.as_bytes());

    let encoded_key = general_purpose::STANDARD.encode(hash.finalize().into_bytes());

    let client = aws_sdk_cognitoidentityprovider::Client::new(&config)
        .admin_initiate_auth()
        .set_user_pool_id(Some(user_pool_id))
        .set_client_id(Some(client_id))
        .auth_flow(auth_flow);

    let credentials: HashMap<String, String> = HashMap::from([
        ("USERNAME".into(), params.email.clone()),
        ("PASSWORD".into(), params.password.clone()),
        ("SECRET_HASH".into(), encoded_key),
    ]);

    let auth_output = client.set_auth_parameters(Some(credentials)).send().await;
    // println!("{:?}", auth_output);
    let auth_output = auth_output?;

    let authentication_result = auth_output.authentication_result().unwrap();

    // println!("{:?}", authentication_result);

    let refresh_cookie = Cookie::build(
        "refresh_token",
        authentication_result.refresh_token().unwrap(),
    )
    .max_age(Duration::minutes(authentication_result.expires_in().into()))
    .same_site(actix_web::cookie::SameSite::Lax)
    .path("/")
    .domain("localhost")
    .finish();

    let access_cookie = Cookie::build(
        "access_token",
        authentication_result.access_token().unwrap(),
    )
    .max_age(Duration::minutes(authentication_result.expires_in().into()))
    .same_site(actix_web::cookie::SameSite::Lax)
    .path("/")
    .domain("localhost")
    .finish();

    let id_cookie = Cookie::build("id_token", authentication_result.id_token().unwrap())
        .max_age(Duration::minutes(authentication_result.expires_in().into()))
        .same_site(actix_web::cookie::SameSite::Lax)
        .path("/")
        .domain("localhost")
        .finish();

    let mut res = HttpResponse::Ok().body("Logged in");

    res.add_cookie(&refresh_cookie)?;
    res.add_cookie(&access_cookie)?;
    res.add_cookie(&id_cookie)?;
    // println!("{:?}", res);

    Ok(res)
}

// pub async fn auth_user_handler(client: web::Data<Client>) -> Result<impl Responder, ServerError> {}
