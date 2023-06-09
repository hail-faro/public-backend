// use crate::data_structs::{login_user, register_user, validate_token};
use actix_web::{web, App, HttpServer};
use reqwest::Client;
mod errors;
mod handlers;
mod operations;

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=debug");
    let client = web::Data::new(Client::new());

    HttpServer::new(move || {
        App::new()
            .app_data(client.clone())
            // .route("/register", web::post().to(handlers::register_user_handler))
            .route("/login", web::post().to(handlers::login_user_handler))
            .route("/auth", web::get().to(handlers::authorize_user_handler))
    })
    .bind("0.0.0.0:3000")?
    .run()
    .await
}
