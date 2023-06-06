use crate::errors::{login::SecretHashError, server::ServerError};
use aws_config::SdkConfig;
use aws_sdk_cognitoidentityprovider::{
    operation::{
        admin_initiate_auth::builders::AdminInitiateAuthFluentBuilder,
        initiate_auth::builders::InitiateAuthFluentBuilder,
    },
    types::{AuthFlowType, AuthenticationResultType},
    Client,
};
use base64::{engine::general_purpose, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{collections::HashMap, sync::Arc};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct AuthCredentials {
    pub secret: Option<String>,
    pub client_id: Option<String>,
    pub user_pool_id: Option<String>,
    pub auth_flow: AuthFlowType,
    pub hash: Option<HmacSha256>,
    pub encoding: Option<String>,
}

impl AuthCredentials {
    pub fn prepare<T>(
        secret: Option<String>,
        client_id: Option<String>,
        user_pool_id: Option<String>,
        auth_flow: T,
    ) -> AuthCredentials
    where
        T: Into<AuthFlowType>,
    {
        AuthCredentials {
            secret: secret,
            client_id: client_id,
            user_pool_id: user_pool_id,
            auth_flow: auth_flow.into(),
            hash: None,
            encoding: None,
        }
    }

    pub fn set_hash(&mut self) {
        // TODO throw if no hash done
        if let Some(secret) = &self.secret {
            let hash = HmacSha256::new_from_slice(secret.as_bytes());
            if let Ok(hash) = hash {
                self.hash = Some(hash);
            }
        }

        return;
    }

    pub fn update_hash(&mut self, updater: &[u8]) {
        // TODO throw if self.hash is none
        if let Some(mut hash) = self.hash.clone() {
            hash.update(updater);
            self.hash = Some(hash);
        }
    }

    pub fn set_encoding(&mut self) {
        // TODO throw if self.hash is none
        if let Some(hash) = self.hash.clone() {
            self.encoding = Some(general_purpose::STANDARD.encode(hash.finalize().into_bytes()));
        }
    }
}

#[derive(Clone, Debug)]
enum CognitoAuthType {
    AdminAuth,
    Auth,
}

#[derive(Debug, Clone)]
pub enum AuthBuilder {
    AdminInitiateAuthFluentBuilder(AdminInitiateAuthFluentBuilder),
    InitiateAuthFluentBuilder(InitiateAuthFluentBuilder),
    Client(Client),
}

#[derive(Clone, Debug)]
pub struct AuthClient {
    connection_credentials: AuthCredentials,
    cognito_auth_type: CognitoAuthType,
    auth_builder: AuthBuilder,
}

impl AuthClient {
    pub fn new(credentials: AuthCredentials, config: &SdkConfig) -> AuthClient {
        AuthClient {
            connection_credentials: credentials.clone(),
            cognito_auth_type: match credentials.auth_flow {
                AuthFlowType::AdminUserPasswordAuth => CognitoAuthType::AdminAuth,
                _ => CognitoAuthType::Auth,
            },
            auth_builder: AuthBuilder::Client(Client::new(config)),
        }
    }

    pub fn get_auth_builder(&self) -> AuthBuilder {
        self.auth_builder.clone()
    }

    pub fn prepare(&mut self) {
        if let AuthBuilder::Client(client) = self.auth_builder.clone() {
            self.auth_builder = match self.cognito_auth_type {
                CognitoAuthType::AdminAuth => AuthBuilder::AdminInitiateAuthFluentBuilder(
                    client
                        .admin_initiate_auth()
                        .set_user_pool_id(self.connection_credentials.user_pool_id.clone())
                        .set_client_id(self.connection_credentials.client_id.clone())
                        .auth_flow(self.connection_credentials.auth_flow.clone()),
                ),
                _ => {
                    AuthBuilder::InitiateAuthFluentBuilder(
                        client
                            .initiate_auth()
                            // .set_user_pool_id(self.connection_credentials.user_pool_id)
                            .set_client_id(self.connection_credentials.client_id.clone())
                            .auth_flow(self.connection_credentials.auth_flow.clone()),
                    )
                }
            }
        }
    }

    pub async fn auth(
        self,
        mut user_credentials: HashMap<String, String>,
    ) -> Result<AuthenticationResultType, ServerError> {
        // NOTE What if connection credentials doesnt contain secret and auth credentials already does....
        // NOTE for auth credentials vs connection credentials which should over rule
        // let err = LoginError::SdkError();
        if let Some(encoding) = self.connection_credentials.encoding {
            user_credentials.insert("SECRET_HASH".into(), encoding);
            // println!("{:?}\n{:?}", user_credentials, self.auth_builder);
            let res = match self.auth_builder {
                AuthBuilder::AdminInitiateAuthFluentBuilder(auth_builder) => {
                    let foo = auth_builder
                        .set_auth_parameters(Some(user_credentials))
                        .send()
                        .await;
                    println!("{:?}", foo);
                    foo?.authentication_result().cloned()
                }

                AuthBuilder::InitiateAuthFluentBuilder(auth_builder) => auth_builder
                    .set_auth_parameters(Some(user_credentials))
                    .send()
                    .await?
                    .authentication_result()
                    .cloned(),
                _ => None,
            };
            println!("Res: {:?}", res);

            if let Some(res) = res {
                return Ok(res.clone());
            }
        }

        return Err(ServerError::new(
            Some("Missing server side SECRET_HASH".into()),
            None,
            Arc::new(SecretHashError),
            401,
        ));
    }
}

// Credentials
// AuthType
// AuthBuilder
// AuthClient
