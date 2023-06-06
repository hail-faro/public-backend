use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize, Serialize, Debug, Clone)]
struct AuthKey {
    kid: String,
    alg: String,
    kty: String,
    e: String,
    n: String,
    intended_use: String,
}

impl AuthKey {
    pub fn new() -> AuthKey {
        AuthKey {
            kid: "".into(),
            alg: "".into(),
            kty: "".into(),
            e: "".into(),
            n: "".into(),
            intended_use: "".into(),
        }
    }

    pub fn build(
        kid: String,
        alg: String,
        kty: String,
        e: String,
        n: String,
        intended_use: String,
    ) -> AuthKey {
        AuthKey {
            kid: kid,
            alg: alg,
            kty: kty,
            e: e,
            n: n,
            intended_use: intended_use,
        }
    }
}

struct AuthSet {
    auth_set: HashMap<String, AuthKey>,
}

impl AuthSet {
    pub fn new() -> AuthSet {
        AuthSet {
            auth_set: HashMap::new(),
        }
    }

    pub fn build(auth_set: HashMap<String, AuthKey>) -> AuthSet {
        AuthSet { auth_set: auth_set }
    }

    pub fn insert(&mut self, auth_key: AuthKey) -> Option<AuthKey> {
        self.auth_set.insert(auth_key.kid.clone(), auth_key)
    }
}
