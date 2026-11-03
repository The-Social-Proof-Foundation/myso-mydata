// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

//! zkLogin session-key certificates.
//!
//! A zkLogin account has no key whose address is the account address, so its certificate
//! signature is the full zkLogin signature (the ephemeral key's signature wrapped in the proof).
//! It is verified in-process under the rules validators apply:
//! - MySo's own Groth16 key (`ZkloginVerifier::new_myso`, exported from the MySo prover's zkey),
//!   not the upstream key;
//! - the claimed `user` must be an address the proof derives;
//! - the issuer's currently published JWK (Google and Apple, the providers the prover serves);
//! - `max_epoch` within the current epoch window.
//!
//! Anything unavailable (JWKS, current epoch) fails closed.

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use std::borrow::Cow;

use myso_crypto::zklogin::ZkloginVerifier;
use myso_crypto::MySoVerifier;
use myso_sdk_types::{Jwk as JWK, JwkId, PersonalMessage, UserSignature};
use myso_types::base_types::MySoAddress;
use myso_types::signature::GenericSignature;

type ImHashMap<K, V> = HashMap<K, V>;

/// OIDC providers whose keys are accepted: `(issuer, JWKS URL)`. Each issuer also matches
/// without its `https://` prefix.
const JWK_PROVIDERS: &[(&str, &str)] = &[
    (
        "https://accounts.google.com",
        "https://www.googleapis.com/oauth2/v3/certs",
    ),
    (
        "https://appleid.apple.com",
        "https://appleid.apple.com/auth/keys",
    ),
];

/// An unknown key id triggers at most one JWKS fetch per issuer this often.
const JWK_REFETCH_INTERVAL: Duration = Duration::from_secs(60);

/// Current epoch is re-read from the fullnode at most this often.
const EPOCH_TTL: Duration = Duration::from_secs(30);

/// Protocol config `zklogin_max_epoch_upper_bound_delta`.
const MAX_EPOCH_UPPER_BOUND_DELTA: u64 = 30;

/// The certificate signature as an SDK zkLogin signature, if it is one.
fn as_zklogin(signature: &GenericSignature) -> Option<UserSignature> {
    if !matches!(signature, GenericSignature::ZkLoginAuthenticator(_)) {
        return None;
    }
    match UserSignature::from_bytes(signature.as_ref()) {
        Ok(sig @ UserSignature::ZkLogin(_)) => Some(sig),
        _ => None,
    }
}

/// Validators' epoch rule: live through `max_epoch`, at most `MAX_EPOCH_UPPER_BOUND_DELTA` ahead.
fn check_epoch_window(max_epoch: u64, current: u64) -> Result<(), String> {
    if current > max_epoch {
        return Err(format!(
            "zkLogin proof expired: max epoch {max_epoch} is before current epoch {current}"
        ));
    }
    if max_epoch - current > MAX_EPOCH_UPPER_BOUND_DELTA {
        return Err(format!(
            "zkLogin max epoch {max_epoch} is too far past current epoch {current}"
        ));
    }
    Ok(())
}

/// Checks `signature` (a zkLogin authenticator) over the personal message `message` for `user`
/// at `current_epoch` with `jwks`.
pub fn verify_zklogin_personal_message(
    signature: &GenericSignature,
    message: &[u8],
    user: MySoAddress,
    current_epoch: u64,
    jwks: ImHashMap<JwkId, JWK>,
) -> Result<(), String> {
    let sig = as_zklogin(signature).ok_or_else(|| "not a zkLogin signature".to_string())?;
    let UserSignature::ZkLogin(zk) = &sig else {
        unreachable!()
    };

    let user = user.to_string();
    if !zk
        .derive_address()
        .any(|address| address.to_string().eq_ignore_ascii_case(&user))
    {
        return Err("zkLogin proof is for a different address".to_string());
    }
    check_epoch_window(zk.max_epoch, current_epoch)?;

    let mut verifier = ZkloginVerifier::new_myso();
    *verifier.jwks_mut() = jwks;
    verifier
        .verify_personal_message(&PersonalMessage(Cow::Borrowed(message)), &sig)
        .map_err(|e| format!("zkLogin proof rejected: {e}"))
}

/// Issuer and key id the proof was made against.
pub fn jwk_id(signature: &GenericSignature) -> Option<JwkId> {
    match as_zklogin(signature)? {
        UserSignature::ZkLogin(zk) => Some(zk.inputs.jwk_id().clone()),
        _ => None,
    }
}

fn provider_jwks_url(iss: &str) -> Option<&'static str> {
    JWK_PROVIDERS.iter().find_map(|(issuer, url)| {
        let bare = issuer.trim_start_matches("https://");
        (iss == *issuer || iss == bare).then_some(*url)
    })
}

/// RSA keys from a JWKS document, as `(kid, key)`.
fn parse_jwks(json: &serde_json::Value) -> Vec<(String, JWK)> {
    let Some(keys) = json.get("keys").and_then(|k| k.as_array()) else {
        return Vec::new();
    };
    keys.iter()
        .filter_map(|key| {
            let field = |name: &str| key.get(name).and_then(|v| v.as_str()).map(str::to_string);
            if field("kty")? != "RSA" {
                return None;
            }
            Some((
                field("kid")?,
                JWK {
                    kty: "RSA".to_string(),
                    e: field("e")?,
                    n: field("n")?,
                    alg: field("alg").unwrap_or_else(|| "RS256".to_string()),
                },
            ))
        })
        .collect()
}

/// JWK and epoch caches for zkLogin certificate checks.
pub struct ZkLoginCertVerifier {
    http: reqwest::Client,
    jwks: RwLock<ImHashMap<JwkId, JWK>>,
    last_fetch: Mutex<HashMap<String, Instant>>,
    epoch: Mutex<Option<(u64, Instant)>>,
}

impl Default for ZkLoginCertVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ZkLoginCertVerifier {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .unwrap_or_default();
        Self {
            http,
            jwks: RwLock::new(HashMap::new()),
            last_fetch: Mutex::new(HashMap::new()),
            epoch: Mutex::new(None),
        }
    }

    /// Verifies a zkLogin certificate signature. `fetch_epoch` reads the current epoch from
    /// the fullnode; its result is cached for `EPOCH_TTL`.
    pub async fn verify<F, Fut>(
        &self,
        signature: &GenericSignature,
        message: &[u8],
        user: MySoAddress,
        fetch_epoch: F,
    ) -> Result<(), String>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<u64, String>>,
    {
        let id = jwk_id(signature).ok_or_else(|| "not a zkLogin signature".to_string())?;
        let epoch = self.current_epoch(fetch_epoch).await?;
        self.ensure_jwk(&id).await?;
        let jwks = self.jwks.read().unwrap_or_else(|e| e.into_inner()).clone();
        verify_zklogin_personal_message(signature, message, user, epoch, jwks)
    }

    async fn current_epoch<F, Fut>(&self, fetch_epoch: F) -> Result<u64, String>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<u64, String>>,
    {
        if let Some((epoch, at)) = *self.epoch.lock().unwrap_or_else(|e| e.into_inner()) {
            if at.elapsed() < EPOCH_TTL {
                return Ok(epoch);
            }
        }
        let epoch = fetch_epoch().await.map_err(|e| format!("current epoch: {e}"))?;
        *self.epoch.lock().unwrap_or_else(|e| e.into_inner()) = Some((epoch, Instant::now()));
        Ok(epoch)
    }

    fn has_jwk(&self, id: &JwkId) -> bool {
        self.jwks
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(id)
    }

    async fn ensure_jwk(&self, id: &JwkId) -> Result<(), String> {
        if self.has_jwk(id) {
            return Ok(());
        }
        let url = provider_jwks_url(&id.iss)
            .ok_or_else(|| format!("zkLogin issuer not supported: {}", id.iss))?;
        let due = {
            let mut last = self.last_fetch.lock().unwrap_or_else(|e| e.into_inner());
            let due = last
                .get(&id.iss)
                .is_none_or(|at| at.elapsed() >= JWK_REFETCH_INTERVAL);
            if due {
                last.insert(id.iss.clone(), Instant::now());
            }
            due
        };
        if due {
            let keys = self.fetch_jwks(url).await?;
            let mut jwks = self.jwks.write().unwrap_or_else(|e| e.into_inner());
            for (kid, jwk) in keys {
                jwks.insert(JwkId {
                    iss: id.iss.clone(),
                    kid,
                }, jwk);
            }
        }
        if self.has_jwk(id) {
            Ok(())
        } else {
            Err(format!("zkLogin key {} is not published by {}", id.kid, id.iss))
        }
    }

    async fn fetch_jwks(&self, url: &str) -> Result<Vec<(String, JWK)>, String> {
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| format!("JWKS fetch: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("JWKS HTTP {}", response.status()));
        }
        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("JWKS body: {e}"))?;
        Ok(parse_jwks(&json))
    }

    #[cfg(test)]
    fn insert_jwk(&self, id: JwkId, jwk: JWK) {
        self.jwks.write().unwrap().insert(id, jwk);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto::traits::ToFromBytes;
    use std::str::FromStr;

    /// A real iOS zkLogin personal-message signature (Google, MySo prover) for `0x6b27…`.
    const ADDRESS: &str = "0x6b27c51107b378c9a1c6f1b471e43407d3027e8485464b0f7e9be8d196cbd8e0";
    const SIGNATURE_HEX: &str = "05034d32303830353033363235363531323036333136353735323430353532363235343930373036333234393831303536333033313534333536323638393233333734333831323635303230333232334d3135313236343938323235363532303636333332333033383234383539333034343939383136363334353535373734333038373336333930383538353636333938363138303537353438303734013103024c353830323537363737323938393637393639343036303036333133373331333038333732353439313134333735333132303230343135383939393130393539323834383439383138343336364d3130373138393235373339393233393932333132363432333236343534343133353735313233353636393337363234353230373432303334373434313830373433303734303531323139373830024d31383933363831363230383236303639333939343832313037363935323132333431323836343030333235333033313036343031323439373632373830393133333237383338383533363132344d32303032373530373332353636303432383031393535363139383232363234353136303930363533363630383436323532393337363538303136323938363230363839333834363735373434380201310130034c353332323233373230393539323539303434303835323736363438343433383635363730393735303037323639393332343733353931333338373136383032313833393839313239393337394d3133373731303134323639383136383033323632383337323834343335393839333938383135323935363730353136373931323030343236383139313739303337333838353731323337393337013131794a7063334d694f694a6f64485277637a6f764c32466a59323931626e527a4c6d6476623264735a53356a623230694c43016665794a68624763694f694a53557a49314e694973496d74705a434936496a6b304d32457a5954566b4e3251354d546b324d6a56684e4455305a5451344f5749334e574d794f57466b595749314e32466a596d45694c434a30655841694f694a4b5631516966514d31323033353135353835393434303739383133383638303433343034313432323530303535303130373631323930323439303033333339363035313031323939323931333030323931343937381300000000000000610026cf5058cbeb1c2a43a8e816402f30513c1ee9c6f6de92f709585ff9404c852c8b06b47fdfb92d2eda5c4cf96a8dfa04e364dcadc3bacdb0a6528ffe50e3e20391de655797f267e1973e23fc2ddd3cae716db16a27265faea7bab384224772d3";
    const GOOGLE_KID: &str = "943a3a5d7d919625a454e489b75c29adab57acba";
    const GOOGLE_N: &str = "pIpnzA2ezyEERJSxiqpLBmMeIqATH-V6iuBtKIibXEyYovujrx8niqTeO6RIyXT6uDUUv0V2kJ8V_iWYFxzXY1BqK9IfcAmjg0XUDoyTVkoyLsF0gj299LH-zw5vCvy8jmamFIZKAbKcQ5hpHvSittM1vl-6vVL-i2GxyGbMA9aY6Hq15NylS1t7ELTYfQimlnvxcb7_DM0cuS5U1SfbCZMCpKhh0nrSlYds240oxpCJOV2rBahs_Ea5c7tezS1nwVC9W_E-bR9TF6BHkC_fv-E8DcWfkI_6geaJzBhINNxBfjx-w1-WUp2Jz3YYFWEfeQjxMqu-Fg6cGxwk7V16uQ";

    fn message() -> Vec<u8> {
        format!("1793688229:{ADDRESS}").into_bytes()
    }

    fn signature() -> (GenericSignature, u64) {
        let sig = GenericSignature::from_bytes(&hex::decode(SIGNATURE_HEX).unwrap()).unwrap();
        let UserSignature::ZkLogin(zk) = as_zklogin(&sig).expect("zkLogin") else {
            unreachable!()
        };
        (sig, zk.max_epoch)
    }

    fn google_jwks() -> ImHashMap<JwkId, JWK> {
        let mut jwks = ImHashMap::new();
        jwks.insert(
            JwkId {
                iss: "https://accounts.google.com".into(),
                kid: GOOGLE_KID.into(),
            },
            JWK {
                kty: "RSA".into(),
                e: "AQAB".into(),
                n: GOOGLE_N.into(),
                alg: "RS256".into(),
            },
        );
        jwks
    }

    fn user() -> MySoAddress {
        MySoAddress::from_str(ADDRESS).unwrap()
    }

    #[test]
    fn real_myso_proof_verifies() {
        let (sig, max_epoch) = signature();
        verify_zklogin_personal_message(&sig, &message(), user(), max_epoch, google_jwks())
            .unwrap();
    }

    #[test]
    fn wrong_message_is_rejected() {
        let (sig, max_epoch) = signature();
        assert!(verify_zklogin_personal_message(
            &sig,
            b"another message",
            user(),
            max_epoch,
            google_jwks()
        )
        .is_err());
    }

    #[test]
    fn wrong_user_is_rejected() {
        let (sig, max_epoch) = signature();
        let other = MySoAddress::from_str(&format!("0x{}", "ab".repeat(32))).unwrap();
        assert!(
            verify_zklogin_personal_message(&sig, &message(), other, max_epoch, google_jwks())
                .is_err()
        );
    }

    #[test]
    fn expired_proof_is_rejected() {
        let (sig, max_epoch) = signature();
        assert!(verify_zklogin_personal_message(
            &sig,
            &message(),
            user(),
            max_epoch + 1,
            google_jwks()
        )
        .is_err());
    }

    #[test]
    fn missing_jwk_is_rejected() {
        let (sig, max_epoch) = signature();
        assert!(verify_zklogin_personal_message(
            &sig,
            &message(),
            user(),
            max_epoch,
            HashMap::new()
        )
        .is_err());
    }

    #[test]
    fn epoch_window_matches_validators() {
        assert!(check_epoch_window(10, 10).is_ok());
        assert!(check_epoch_window(10 + MAX_EPOCH_UPPER_BOUND_DELTA, 10).is_ok());
        assert!(check_epoch_window(11 + MAX_EPOCH_UPPER_BOUND_DELTA, 10).is_err());
        assert!(check_epoch_window(9, 10).is_err());
    }

    #[test]
    fn plain_signatures_are_not_zklogin() {
        let plain = GenericSignature::from_bytes(&[0u8; 97]);
        if let Ok(plain) = plain {
            assert!(jwk_id(&plain).is_none());
        }
    }

    #[tokio::test]
    async fn cached_verifier_uses_its_epoch_and_jwks() {
        let (sig, max_epoch) = signature();
        let verifier = ZkLoginCertVerifier::new();
        for (id, jwk) in google_jwks() {
            verifier.insert_jwk(id, jwk);
        }
        verifier
            .verify(&sig, &message(), user(), || async move { Ok(max_epoch) })
            .await
            .unwrap();
        // Epoch is cached: a failing fetch isn't consulted again within the TTL.
        verifier
            .verify(&sig, &message(), user(), || async { Err("down".to_string()) })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn epoch_unavailable_fails_closed() {
        let (sig, _) = signature();
        let verifier = ZkLoginCertVerifier::new();
        for (id, jwk) in google_jwks() {
            verifier.insert_jwk(id, jwk);
        }
        assert!(verifier
            .verify(&sig, &message(), user(), || async { Err("down".to_string()) })
            .await
            .is_err());
    }

    #[test]
    fn only_allow_listed_issuers() {
        assert!(provider_jwks_url("https://accounts.google.com").is_some());
        assert!(provider_jwks_url("accounts.google.com").is_some());
        assert!(provider_jwks_url("https://appleid.apple.com").is_some());
        assert!(provider_jwks_url("https://evil.example").is_none());
    }

    #[test]
    fn jwks_parsing_keeps_rsa_keys() {
        let json = serde_json::json!({"keys": [
            {"kid": "a", "kty": "RSA", "e": "AQAB", "n": "xyz", "alg": "RS256"},
            {"kid": "b", "kty": "EC", "crv": "P-256"},
        ]});
        let keys = parse_jwks(&json);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "a");
    }
}
