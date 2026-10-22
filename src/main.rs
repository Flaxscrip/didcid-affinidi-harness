//! did:cid through Affinidi's stack, end to end:
//!   1. register a did:cid resolver on `DIDCacheClient` via `set_resolver` (the SDK's
//!      documented plug-in point; no change to Affinidi code),
//!   2. resolve the Archon recipient with it, take the keyAgreement key through
//!      affinidi-did-common's own `decode_public_key`,
//!   3. pack authcrypt with `affinidi-messaging-didcomm` from a did:peer:2 sender,
//!   4. POST the envelope to the published DIDCommMessaging uri as-is.
//! Usage: affinidi-harness <recipient did> [--post]
//! Prints public values only.
use std::future::Future;
use std::pin::Pin;

use affinidi_crypto::jose::key_agreement::{Curve, PrivateKeyAgreement, PublicKeyAgreement};
use affinidi_did_common::{DID, Document, DocumentExt};
use affinidi_did_resolver_cache_sdk::{
    AsyncResolver, DIDCacheClient, MethodName, Resolution, ResolverError,
    config::DIDCacheConfigBuilder,
};
use affinidi_messaging_didcomm::{DIDCommAgent, Message, identity::{PrivateIdentity, ResolvedIdentity}};
use anyhow::{Context, anyhow};
use base64::Engine;
use serde_json::{Value, json};

/// did:cid driver: HTTP to a universal-resolver-compatible endpoint
/// (`<base>/1.0/identifiers/<did>`). dev.uniresolver.io and every Archon
/// gateway serve this shape.
struct CidResolver {
    base: String,
    http: reqwest::Client,
}

/// DID Core allows relative verification-method references ("#key-1"); Archon
/// documents use them for the control key. Make every id absolute so a strict
/// consumer sees whole DID URLs. A resolver wrapper is the right layer for this.
fn absolutize(doc: &mut Value, did: &str) {
    let fix = |v: &mut Value| {
        if let Some(s) = v.as_str()
            && s.starts_with('#')
        {
            *v = Value::String(format!("{did}{s}"));
        }
    };
    if let Some(vms) = doc.get_mut("verificationMethod").and_then(Value::as_array_mut) {
        for vm in vms {
            if let Some(id) = vm.get_mut("id") {
                fix(id);
            }
        }
    }
    for rel in ["authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"] {
        if let Some(refs) = doc.get_mut(rel).and_then(Value::as_array_mut) {
            for r in refs {
                fix(r);
            }
        }
    }
    if let Some(svcs) = doc.get_mut("service").and_then(Value::as_array_mut) {
        for s in svcs {
            if let Some(id) = s.get_mut("id") {
                fix(id);
            }
        }
    }
}

impl AsyncResolver for CidResolver {
    fn name(&self) -> &str {
        "CidResolver"
    }

    fn resolve<'a>(&'a self, did: &'a DID) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            if did.method().name() != "cid" {
                return None;
            }
            let did_str = did.to_string();
            let url = format!("{}/1.0/identifiers/{}", self.base, did_str);
            let result = async {
                let resp = self.http.get(&url).send().await.map_err(|e| ResolverError::ResolutionFailed(e.to_string()))?;
                if !resp.status().is_success() {
                    return Err(ResolverError::ResolutionFailed(format!("{url} -> HTTP {}", resp.status())));
                }
                let body: Value = resp.json().await.map_err(|e| ResolverError::InvalidDocument(e.to_string()))?;
                // Universal-resolver envelope or bare document.
                let mut doc = body.get("didDocument").cloned().unwrap_or(body);
                absolutize(&mut doc, &did_str);
                serde_json::from_value::<Document>(doc).map_err(|e| ResolverError::InvalidDocument(e.to_string()))
            }
            .await;
            Some(result)
        })
    }
}

fn multibase(prefix: &[u8], key: &[u8]) -> String {
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(key);
    format!("z{}", bs58::encode(bytes).into_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let recipient = args.get(1).cloned().ok_or_else(|| anyhow!("usage: affinidi-harness <recipient did> [--post]"))?;
    let post = args.iter().any(|a| a == "--post");
    let resolver_base = std::env::var("RESOLVER_BASE").unwrap_or_else(|_| "https://dev.uniresolver.io".to_string());

    println!("=== 1. DIDCacheClient + did:cid resolver via set_resolver (SDK plug-in point)");
    let mut client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build()).await?;
    client.set_resolver(
        MethodName::Other("cid".to_string()),
        Box::new(CidResolver { base: resolver_base.clone(), http: reqwest::Client::new() }),
    );
    println!("registered CidResolver -> {resolver_base}/1.0/identifiers/<did>");

    println!("\n=== 2. did:peer:2 sender (keys generated here, DID built per the peer DID spec)");
    let ka_private = PrivateKeyAgreement::generate(Curve::X25519);
    let ka_public = ka_private.public_key().to_public_bytes();
    let scratch = PrivateIdentity::generate("did:example:scratch"); // only for an Ed25519 signing key
    let sig_private = scratch.signing_private.context("no signing key")?;
    let sig_public = scratch.verifying_key().context("no verifying key")?;
    let service = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(json!({"t":"dm","s":"https://example.invalid/didcomm","a":["didcomm/v2"]}).to_string());
    let sender_did = format!(
        "did:peer:2.E{}.V{}.S{}",
        multibase(&[0xec, 0x01], &ka_public),
        multibase(&[0xed, 0x01], &sig_public),
        service
    );
    println!("sender = {sender_did}");
    // Self-check with the SDK's own did:peer resolver: #key-1 must be our X25519 key.
    let peer_doc = client.resolve(&sender_did).await?.doc;
    let peer_ka = peer_doc.find_key_agreement(None);
    println!("SDK resolves sender; keyAgreement = {peer_ka:?}");
    let sender = PrivateIdentity {
        did: sender_did.clone(),
        key_agreement_kid: format!("{sender_did}#key-1"),
        key_agreement_private: ka_private,
        signing_kid: Some(format!("{sender_did}#key-2")),
        signing_private: Some(sig_private),
    };

    println!("\n=== 3. resolve the did:cid recipient through the SDK");
    let resolved = client.resolve(&recipient).await.context("SDK resolve of did:cid failed")?;
    let doc: Document = resolved.doc;
    println!("method = {:?}, cache_hit = {}", resolved.method, resolved.cache_hit);
    let doc_json = serde_json::to_value(&doc)?;
    let vm_types: Vec<String> = doc_json["verificationMethod"].as_array().unwrap_or(&vec![]).iter()
        .map(|vm| format!("{}:{}", vm["id"].as_str().unwrap_or("?").replace(&recipient, ""), vm["type"].as_str().unwrap_or("?")))
        .collect();
    println!("verification methods = {vm_types:?}");
    let kids = doc.find_key_agreement(None);
    let kid = kids.first().copied().ok_or_else(|| anyhow!("recipient has no keyAgreement"))?.to_string();
    let vm = doc.get_verification_method(&kid).ok_or_else(|| anyhow!("keyAgreement VM {kid} not found"))?;
    let (codec, bytes) = vm.decode_public_key().map_err(|e| anyhow!("decode_public_key: {e}"))?;
    println!("keyAgreement kid = {kid}, type = {}, multicodec = 0x{codec:x}, {} bytes", vm.type_, bytes.len());
    let curve = match codec {
        0xec => Curve::X25519,
        0x1200 => Curve::P256,
        other => return Err(anyhow!("unsupported key-agreement codec 0x{other:x}")),
    };
    let ka_pub = PublicKeyAgreement::from_raw_bytes(curve, &bytes).map_err(|e| anyhow!("from_raw_bytes: {e}"))?;
    println!("service, as the SDK's Document serialises it = {}", doc_json["service"]);
    let pick = |services: &Value| services.as_array().unwrap_or(&vec![]).iter()
        .find(|s| s["type"] == "DIDCommMessaging" || s["type"].as_array().is_some_and(|t| t.iter().any(|x| x == "DIDCommMessaging"))) // the SDK normalises `type` to an array
        .and_then(|s| s["serviceEndpoint"]["uri"].as_str().or_else(|| s["serviceEndpoint"].as_str()).map(str::to_string));
    let endpoint = match pick(&doc_json["service"]) {
        Some(uri) => uri,
        None => {
            // Fall back to the document as the resolver served it, to tell a lost service from a renamed one.
            let raw: Value = reqwest::Client::new().get(format!("{resolver_base}/1.0/identifiers/{recipient}")).send().await?.json().await?;
            let raw_doc = raw.get("didDocument").cloned().unwrap_or(raw);
            println!("service, as the resolver served it = {}", raw_doc["service"]);
            pick(&raw_doc["service"]).ok_or_else(|| anyhow!("no DIDCommMessaging service in either form"))?
        }
    };
    println!("DIDCommMessaging uri = {endpoint}");

    println!("\n=== 4. pack authcrypt with affinidi-messaging-didcomm");
    let mut agent = DIDCommAgent::new();
    agent.add_identity(sender);
    agent.add_peer(ResolvedIdentity::new(recipient.clone(), kid.clone(), ka_pub));
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let msg = Message::new(
        "https://didcomm.org/basicmessage/2.0/message",
        json!({"content": format!("Hello from Affinidi's DIDComm engine via a did:cid resolver plug-in, {now}")}),
    )
    .from(sender_did.clone())
    .to(vec![recipient.clone()])
    .created_time(now);
    let jwe = agent.pack_authcrypt(&msg, &sender_did, &recipient).map_err(|e| anyhow!("pack_authcrypt: {e}"))?;
    let env: Value = serde_json::from_str(&jwe)?;
    let protected: Value = serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(env["protected"].as_str().unwrap_or(""))?)?;
    println!("alg = {}, enc = {}, skid = {}...", protected["alg"], protected["enc"], protected["skid"].as_str().unwrap_or("").chars().take(40).collect::<String>());
    println!("recipient kid = {}", env["recipients"][0]["header"]["kid"]);
    std::fs::write("affinidi-envelope.json", &jwe)?;
    std::fs::write("affinidi-sender.txt", &sender_did)?;

    if !post {
        println!("\n(no --post) envelope written to affinidi-envelope.json");
        return Ok(());
    }
    println!("\n=== 5. POST to the published uri as-is");
    let resp = reqwest::Client::new()
        .post(&endpoint)
        .header("content-type", "application/didcomm-encrypted+json")
        .body(jwe)
        .send()
        .await?;
    let status = resp.status();
    let body = resp.text().await?;
    println!("POST {endpoint} -> HTTP {status}: {}", body.chars().take(200).collect::<String>());
    Ok(())
}
