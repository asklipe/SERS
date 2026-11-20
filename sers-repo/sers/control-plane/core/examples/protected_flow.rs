//! Demonstração ponta a ponta, em memória, do fluxo de autorização do SERS.
//!
//! Executar: `cargo run -p sers-controlplane --example protected_flow`
//!
//! Tudo roda no mesmo processo: publicador, Control Plane e cliente. Não há rede,
//! TLS nem TEE. O objetivo é mostrar a lógica de autorização e de liberação de chave.

use sers_controlplane::{
    AuthorizationDecision, ClientBackendClaim, ControlPlane, ControlPlaneConfig,
    LocalDevKeyProvider, UnsupportedAttestationVerifier,
};
use sers_core::{
    ApplicationId, Digest32, ExecutionPolicy, LicenseId, ModuleId, SersError, TenantId,
    X25519PublicKey,
};
use sers_crypto::{kex::EphemeralKeyPair, secret::SymmetricKey, sign::SigningKeyPair};
use sers_identity::InstallationIdentity;
use sers_package::{PackageBuilder, RawPackage};
use sers_protocol::{
    open_key_release, Challenge, ChallengeRequest, KeyReleaseContext, PROTOCOL_VERSION,
};
use std::time::{SystemTime, UNIX_EPOCH};

const SECRET: &[u8] = b"logica sensivel de exemplo";

struct Deployed {
    app: ApplicationId,
    package: Vec<u8>,
    digest: Digest32,
    license: LicenseId,
}

fn deploy(
    cp: &ControlPlane,
    tenant: &TenantId,
    publisher: &SigningKeyPair,
    name: &str,
    policy: ExecutionPolicy,
    now: u64,
) -> Result<Deployed, SersError> {
    let app = ApplicationId::new(name)?;
    cp.register_application(tenant, app.clone(), policy, &[publisher.public_key()], now)?;
    let package_key = SymmetricKey::generate()?;
    let mut builder = PackageBuilder::new(app.clone(), "1.0.0", 1, policy, now)?;
    builder.add_module(ModuleId::new("core")?, 1, SECRET.to_vec())?;
    let package = builder.build(publisher, &package_key)?;
    cp.register_package(tenant, &app, &package, &package_key, now)?;
    let digest = RawPackage::parse(&package)?.manifest_digest();
    let license = cp.create_license(tenant, &app, None, 1, now)?;
    Ok(Deployed {
        app,
        package,
        digest,
        license,
    })
}

fn authorize(
    cp: &ControlPlane,
    identity: &InstallationIdentity,
    d: &Deployed,
    now: u64,
) -> Result<(AuthorizationDecision, Challenge, EphemeralKeyPair), SersError> {
    let ephemeral = EphemeralKeyPair::generate();
    let request = ChallengeRequest {
        version: PROTOCOL_VERSION,
        application_id: d.app.clone(),
        installation_id: identity.id(),
        package_digest: d.digest,
        client_ephemeral_key: X25519PublicKey::from_bytes(ephemeral.public_key()),
    };
    let challenge = cp.request_challenge(&request, now)?;
    let response = identity.respond_to(&challenge)?;
    let claim = ClientBackendClaim {
        process_isolation: true,
    };
    let decision = cp.authorize(&response, &claim, None, now + 1)?;
    Ok((decision, challenge, ephemeral))
}

fn main() -> Result<(), SersError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let cp = ControlPlane::new(
        ControlPlaneConfig::default(),
        Box::new(LocalDevKeyProvider::generate()?),
        Box::new(SigningKeyPair::generate()?),
        Box::new(UnsupportedAttestationVerifier),
    )?;
    let tenant = TenantId::new("acme")?;
    cp.create_tenant(tenant.clone(), now)?;
    let publisher = SigningKeyPair::generate()?;

    println!("1. O publicador cria um pacote .sers com um modulo cifrado");
    let d = deploy(&cp, &tenant, &publisher, "acme.editor", ExecutionPolicy::SoftwareAllowed, now)?;
    let visible = d.package.windows(SECRET.len()).any(|w| w == SECRET);
    println!("   pacote: {} bytes; texto do modulo visivel no arquivo: {visible}", d.package.len());

    println!("2. Uma instalacao registra sua chave (prova de posse) com uma licenca");
    let identity = InstallationIdentity::generate()?;
    cp.register_installation(&identity.registration_request(&d.app), &d.license, now)?;
    println!("   instalacao: {}", identity.id());

    println!("3. Desafio e resposta; o Control Plane decide");
    let (decision, challenge, ephemeral) = authorize(&cp, &identity, &d, now)?;
    let grant = match decision {
        AuthorizationDecision::Granted(grant) => grant,
        other => {
            println!("   decisao inesperada: {other:?}");
            return Err(SersError::PolicyDenied("authorization was not granted"));
        }
    };
    let installation_id = identity.id();
    grant.authorization.verify(
        &cp.authorization_public_key(),
        &d.app,
        &installation_id,
        &d.digest,
        now + 2,
    )?;
    println!("   concedido; autorizacao assinada e valida para esta instalacao e este pacote");

    println!("4. A chave do pacote chega selada para esta sessao e o modulo e decifrado");
    let ctx = KeyReleaseContext {
        nonce: &challenge.nonce,
        application_id: &d.app,
        installation_id: &installation_id,
        package_digest: &d.digest,
    };
    let key = open_key_release(&ctx, ephemeral, &grant.key_release)?;
    let verified = RawPackage::parse(&d.package)?.verify(&publisher.public_key())?;
    let plaintext = verified.decrypt_module(&key, &ModuleId::new("core")?)?;
    println!("   modulo: {}", String::from_utf8_lossy(&plaintext));

    println!("5. Revogar a instalacao impede novas autorizacoes");
    cp.revoke_installation(&tenant, &installation_id, now + 3)?;
    match authorize(&cp, &identity, &d, now + 4) {
        Err(e) => println!("   recusado: {e}"),
        Ok((decision, _, _)) => println!("   INESPERADO: {decision:?}"),
    }

    println!("6. Aplicacao com politica hardware_required falha fechada (nenhum TEE e suportado)");
    let strict = deploy(&cp, &tenant, &publisher, "acme.secure", ExecutionPolicy::HardwareRequired, now)?;
    let other = InstallationIdentity::generate()?;
    cp.register_installation(&other.registration_request(&strict.app), &strict.license, now)?;
    let (decision, _, _) = authorize(&cp, &other, &strict, now + 5)?;
    println!("   decisao: {decision:?}");

    println!("7. Trilha de auditoria: {} eventos, cadeia integra: {}",
        cp.audit_events().len(), cp.verify_audit_chain());
    Ok(())
}
