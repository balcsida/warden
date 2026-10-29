use std::io::Read;
use std::process::ExitCode;

use crate::{Cli, Fail, PolicyCmd, run};

pub fn dispatch(cli: &Cli, cmd: &PolicyCmd) -> Result<ExitCode, Fail> {
    match cmd {
        PolicyCmd::Keygen => {
            let k = warden_policy::sign::keygen();
            println!(
                "private: {}",
                warden_policy::sign::signing_key_to_string(&k)
            );
            println!(
                "public:  {}",
                warden_policy::key_to_string(&k.verifying_key())
            );
            println!(
                "\nPut the public key in {} (one per line). Keep the private key out of the repo.",
                crate::dirs::system_dir().join("trusted-keys").display()
            );
            Ok(ExitCode::SUCCESS)
        }
        PolicyCmd::Sign { bundle, key } => {
            let key = if key == "-" {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                s
            } else {
                key.clone()
            };
            let sk = warden_policy::sign::parse_signing_key(&key)
                .map_err(|e| Fail::new(crate::EX_USAGE, e))?;
            warden_policy::sign::sign_file(bundle, &sk)
                .map_err(|e| Fail::new(crate::EX_CONFIG, e))?;
            println!("wrote {}.sig", bundle.display());
            Ok(ExitCode::SUCCESS)
        }
        PolicyCmd::Show => {
            let v = run::load_bundle(cli)?;
            let b = &v.bundle;
            println!(
                "bundle:    {}",
                crate::dirs::bundle_path(cli.policy.as_ref()).display()
            );
            println!("version:   {}  issuer: {}", b.meta.version, b.meta.issuer);
            println!(
                "issued:    {}  not_after: {}{}",
                b.meta.issued_at,
                b.meta.not_after,
                if v.is_past_not_after() {
                    "  (PAST not_after; running on grace)"
                } else {
                    ""
                }
            );
            println!("sha256:    {}", v.sha256_hex);
            println!("signed by: {}", v.verified_by);
            println!(
                "identity:  {} client_id={} groups_claim={}",
                b.identity.issuer, b.identity.client_id, b.identity.groups_claim
            );
            println!(
                "providers: {}",
                b.providers
                    .iter()
                    .map(|p| p.id().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!("harnesses: {}", b.catalog.harnesses.join(", "));
            println!(
                "models:    {}",
                b.catalog
                    .models
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!("\n--- policies ---\n{}", b.policies.join("\n"));
            match run::identity(cli, b) {
                Ok(id) => {
                    println!(
                        "\n--- effective for {} (groups: {}) ---",
                        id.subject,
                        id.groups.join(", ")
                    );
                    for h in &b.catalog.harnesses {
                        let (ents, ctx) = run::entities_for(&v, &id, h, &Default::default())?;
                        let d = v.evaluator.authorize(
                            &ents,
                            &v.evaluator.user(&id),
                            warden_core::Action::Launch,
                            &v.evaluator.harness(h),
                            &ctx,
                        );
                        println!(
                            "launch {h:<12} {}  ({})",
                            if d.allowed { "allow" } else { "deny " },
                            d.reason
                        );
                    }
                    let (ents, ctx) = run::entities_for(&v, &id, "none", &Default::default())?;
                    let eff = v.evaluator.effective(
                        b,
                        &ents,
                        &id,
                        &Default::default(),
                        &ctx,
                        &run::vars(),
                    );
                    println!("models:  {}", eff.models.join(", "));
                    println!(
                        "hosts:   {}",
                        eff.hosts
                            .iter()
                            .map(|(h, p)| format!("{h}:{p}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    println!("rw:      {}", eff.read_write.join(", "));
                    println!("deny:    {}", eff.deny_read.join(", "));
                }
                Err(e) => println!("\n(not logged in: {e})"),
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}
