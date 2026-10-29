//! Cedar schema, entity construction and evaluation. Cedar answers yes/no for a
//! concrete request; warden asks it about every catalog entry and compiles the
//! allowed set into the sandbox spec.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, PolicySet, Request,
    RestrictedExpression, Schema, ValidationMode, Validator,
};

use warden_core::{Action, ApiFormat, Decision, Identity, ProviderConfig};

use crate::bundle::{Bundle, Catalog, PolicyError};

pub const SCHEMA: &str = r#"
namespace Warden {
  entity Group;
  entity User in [Group] { email: String };
  entity HarnessSet;
  entity Harness in [HarnessSet];
  entity Provider { format: String, url: String };
  entity Model in [Provider] { tier: String, provider: String };
  entity PathSet;
  entity Path in [PathSet] { path: String, access: String, harness: String };
  entity HostSet;
  entity Host in [HostSet] { host: String, port: Long, purpose: String, harness: String };

  type Ctx = { harness: String, workspace: String, os: String, warden_version: String };

  action launch            appliesTo { principal: User, resource: Harness,  context: Ctx };
  action launchUnsandboxed appliesTo { principal: User, resource: Harness,  context: Ctx };
  action useProvider       appliesTo { principal: User, resource: Provider, context: Ctx };
  action useModel          appliesTo { principal: User, resource: Model,    context: Ctx };
  action readPath          appliesTo { principal: User, resource: Path,     context: Ctx };
  action writePath         appliesTo { principal: User, resource: Path,     context: Ctx };
  action connect           appliesTo { principal: User, resource: Host,     context: Ctx };
}
"#;

pub struct Evaluator {
    schema: Schema,
    policies: PolicySet,
    authorizer: Authorizer,
}

/// Request context, same for every decision in one launch.
#[derive(Debug, Clone)]
pub struct Ctx {
    pub harness: String,
    pub workspace: String,
    pub os: String,
    pub warden_version: String,
}

/// Extra candidates the harness adapter contributes at launch.
#[derive(Debug, Clone, Default)]
pub struct AdapterNeeds {
    /// (host, port, purpose, default_allow)
    pub hosts: Vec<(String, u16, String, bool)>,
    /// (path, access) with access `ro` or `rw`
    pub paths: Vec<(String, String)>,
}

/// Everything the launcher needs after evaluation.
#[derive(Debug, Clone, Default)]
pub struct Effective {
    pub models: Vec<String>,
    pub providers: Vec<String>,
    pub read_only: Vec<String>,
    pub read_write: Vec<String>,
    pub deny_read: Vec<String>,
    /// (host, port)
    pub hosts: Vec<(String, u16)>,
    pub denied_hosts: Vec<(String, u16)>,
}

fn uid(ty: &str, id: &str) -> EntityUid {
    EntityUid::from_type_name_and_id(
        EntityTypeName::from_str(&format!("Warden::{ty}")).expect("static type name"),
        EntityId::new(id),
    )
}

fn s(v: &str) -> RestrictedExpression {
    RestrictedExpression::new_string(v.to_string())
}

impl Evaluator {
    pub fn new(bundle: &Bundle) -> Result<Self, PolicyError> {
        let (schema, _warnings) =
            Schema::from_cedarschema_str(SCHEMA).map_err(|e| PolicyError::Schema(e.to_string()))?;
        let text = bundle.policies.join("\n");
        let policies =
            PolicySet::from_str(&text).map_err(|e| PolicyError::Policy(e.to_string()))?;
        let result = Validator::new(schema.clone()).validate(&policies, ValidationMode::default());
        if !result.validation_passed() {
            let msgs: Vec<String> = result.validation_errors().map(|e| e.to_string()).collect();
            return Err(PolicyError::Validation(msgs.join("; ")));
        }
        Ok(Self {
            schema,
            policies,
            authorizer: Authorizer::new(),
        })
    }

    fn context(&self, ctx: &Ctx, action: &EntityUid) -> Context {
        let v = serde_json::json!({
            "harness": ctx.harness, "workspace": ctx.workspace, "os": ctx.os, "warden_version": ctx.warden_version,
        });
        Context::from_json_value(v, Some((&self.schema, action))).expect("context matches schema")
    }

    pub fn authorize(
        &self,
        entities: &Entities,
        principal: &EntityUid,
        action: Action,
        resource: &EntityUid,
        ctx: &Ctx,
    ) -> Decision {
        let action_uid = uid("Action", action.as_str());
        let req = match Request::new(
            principal.clone(),
            action_uid.clone(),
            resource.clone(),
            self.context(ctx, &action_uid),
            Some(&self.schema),
        ) {
            Ok(r) => r,
            Err(e) => {
                return Decision {
                    allowed: false,
                    policy_ids: vec![],
                    reason: format!("request rejected by schema: {e}"),
                };
            }
        };
        let resp = self
            .authorizer
            .is_authorized(&req, &self.policies, entities);
        let policy_ids: Vec<String> = resp.diagnostics().reason().map(|p| p.to_string()).collect();
        let errors: Vec<String> = resp.diagnostics().errors().map(|e| e.to_string()).collect();
        let allowed = resp.decision() == cedar_policy::Decision::Allow;
        let reason = if !errors.is_empty() {
            format!("evaluation errors: {}", errors.join("; "))
        } else if allowed {
            format!("permitted by {}", policy_ids.join(","))
        } else if policy_ids.is_empty() {
            "no permit policy matched".into()
        } else {
            format!("forbidden by {}", policy_ids.join(","))
        };
        Decision {
            allowed,
            policy_ids,
            reason,
        }
    }

    /// Build the entity store for one launch: catalog + adapter needs + the user.
    pub fn entities(
        &self,
        bundle: &Bundle,
        identity: &Identity,
        needs: &AdapterNeeds,
        harness: &str,
        vars: &BTreeMap<String, String>,
    ) -> Result<Entities, PolicyError> {
        let cat = &bundle.catalog;
        let mut ents: Vec<Entity> = Vec::new();
        let mk = |ty: &str,
                  id: &str,
                  attrs: Vec<(&str, RestrictedExpression)>,
                  parents: Vec<EntityUid>|
         -> Entity {
            let attrs: HashMap<String, RestrictedExpression> =
                attrs.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
            Entity::new(
                uid(ty, id),
                attrs,
                parents.into_iter().collect::<HashSet<_>>(),
            )
            .expect("restricted exprs")
        };

        // user + groups
        let groups: Vec<EntityUid> = identity.groups.iter().map(|g| uid("Group", g)).collect();
        for g in &identity.groups {
            ents.push(mk("Group", g, vec![], vec![]));
        }
        ents.push(mk(
            "User",
            &identity.subject,
            vec![("email", s(identity.email.as_deref().unwrap_or("")))],
            groups,
        ));

        // harnesses
        for set in cat.harness_sets.keys() {
            ents.push(mk("HarnessSet", set, vec![], vec![]));
        }
        for h in &cat.harnesses {
            let parents = cat
                .harness_sets
                .iter()
                .filter(|(_, m)| m.contains(h))
                .map(|(k, _)| uid("HarnessSet", k))
                .collect();
            ents.push(mk("Harness", h, vec![], parents));
        }

        // providers + models
        for p in &bundle.providers {
            let (format, url) = match p {
                ProviderConfig::Static {
                    format, base_url, ..
                } => (format.as_str(), base_url.as_str()),
                ProviderConfig::Litellm { base_url, .. } => {
                    (ApiFormat::Litellm.as_str(), base_url.as_str())
                }
            };
            ents.push(mk(
                "Provider",
                p.id(),
                vec![("format", s(format)), ("url", s(url))],
                vec![],
            ));
        }
        for (id, m) in &cat.models {
            ents.push(mk(
                "Model",
                id,
                vec![("tier", s(&m.tier)), ("provider", s(&m.provider))],
                vec![uid("Provider", &m.provider)],
            ));
        }

        // paths
        for set in cat.path_sets.keys() {
            ents.push(mk("PathSet", set, vec![], vec![]));
        }
        for (id, p) in &cat.paths {
            let path =
                warden_core::template::expand(&p.path, vars).unwrap_or_else(|_| p.path.clone());
            let parents = cat
                .path_sets
                .iter()
                .filter(|(_, m)| m.contains(id))
                .map(|(k, _)| uid("PathSet", k))
                .collect();
            ents.push(mk(
                "Path",
                id,
                vec![
                    ("path", s(&path)),
                    ("access", s(&p.access)),
                    ("harness", s("")),
                ],
                parents,
            ));
        }
        for (i, (path, access)) in needs.paths.iter().enumerate() {
            let id = format!("{harness}:path:{i}");
            ents.push(mk(
                "Path",
                &id,
                vec![
                    ("path", s(path)),
                    ("access", s(access)),
                    ("harness", s(harness)),
                ],
                vec![],
            ));
        }

        // hosts
        for set in cat.host_sets.keys() {
            ents.push(mk("HostSet", set, vec![], vec![]));
        }
        for (id, h) in &cat.hosts {
            let parents = cat
                .host_sets
                .iter()
                .filter(|(_, m)| m.contains(id))
                .map(|(k, _)| uid("HostSet", k))
                .collect();
            ents.push(mk(
                "Host",
                id,
                vec![
                    ("host", s(&h.host)),
                    ("port", RestrictedExpression::new_long(h.port as i64)),
                    ("purpose", s(&h.purpose)),
                    ("harness", s("")),
                ],
                parents,
            ));
        }
        for (i, (host, port, purpose, _)) in needs.hosts.iter().enumerate() {
            let id = format!("{harness}:host:{i}");
            ents.push(mk(
                "Host",
                &id,
                vec![
                    ("host", s(host)),
                    ("port", RestrictedExpression::new_long(*port as i64)),
                    ("purpose", s(purpose)),
                    ("harness", s(harness)),
                ],
                vec![],
            ));
        }

        Entities::from_entities(ents, Some(&self.schema))
            .map_err(|e| PolicyError::Policy(e.to_string()))
    }

    /// Steps 5.ii–5.v of the launch sequence. `launch` itself is checked by the caller.
    pub fn effective(
        &self,
        bundle: &Bundle,
        entities: &Entities,
        identity: &Identity,
        needs: &AdapterNeeds,
        ctx: &Ctx,
        vars: &BTreeMap<String, String>,
    ) -> Effective {
        let cat: &Catalog = &bundle.catalog;
        let principal = uid("User", &identity.subject);
        let mut eff = Effective::default();

        for id in cat.models.keys() {
            if self
                .authorize(
                    entities,
                    &principal,
                    Action::UseModel,
                    &uid("Model", id),
                    ctx,
                )
                .allowed
            {
                eff.models.push(id.clone());
            }
        }
        for p in &bundle.providers {
            if self
                .authorize(
                    entities,
                    &principal,
                    Action::UseProvider,
                    &uid("Provider", p.id()),
                    ctx,
                )
                .allowed
            {
                eff.providers.push(p.id().to_string());
            }
        }
        for (id, p) in &cat.paths {
            let path =
                warden_core::template::expand(&p.path, vars).unwrap_or_else(|_| p.path.clone());
            match p.access.as_str() {
                "deny" => eff.deny_read.push(path),
                "rw" if self
                    .authorize(
                        entities,
                        &principal,
                        Action::WritePath,
                        &uid("Path", id),
                        ctx,
                    )
                    .allowed =>
                {
                    eff.read_write.push(path)
                }
                "rw" | "ro"
                    if self
                        .authorize(
                            entities,
                            &principal,
                            Action::ReadPath,
                            &uid("Path", id),
                            ctx,
                        )
                        .allowed =>
                {
                    eff.read_only.push(path)
                }
                _ => {}
            }
        }
        for (i, (path, access)) in needs.paths.iter().enumerate() {
            let r = uid("Path", &format!("{}:path:{i}", ctx.harness));
            let action = if access == "rw" {
                Action::WritePath
            } else {
                Action::ReadPath
            };
            if self
                .authorize(entities, &principal, action, &r, ctx)
                .allowed
            {
                if access == "rw" {
                    eff.read_write.push(path.clone())
                } else {
                    eff.read_only.push(path.clone())
                }
            }
        }
        for (id, h) in &cat.hosts {
            if self
                .authorize(entities, &principal, Action::Connect, &uid("Host", id), ctx)
                .allowed
            {
                eff.hosts.push((h.host.clone(), h.port));
            } else {
                eff.denied_hosts.push((h.host.clone(), h.port));
            }
        }
        for (i, (host, port, _, default_allow)) in needs.hosts.iter().enumerate() {
            let r = uid("Host", &format!("{}:host:{i}", ctx.harness));
            let d = self.authorize(entities, &principal, Action::Connect, &r, ctx);
            // adapter `default` applies only when no policy mentioned the host at all
            let allow = if d.policy_ids.is_empty() {
                *default_allow
            } else {
                d.allowed
            };
            if allow {
                eff.hosts.push((host.clone(), *port))
            } else {
                eff.denied_hosts.push((host.clone(), *port))
            }
        }
        eff
    }

    pub fn user(&self, identity: &Identity) -> EntityUid {
        uid("User", &identity.subject)
    }
    pub fn harness(&self, id: &str) -> EntityUid {
        uid("Harness", id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::*;
    use secrecy::SecretString;
    use std::time::SystemTime;

    pub(crate) const POLICIES: &str = r#"
permit(principal in Warden::Group::"engineering", action == Warden::Action::"launch", resource in Warden::HarnessSet::"approved");
forbid(principal, action == Warden::Action::"launch", resource == Warden::Harness::"codex") unless { principal in Warden::Group::"codex-pilot" };
forbid(principal, action == Warden::Action::"launch", resource) when { context.os == "windows" };
permit(principal, action == Warden::Action::"useModel", resource) when { resource.tier == "standard" };
permit(principal in Warden::Group::"ml-leads", action == Warden::Action::"useModel", resource) when { resource.tier == "frontier" };
permit(principal, action == Warden::Action::"useProvider", resource);
permit(principal, action == Warden::Action::"writePath", resource == Warden::Path::"workspace");
permit(principal, action == Warden::Action::"readPath", resource in Warden::PathSet::"default-ro");
permit(principal, action == Warden::Action::"connect", resource == Warden::Host::"gw");
permit(principal in Warden::Group::"engineering", action == Warden::Action::"connect", resource in Warden::HostSet::"registries");
permit(principal in Warden::Group::"engineering", action == Warden::Action::"connect", resource in Warden::HostSet::"git") unless { principal in Warden::Group::"contractors" };
forbid(principal, action == Warden::Action::"connect", resource) when { resource.purpose == "telemetry" || resource.purpose == "update-check" };
permit(principal in Warden::Group::"platform-admins", action == Warden::Action::"launchUnsandboxed", resource);
"#;

    pub(crate) fn bundle() -> Bundle {
        let json = serde_json::json!({
            "meta": {"version": "1", "issuer": "test", "issued_at": now_secs() - 10, "not_after": now_secs() + 3600},
            "policies": [POLICIES],
            "identity": {"issuer": "https://idp.example.com", "client_id": "warden"},
            "providers": [{"kind": "litellm", "id": "gw", "base_url": "https://gw.example.com"}],
            "catalog": {
                "harnesses": ["claude-code", "codex", "opencode", "pi"],
                "harness_sets": {"approved": ["claude-code", "codex", "opencode", "pi"]},
                "models": {
                    "claude-sonnet-5": {"provider": "gw", "tier": "standard"},
                    "claude-opus-5-5": {"provider": "gw", "tier": "frontier"}
                },
                "paths": {
                    "workspace": {"path": "${workspace}", "access": "rw"},
                    "home-ro": {"path": "${HOME}", "access": "ro"},
                    "ssh": {"path": "${HOME}/.ssh", "access": "deny"}
                },
                "path_sets": {"default-ro": ["home-ro"]},
                "hosts": {
                    "gw": {"host": "gw.example.com", "purpose": "gateway"},
                    "github": {"host": "github.com", "purpose": "git"},
                    "npm": {"host": "registry.npmjs.org", "purpose": "packages"}
                },
                "host_sets": {"registries": ["npm"], "git": ["github"]}
            }
        });
        serde_json::from_value(json).unwrap()
    }

    fn ident(groups: &[&str]) -> Identity {
        Identity {
            subject: "alice".into(),
            email: Some("alice@example.com".into()),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            id_token: SecretString::from("t"),
            expires_at: SystemTime::now(),
        }
    }

    fn ctx(harness: &str, os: &str) -> Ctx {
        Ctx {
            harness: harness.into(),
            workspace: "/ws".into(),
            os: os.into(),
            warden_version: "0".into(),
        }
    }

    fn vars() -> BTreeMap<String, String> {
        [("workspace", "/ws"), ("HOME", "/home/alice")]
            .map(|(k, v)| (k.into(), v.into()))
            .into()
    }

    fn needs() -> AdapterNeeds {
        AdapterNeeds {
            hosts: vec![
                ("pi.dev".into(), 443, "catalog".into(), false),
                ("models.dev".into(), 443, "catalog".into(), true),
                ("api.github.com".into(), 443, "update-check".into(), true),
            ],
            paths: vec![("/home/alice/.cache/x".into(), "rw".into())],
        }
    }

    #[test]
    fn launch_decisions() {
        let b = bundle();
        let ev = Evaluator::new(&b).unwrap();
        let eng = ident(&["engineering"]);
        let ents = ev.entities(&b, &eng, &needs(), "pi", &vars()).unwrap();
        let u = ev.user(&eng);
        assert!(
            ev.authorize(
                &ents,
                &u,
                Action::Launch,
                &ev.harness("pi"),
                &ctx("pi", "macos")
            )
            .allowed
        );
        let d = ev.authorize(
            &ents,
            &u,
            Action::Launch,
            &ev.harness("codex"),
            &ctx("codex", "macos"),
        );
        assert!(!d.allowed, "{d:?}");
        assert!(
            !ev.authorize(
                &ents,
                &u,
                Action::Launch,
                &ev.harness("pi"),
                &ctx("pi", "windows")
            )
            .allowed
        );
        assert!(
            !ev.authorize(
                &ents,
                &u,
                Action::LaunchUnsandboxed,
                &ev.harness("pi"),
                &ctx("pi", "macos")
            )
            .allowed
        );

        let nobody = ident(&[]);
        let ents2 = ev.entities(&b, &nobody, &needs(), "pi", &vars()).unwrap();
        let d = ev.authorize(
            &ents2,
            &ev.user(&nobody),
            Action::Launch,
            &ev.harness("pi"),
            &ctx("pi", "macos"),
        );
        assert!(!d.allowed);
        assert_eq!(d.reason, "no permit policy matched");

        let pilot = ident(&["engineering", "codex-pilot"]);
        let ents3 = ev.entities(&b, &pilot, &needs(), "codex", &vars()).unwrap();
        assert!(
            ev.authorize(
                &ents3,
                &ev.user(&pilot),
                Action::Launch,
                &ev.harness("codex"),
                &ctx("codex", "linux")
            )
            .allowed
        );
    }

    #[test]
    fn effective_sets() {
        let b = bundle();
        let ev = Evaluator::new(&b).unwrap();
        let eng = ident(&["engineering"]);
        let ents = ev.entities(&b, &eng, &needs(), "pi", &vars()).unwrap();
        let eff = ev.effective(&b, &ents, &eng, &needs(), &ctx("pi", "macos"), &vars());
        assert_eq!(eff.models, ["claude-sonnet-5"]);
        assert_eq!(eff.providers, ["gw"]);
        assert_eq!(eff.read_write, ["/ws"]);
        assert_eq!(eff.read_only, ["/home/alice"]);
        assert_eq!(eff.deny_read, ["/home/alice/.ssh"]);
        let mut hosts = eff.hosts.clone();
        hosts.sort();
        // gw + registries + git from catalog; models.dev by adapter default; pi.dev denied by default;
        // api.github.com forbidden by the update-check rule even though its default is allow
        assert_eq!(
            hosts,
            [
                ("github.com".to_string(), 443),
                ("gw.example.com".into(), 443),
                ("models.dev".into(), 443),
                ("registry.npmjs.org".into(), 443)
            ]
        );
        assert!(
            eff.denied_hosts
                .contains(&("api.github.com".to_string(), 443))
        );
        assert!(eff.denied_hosts.contains(&("pi.dev".to_string(), 443)));

        let lead = ident(&["engineering", "ml-leads", "contractors"]);
        let ents = ev.entities(&b, &lead, &needs(), "pi", &vars()).unwrap();
        let eff = ev.effective(&b, &ents, &lead, &needs(), &ctx("pi", "macos"), &vars());
        assert_eq!(eff.models, ["claude-opus-5-5", "claude-sonnet-5"]);
        assert!(
            !eff.hosts.contains(&("github.com".to_string(), 443)),
            "contractors get no git"
        );
    }

    #[test]
    fn invalid_policy_rejected() {
        let mut b = bundle();
        b.policies =
            vec![r#"permit(principal, action == Warden::Action::"fly", resource);"#.into()];
        assert!(matches!(
            Evaluator::new(&b),
            Err(PolicyError::Validation(_))
        ));
        b.policies = vec!["permit(".into()];
        assert!(matches!(Evaluator::new(&b), Err(PolicyError::Policy(_))));
    }

    #[test]
    fn sign_verify_roundtrip_and_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.bundle");
        std::fs::write(&path, serde_json::to_vec(&bundle()).unwrap()).unwrap();
        let key = crate::sign::keygen();
        crate::sign::sign_file(&path, &key).unwrap();
        let trusted_path = dir.path().join("trusted-keys");
        std::fs::write(
            &trusted_path,
            format!("# org key\n{}\n", key_to_string(&key.verifying_key())),
        )
        .unwrap();
        let trusted = read_trusted_keys(&trusted_path).unwrap();
        let v = load(&path, &trusted).unwrap();
        assert_eq!(v.verified_by, key_to_string(&key.verifying_key()));

        // tamper
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[10] ^= 1;
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            load(&path, &trusted),
            Err(PolicyError::BadSignature)
        ));

        // wrong key
        std::fs::write(&path, serde_json::to_vec(&bundle()).unwrap()).unwrap();
        crate::sign::sign_file(&path, &crate::sign::keygen()).unwrap();
        assert!(matches!(
            load(&path, &trusted),
            Err(PolicyError::BadSignature)
        ));

        // expiry with grace
        let mut b = bundle();
        b.meta.issued_at = 900;
        b.meta.not_after = 1000;
        b.defaults.not_after_grace = std::time::Duration::from_secs(100);
        let bytes = serde_json::to_vec(&b).unwrap();
        assert!(load_verified_bytes(&bytes, "k".into(), 1050).is_ok());
        assert!(matches!(
            load_verified_bytes(&bytes, "k".into(), 1101),
            Err(PolicyError::Expired { .. })
        ));
        assert!(matches!(
            load_verified_bytes(&bytes, "k".into(), 10),
            Err(PolicyError::FromFuture(_))
        ));
    }
}
