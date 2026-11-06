//! Source-IP filtering: manual block/allow rules (CIDR, IPv4 and IPv6),
//! an optional allowlist mode, and automatic temporary bans after repeated
//! authentication failures or repeated anonymous requests that were denied
//! (scanners probing for buckets such as `.env` or `.git`).
//!
//! Evaluation order for a client address:
//! 1. loopback is always allowed (the local healthcheck and an admin on the
//!    server itself can never be locked out);
//! 2. a matching *allow* rule lets the request through (and exempts the
//!    address from automatic bans);
//! 3. an active automatic ban denies;
//! 4. a matching *block* rule denies;
//! 5. in allowlist mode, anything not explicitly allowed is denied.
//!
//! Rules are persisted in the index and on every disk; automatic bans live in
//! memory and end on restart. `BOXSPACE_IP_FILTER=off` disables filtering.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, RwLock,
    },
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct Rule {
    /// Address or CIDR range, e.g. `203.0.113.7`, `10.0.0.0/8`, `2001:db8::/32`.
    pub cidr: String,
    /// "block" or "allow".
    pub action: String,
    /// "all", "api" or "console".
    pub scope: String,
    pub note: String,
    pub created: Option<DateTime<Utc>>,
    pub expires: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct AutoBan {
    pub enabled: bool,
    /// Failed authentications within `window_secs` that trigger a ban.
    pub max_failures: u32,
    /// Anonymous requests refused with AccessDenied within `window_secs` that
    /// trigger a ban. 0 disables this check.
    pub max_denied: u32,
    pub window_secs: u64,
    pub ban_secs: u64,
}

impl Default for AutoBan {
    fn default() -> Self {
        AutoBan { enabled: true, max_failures: 10, max_denied: 30, window_secs: 300, ban_secs: 900 }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct IpConfig {
    /// "blocklist" (default) or "allowlist".
    pub mode: String,
    pub rules: Vec<Rule>,
    pub auto: AutoBan,
}

impl Default for IpConfig {
    fn default() -> Self {
        IpConfig { mode: "blocklist".into(), rules: Vec::new(), auto: AutoBan::default() }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Surface {
    Api,
    Console,
}

/// A parsed network: address bits (IPv4 in the low 32 bits) and prefix length.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Net {
    addr: u128,
    bits: u8,
    v4: bool,
}

fn bits_of(ip: IpAddr) -> (u128, bool) {
    match ip.to_canonical() {
        IpAddr::V4(a) => (u32::from(a) as u128, true),
        IpAddr::V6(a) => (u128::from(a), false),
    }
}

fn mask(bits: u8, v4: bool) -> u128 {
    let width = if v4 { 32 } else { 128 };
    if bits == 0 {
        0
    } else if v4 {
        (u32::MAX << (width - bits as u32)) as u128
    } else {
        u128::MAX << (width - bits as u32)
    }
}

impl Net {
    pub fn parse(s: &str) -> Result<Net, String> {
        let s = s.trim();
        let (addr, len) = match s.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (s, None),
        };
        let ip: IpAddr = addr.trim().parse().map_err(|_| format!("endereço IP inválido: {s}"))?;
        let (raw, v4) = bits_of(ip);
        let width = if v4 { 32 } else { 128 };
        let bits = match len {
            None => width,
            Some(l) => {
                let b: u32 = l.trim().parse().map_err(|_| format!("tamanho de prefixo inválido: {s}"))?;
                // An IPv4-mapped IPv6 prefix (::ffff:a.b.c.d/120) maps to IPv4 /24.
                let b = if v4 && matches!(ip, IpAddr::V6(_)) { b.checked_sub(96).ok_or(format!("prefixo inválido: {s}"))? } else { b };
                if b > width {
                    return Err(format!("o prefixo de {s} passa de /{width}"));
                }
                b
            }
        };
        Ok(Net { addr: raw & mask(bits as u8, v4), bits: bits as u8, v4 })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let (raw, v4) = bits_of(ip);
        v4 == self.v4 && raw & mask(self.bits, v4) == self.addr
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BanInfo {
    pub ip: String,
    pub since: DateTime<Utc>,
    pub until: DateTime<Utc>,
    pub failures: u32,
    /// "auth" (wrong credentials) or "denied" (anonymous requests refused).
    pub reason: String,
}

/// What kind of strike is being counted against an address.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Strike {
    /// Wrong signature, unknown access key or failed console login.
    Auth,
    /// Anonymous request refused with AccessDenied.
    Denied,
}

struct Ban {
    until: Instant,
    info: BanInfo,
}

struct Compiled {
    cfg: IpConfig,
    nets: Vec<(Net, Rule)>,
}

pub struct IpFilter {
    disabled: bool,
    compiled: RwLock<Compiled>,
    failures: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    denied: Mutex<HashMap<IpAddr, Vec<Instant>>>,
    bans: Mutex<HashMap<IpAddr, Ban>>,
    logged: Mutex<HashMap<IpAddr, Instant>>,
    pub blocked_total: AtomicU64,
    pub bans_total: AtomicU64,
}

fn scope_matches(scope: &str, s: Surface) -> bool {
    match scope {
        "api" => s == Surface::Api,
        "console" => s == Surface::Console,
        _ => true,
    }
}

/// Validate a configuration and compile its rules.
pub fn compile(cfg: &IpConfig) -> Result<Vec<(Net, Rule)>, String> {
    if !matches!(cfg.mode.as_str(), "blocklist" | "allowlist") {
        return Err("modo deve ser blocklist ou allowlist".into());
    }
    if cfg.rules.len() > 10_000 {
        return Err("no máximo 10.000 regras".into());
    }
    let a = &cfg.auto;
    if a.enabled && (a.max_failures == 0 || a.window_secs == 0 || a.ban_secs == 0) {
        return Err("os valores do bloqueio automático devem ser maiores que zero".into());
    }
    let mut out = Vec::with_capacity(cfg.rules.len());
    for r in &cfg.rules {
        if !matches!(r.action.as_str(), "block" | "allow") {
            return Err(format!("ação inválida na regra {}: use block ou allow", r.cidr));
        }
        if !matches!(r.scope.as_str(), "all" | "api" | "console") {
            return Err(format!("escopo inválido na regra {}", r.cidr));
        }
        out.push((Net::parse(&r.cidr)?, r.clone()));
    }
    Ok(out)
}

/// Decision for one address under a rule set (bans not included).
fn decide(cfg: &IpConfig, nets: &[(Net, Rule)], ip: IpAddr, s: Surface, now: DateTime<Utc>) -> Decision {
    let active = |r: &Rule| r.expires.is_none_or(|e| e > now) && scope_matches(&r.scope, s);
    if nets.iter().any(|(n, r)| r.action == "allow" && active(r) && n.contains(ip)) {
        return Decision::Allowed;
    }
    if nets.iter().any(|(n, r)| r.action == "block" && active(r) && n.contains(ip)) {
        return Decision::Blocked;
    }
    if cfg.mode == "allowlist" { Decision::NotListed } else { Decision::Default }
}

#[derive(PartialEq, Debug)]
enum Decision {
    /// Explicitly allowed (also exempt from automatic bans).
    Allowed,
    Blocked,
    NotListed,
    Default,
}

impl IpFilter {
    pub fn new(cfg: IpConfig, disabled: bool) -> IpFilter {
        let nets = compile(&cfg).unwrap_or_else(|e| {
            tracing::error!("regras de IP inválidas ignoradas: {e}");
            Vec::new()
        });
        if disabled {
            tracing::warn!("filtro de IPs desligado por BOXSPACE_IP_FILTER=off");
        }
        IpFilter {
            disabled,
            compiled: RwLock::new(Compiled { cfg, nets }),
            failures: Mutex::default(),
            denied: Mutex::default(),
            bans: Mutex::default(),
            logged: Mutex::default(),
            blocked_total: AtomicU64::new(0),
            bans_total: AtomicU64::new(0),
        }
    }

    pub fn disabled(&self) -> bool {
        self.disabled
    }

    pub fn config(&self) -> IpConfig {
        self.compiled.read().unwrap_or_else(|e| e.into_inner()).cfg.clone()
    }

    pub fn set(&self, cfg: IpConfig) -> Result<(), String> {
        let nets = compile(&cfg)?;
        *self.compiled.write().unwrap_or_else(|e| e.into_inner()) = Compiled { cfg, nets };
        Ok(())
    }

    /// Would `cfg` let `ip` reach `s`? (Ignores automatic bans.)
    pub fn would_allow(cfg: &IpConfig, ip: IpAddr, s: Surface) -> Result<bool, String> {
        if ip.to_canonical().is_loopback() {
            return Ok(true);
        }
        let nets = compile(cfg)?;
        Ok(!matches!(decide(cfg, &nets, ip, s, Utc::now()), Decision::Blocked | Decision::NotListed))
    }

    /// `Err(reason)` when the address must be refused.
    pub fn check(&self, ip: IpAddr, s: Surface) -> Result<(), &'static str> {
        if self.disabled || ip.to_canonical().is_loopback() {
            return Ok(());
        }
        let decision = {
            let c = self.compiled.read().unwrap_or_else(|e| e.into_inner());
            decide(&c.cfg, &c.nets, ip, s, Utc::now())
        };
        if decision == Decision::Allowed {
            return Ok(());
        }
        let banned = {
            let mut bans = self.bans.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            bans.retain(|_, b| b.until > now);
            bans.contains_key(&ip.to_canonical())
        };
        let r = if banned {
            Err("bloqueio automático")
        } else {
            match decision {
                Decision::Blocked => Err("bloqueado por regra"),
                Decision::NotListed => Err("fora da lista de IPs permitidos"),
                _ => Ok(()),
            }
        };
        if r.is_err() {
            self.blocked_total.fetch_add(1, Ordering::Relaxed);
        }
        r
    }

    /// Count a failed authentication. Returns the ban if this triggered one.
    pub fn record_failure(&self, ip: IpAddr) -> Option<BanInfo> {
        self.strike(ip, Strike::Auth)
    }

    /// Count an anonymous request refused with AccessDenied. Returns the ban
    /// if this triggered one.
    pub fn record_denied(&self, ip: IpAddr) -> Option<BanInfo> {
        self.strike(ip, Strike::Denied)
    }

    fn strike(&self, ip: IpAddr, kind: Strike) -> Option<BanInfo> {
        let ip = ip.to_canonical();
        if self.disabled || ip.is_loopback() {
            return None;
        }
        let (auto, exempt) = {
            let c = self.compiled.read().unwrap_or_else(|e| e.into_inner());
            let exempt = c.nets.iter().any(|(n, r)| r.action == "allow" && r.expires.is_none_or(|e| e > Utc::now()) && n.contains(ip));
            (c.cfg.auto.clone(), exempt)
        };
        let max = match kind {
            Strike::Auth => auto.max_failures,
            Strike::Denied => auto.max_denied,
        };
        if !auto.enabled || exempt || max == 0 {
            return None;
        }
        let now = Instant::now();
        let window = Duration::from_secs(auto.window_secs);
        let counter = match kind {
            Strike::Auth => &self.failures,
            Strike::Denied => &self.denied,
        };
        let count = {
            let mut f = counter.lock().unwrap_or_else(|e| e.into_inner());
            if f.len() > 100_000 {
                f.retain(|_, v| v.last().is_some_and(|t| now.duration_since(*t) < window));
            }
            let list = f.entry(ip).or_default();
            list.retain(|t| now.duration_since(*t) < window);
            list.push(now);
            let n = list.len() as u32;
            if n >= max {
                f.remove(&ip);
            }
            n
        };
        if count < max {
            return None;
        }
        let since = Utc::now();
        let info = BanInfo {
            ip: ip.to_string(),
            since,
            until: since + chrono::Duration::seconds(auto.ban_secs as i64),
            failures: count,
            reason: match kind {
                Strike::Auth => "auth",
                Strike::Denied => "denied",
            }
            .into(),
        };
        self.bans
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(ip, Ban { until: now + Duration::from_secs(auto.ban_secs), info: info.clone() });
        self.bans_total.fetch_add(1, Ordering::Relaxed);
        let what = match kind {
            Strike::Auth => "falhas de autenticação",
            Strike::Denied => "requisições anônimas recusadas",
        };
        tracing::warn!("IP {ip} bloqueado por {} s após {count} {what}", auto.ban_secs);
        Some(info)
    }

    pub fn bans(&self) -> Vec<BanInfo> {
        let now = Instant::now();
        let mut bans = self.bans.lock().unwrap_or_else(|e| e.into_inner());
        bans.retain(|_, b| b.until > now);
        let mut v: Vec<BanInfo> = bans.values().map(|b| b.info.clone()).collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.since));
        v
    }

    pub fn unban(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.failures.lock().unwrap_or_else(|e| e.into_inner()).remove(&ip);
        self.denied.lock().unwrap_or_else(|e| e.into_inner()).remove(&ip);
        self.bans.lock().unwrap_or_else(|e| e.into_inner()).remove(&ip).is_some()
    }

    /// Rate-limit audit entries for blocked requests to one per minute per IP.
    pub fn should_log(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut l = self.logged.lock().unwrap_or_else(|e| e.into_inner());
        if l.len() > 100_000 {
            l.clear();
        }
        match l.get(&ip) {
            Some(t) if now.duration_since(*t) < Duration::from_secs(60) => false,
            _ => {
                l.insert(ip, now);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn rule(cidr: &str, action: &str) -> Rule {
        Rule { cidr: cidr.into(), action: action.into(), scope: "all".into(), ..Default::default() }
    }

    #[test]
    fn cidr_matching() {
        let n = Net::parse("10.1.0.0/16").unwrap();
        assert!(n.contains(ip("10.1.200.3")));
        assert!(!n.contains(ip("10.2.0.1")));
        assert!(n.contains(ip("::ffff:10.1.2.3")), "IPv4-mapped IPv6 is treated as IPv4");
        assert!(Net::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        assert!(!Net::parse("0.0.0.0/0").unwrap().contains(ip("2001:db8::1")));
        let v6 = Net::parse("2001:db8::/32").unwrap();
        assert!(v6.contains(ip("2001:db8:ffff::1")));
        assert!(!v6.contains(ip("2001:db9::1")));
        assert!(Net::parse("1.2.3.4").unwrap().contains(ip("1.2.3.4")));
        assert!(!Net::parse("1.2.3.4").unwrap().contains(ip("1.2.3.5")));
        assert!(Net::parse("1.2.3.4/33").is_err());
        assert!(Net::parse("nope").is_err());
        assert!(Net::parse("10.1.2.3/8").unwrap().contains(ip("10.200.0.1")), "host bits are masked");
    }

    #[test]
    fn order_of_evaluation() {
        let cfg = IpConfig { rules: vec![rule("10.0.0.0/8", "block"), rule("10.9.9.9", "allow")], ..Default::default() };
        let f = IpFilter::new(cfg, false);
        assert!(f.check(ip("10.1.1.1"), Surface::Api).is_err());
        assert!(f.check(ip("10.9.9.9"), Surface::Api).is_ok(), "allow beats block");
        assert!(f.check(ip("192.0.2.1"), Surface::Api).is_ok());
        assert!(f.check(ip("127.0.0.1"), Surface::Api).is_ok());
    }

    #[test]
    fn allowlist_scope_and_expiry() {
        let mut console_only = rule("198.51.100.0/24", "allow");
        console_only.scope = "console".into();
        let mut expired = rule("203.0.113.0/24", "allow");
        expired.expires = Some(Utc::now() - chrono::Duration::seconds(5));
        let cfg = IpConfig { mode: "allowlist".into(), rules: vec![console_only, expired], ..Default::default() };
        let f = IpFilter::new(cfg, false);
        assert!(f.check(ip("198.51.100.7"), Surface::Console).is_ok());
        assert!(f.check(ip("198.51.100.7"), Surface::Api).is_err());
        assert!(f.check(ip("203.0.113.1"), Surface::Console).is_err(), "expired rule ignored");
        assert!(f.check(ip("::1"), Surface::Api).is_ok(), "loopback always allowed");
    }

    #[test]
    fn auto_ban() {
        let cfg = IpConfig { auto: AutoBan { enabled: true, max_failures: 3, max_denied: 5, window_secs: 60, ban_secs: 60 }, ..Default::default() };
        let f = IpFilter::new(cfg, false);
        let a = ip("192.0.2.50");
        assert!(f.record_failure(a).is_none());
        assert!(f.record_failure(a).is_none());
        assert!(f.check(a, Surface::Api).is_ok());
        assert!(f.record_failure(a).is_some());
        assert!(f.check(a, Surface::Api).is_err());
        assert!(f.check(a, Surface::Console).is_err());
        assert!(f.unban(a));
        assert!(f.check(a, Surface::Api).is_ok());
        assert!(f.record_failure(ip("127.0.0.1")).is_none());
    }

    #[test]
    fn auto_ban_anonymous_denied() {
        let cfg = IpConfig { auto: AutoBan { enabled: true, max_failures: 3, max_denied: 5, window_secs: 60, ban_secs: 60 }, ..Default::default() };
        let f = IpFilter::new(cfg, false);
        let a = ip("192.0.2.60");
        for _ in 0..4 {
            assert!(f.record_denied(a).is_none());
        }
        // Denials and auth failures are counted separately.
        assert!(f.record_failure(a).is_none());
        assert!(f.check(a, Surface::Api).is_ok());
        let ban = f.record_denied(a).expect("fifth denial bans");
        assert_eq!(ban.reason, "denied");
        assert!(f.check(a, Surface::Api).is_err());
        assert!(f.unban(a));
        assert!(f.check(a, Surface::Api).is_ok());

        // max_denied = 0 turns the check off; allow rules exempt the address.
        let off = IpFilter::new(IpConfig { auto: AutoBan { max_denied: 0, ..AutoBan::default() }, ..Default::default() }, false);
        assert!((0..100).all(|_| off.record_denied(a).is_none()));
        let allowed = IpFilter::new(IpConfig { rules: vec![rule("192.0.2.0/24", "allow")], auto: AutoBan { max_denied: 1, ..AutoBan::default() }, ..Default::default() }, false);
        assert!(allowed.record_denied(a).is_none());
        assert!(allowed.record_denied(ip("::1")).is_none());
    }

    #[test]
    fn old_config_gets_default_max_denied() {
        let cfg: IpConfig = serde_json::from_str(r#"{"mode":"blocklist","rules":[],"auto":{"enabled":true,"maxFailures":10,"windowSecs":300,"banSecs":900}}"#).unwrap();
        assert_eq!(cfg.auto.max_denied, 30);
    }
}
