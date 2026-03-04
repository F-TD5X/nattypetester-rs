pub const DEFAULT_STUN_PORT: u16 = 3478;
pub const DEFAULT_STUN_TLS_PORT: u16 = 5349;

pub const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.hot-chilli.net",
    "stun.fitauto.ru",
    "stun.internetcalls.com",
    "stun.voip.aebc.com",
    "stun.voipbuster.com",
    "stun.voipstunt.com",
];

pub fn default_server() -> &'static str {
    DEFAULT_STUN_SERVERS[0]
}
