use zcash_protocol::{
    consensus::{BlockHeight, MainNetwork, NetworkType, NetworkUpgrade, OrchardMode, Parameters, TestNetwork},
    local_consensus::LocalNetwork,
};

/// Zcash network variant.
#[derive(Copy, Clone, Debug)]
pub enum Network {
    Main,
    Test,
    Regtest(LocalNetwork),
    /// ZSA regtest network (NU7, no Ironwood).
    ZsaRegtest(LocalNetwork),
}

impl Parameters for Network {
    fn network_type(&self) -> NetworkType {
        match self {
            Network::Main => MainNetwork.network_type(),
            Network::Test => TestNetwork.network_type(),
            Network::Regtest(n) | Network::ZsaRegtest(n) => n.network_type(),
        }
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match self {
            Network::Main => MainNetwork.activation_height(nu),
            Network::Test => TestNetwork.activation_height(nu),
            Network::Regtest(n) | Network::ZsaRegtest(n) => n.activation_height(nu),
        }
    }

    fn orchard_mode(&self) -> OrchardMode {
        match self {
            Network::Main => MainNetwork.orchard_mode(),
            Network::Test => TestNetwork.orchard_mode(),
            Network::Regtest(n) | Network::ZsaRegtest(n) => n.orchard_mode(),
        }
    }
}
