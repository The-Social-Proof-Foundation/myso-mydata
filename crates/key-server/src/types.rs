// Copyright (c), Mysten Labs, Inc.
// Copyright (c), The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

pub use crate::common::Network;
use crate::mydata_package::MyDataPackage;
use crate::utils::decode_object_id;
use crypto::ibe;
use std::str::FromStr;

/// The Identity-based encryption types.
pub type IbeMasterKey = ibe::MasterKey;

/// Proof-of-possession of a key-servers master key.
pub type MasterKeyPOP = ibe::ProofOfPossession;

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "devnet" => Ok(Network::Devnet {
                mydata_package: decode_object_id("MYDATA_PACKAGE")
                    .expect("MyData package ID must be set as env var MYDATA_PACKAGE"),
            }),
            "testnet" => Ok(Network::Testnet),
            "mainnet" => Ok(Network::Mainnet),
            _ => Err(format!("Unknown network: {s}")),
        }
    }
}

impl Network {
    pub fn mydata_package(&self) -> MyDataPackage {
        match self {
            Network::Devnet { mydata_package } => MyDataPackage::Custom(*mydata_package),
            Network::Testnet => MyDataPackage::Testnet,
            Network::Mainnet => MyDataPackage::Mainnet,
            #[cfg(test)]
            Network::TestCluster { mydata_package } => MyDataPackage::Custom(*mydata_package),
        }
    }
}
