use alloy::{
    primitives::{Address, Bytes, U256},
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
};
use std::sync::Arc;
use url::Url;

mod account;
use account::{Account, Call};

const RPC_URL: &str = "http://127.0.0.1:8545";
const CHAIN_ID: u64 = 31337; // Local development chain ID
const DELEGATION_ADDRESS: &str = "0x5FbDB2315678afecb367f032d93F642f64180aa3";
//const ENTRY_POINT_ADDRESS: &str = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512";

const USER_PK: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const DEPLOYER_PK: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

#[tokio::main]
async fn main() {
    let user_pk: PrivateKeySigner = USER_PK.parse().unwrap();
    let user_signer = Arc::new(user_pk);

    let deployer_pk: PrivateKeySigner = DEPLOYER_PK.parse().unwrap();
    let deployer_signer = Arc::new(deployer_pk);

    let delegation_address: Address = DELEGATION_ADDRESS.parse().unwrap();

    let rpc_url = Url::parse(RPC_URL).unwrap();
    let provider = ProviderBuilder::new().on_http(rpc_url);

    let mut account = Account::new(
        provider.clone(),
        user_signer.address(),
        delegation_address,
        CHAIN_ID,
    );

    match account.create(&user_signer, &deployer_signer).await {
        Ok(_) => {
            println!("Account created successfully!");
            println!("Address: {:?}", account.address());
        }
        Err(e) => {
            println!("Failed to create account: {:?}", e);
            return;
        }
    };

    let target_user_address: Address = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
        .parse()
        .unwrap();
    println!("Executing a call...");
    let calls = vec![Call {
        to: target_user_address,
        value: Some(U256::from(0)),
        data: Some(Bytes::new()),
    }];

    match account.execute(calls, user_signer.clone()).await {
        Ok(tx_hash) => {
            println!("Call executed successfully!");
            println!("Transaction Hash: {:?}", tx_hash);
        }
        Err(e) => {
            println!("Failed to execute call: {:?}", e);
        }
    }
}
