use alloy::{
    consensus::{TxEip7702, TypedTransaction},
    network::TransactionBuilder,
    primitives::{Address, Bytes, FixedBytes, Uint, B256, U256},
    providers::Provider,
    rpc::types::{AccessList, Authorization, TransactionRequest},
    sol,
};
use std::sync::Arc;
use thiserror::Error;

const DEFAULT_EXECUTION_MODE: &str =
    "0x0100000000007821000100000000000000000000000000000000000000000000";

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Delegation,
    "src/abi/Delegation.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    EntryPoint,
    "src/abi/EntryPoint.json"
);

#[derive(Debug, Error)]
pub enum AccountError {
    #[error("Provider error: {0}")]
    ProviderError(String),
    #[error("Signer error: {0}")]
    SignerError(String),
    #[error("Transaction error: {0}")]
    TransactionError(String),
}

#[derive(Debug, Clone)]
pub struct Call {
    pub to: Address,
    pub value: Option<U256>,
    pub data: Option<Bytes>,
}

pub struct Account<P: Provider + Clone> {
    provider: P,
    address: Address,
    delegation_address: Address,
    chain_id: u64,
}

impl<P: Provider + Clone> Account<P> {
    pub fn new(provider: P, address: Address, delegation_address: Address, chain_id: u64) -> Self {
        Self {
            provider,
            address,
            delegation_address,
            chain_id,
        }
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub async fn execute<S>(&self, calls: Vec<Call>, signer: Arc<S>) -> Result<B256, AccountError>
    where
        S: alloy::signers::Signer + Send + Sync,
    {
        let delegation = Delegation::new(self.address, self.provider.clone());

        let nonce = delegation
            .getNonce(Uint::from(0))
            .call()
            .await
            .map_err(|e| AccountError::ProviderError(format!("Failed to get nonce: {}", e)))?
            ._0;

        let erc7821_calls: Vec<ERC7821::Call> = calls
            .iter()
            .map(|call| ERC7821::Call {
                target: call.to,
                value: call.value.clone().unwrap_or(U256::ZERO),
                data: call.data.clone().unwrap_or(Bytes::new()),
            })
            .collect();

        let digest: FixedBytes<32> = delegation
            .computeDigest(erc7821_calls, nonce)
            .call()
            .await
            .map_err(|e| AccountError::ProviderError(format!("Failed to compute digest: {}", e)))?
            .result;

        let signature = signer
            .sign_hash(&B256::from(digest))
            .await
            .map_err(|e| AccountError::SignerError(e.to_string()))?;

        let signature_bytes = self
            .format_signature_for_delegation(&signature, &signer)
            .await;

        let op_data = Bytes::from([&nonce.to_be_bytes_vec()[..], &signature_bytes[..]].concat());

        let encoded_calls = self.encode_calls(&calls);

        let execution_data = self.prepare_execution_data(&encoded_calls, &op_data);

        let mode_bytes: FixedBytes<32> = DEFAULT_EXECUTION_MODE.parse().unwrap();

        let execution_result = delegation
            .execute(mode_bytes, execution_data)
            .send()
            .await
            .map_err(|e| {
                AccountError::TransactionError(format!("Failed to execute calls: {}", e))
            })?;

        let tx_hash = *execution_result.tx_hash();

        Ok(tx_hash)
    }

    pub async fn create<S, D>(
        &mut self,
        user_signer: &Arc<S>,
        deployer_signer: &Arc<D>,
    ) -> Result<(), AccountError>
    where
        S: alloy::signers::Signer + Send + Sync,
        D: alloy::signers::Signer + Send + Sync,
    {
        let user_code = self
            .provider
            .get_code_at(user_signer.address())
            .await
            .map_err(|e| AccountError::ProviderError(e.to_string()))?;

        if user_code.is_empty() {
            let _tx_hash = self
                .authorize_with_eip7702(user_signer, deployer_signer)
                .await?;
        }

        let delegation = Delegation::new(user_signer.address(), self.provider.clone());

        let key_count_result =
            delegation.keyCount().call().await.map_err(|e| {
                AccountError::ProviderError(format!("Failed to get key count: {}", e))
            })?;
        let key_count = key_count_result._0.as_limbs()[0] as u64;

        let public_key = user_signer.address();

        let mut key_already_authorized = false;

        for i in 0..key_count {
            let key_result = delegation.keyAt(Uint::from(i)).call().await.map_err(|e| {
                AccountError::ProviderError(format!("Failed to get key at index {}: {}", i, e))
            })?;
            let key = key_result._0;
            if key.publicKey.len() >= 20 {
                let key_address = Address::from_slice(&key.publicKey[key.publicKey.len() - 20..]);
                if key_address == public_key {
                    key_already_authorized = true;
                    break;
                }
            }
        }

        if !key_already_authorized {
            if key_count == 0 {
                let expiry = Uint::from(0);
                let key_type = 0u8;
                let is_super_admin = true;
                let public_key_bytes = Bytes::from(public_key.to_vec());
                let key = Delegation::Key {
                    expiry,
                    keyType: key_type,
                    isSuperAdmin: is_super_admin,
                    publicKey: public_key_bytes,
                };
                let authorize_calldata = delegation.authorize(key).calldata().to_owned();

                let authorize_call = Call {
                    to: self.address,
                    value: None,
                    data: Some(authorize_calldata),
                };

                let encoded_calls = self.encode_calls(&[authorize_call]);

                let empty_op_data = Bytes::new();

                let execution_data = self.prepare_execution_data(&encoded_calls, &empty_op_data);

                let mode_bytes: FixedBytes<32> = DEFAULT_EXECUTION_MODE.parse().unwrap();

                let execution_result = delegation
                    .execute(mode_bytes, execution_data)
                    .send()
                    .await
                    .map_err(|e| {
                        AccountError::TransactionError(format!("Failed to authorize key: {}", e))
                    })?;

                let _tx_hash = *execution_result.tx_hash();
            } else {
                let expiry = Uint::from(0);
                let key_type = 0u8;
                let is_super_admin = true;
                let public_key_bytes = Bytes::from(public_key.to_vec());
                let key = Delegation::Key {
                    expiry,
                    keyType: key_type,
                    isSuperAdmin: is_super_admin,
                    publicKey: public_key_bytes,
                };

                let authorize_calldata = delegation.authorize(key).calldata().to_owned();
                let authorize_call = Call {
                    to: self.address,
                    value: None,
                    data: Some(authorize_calldata),
                };

                let _tx_hash = self
                    .execute(vec![authorize_call], user_signer.clone())
                    .await?;
            }
        }

        Ok(())
    }

    pub async fn load(
        _provider: P,
        _address: Address,
        _delegation_address: Address,
        _entry_point_address: Address,
        _chain_id: u64,
    ) -> Result<Self, AccountError> {
        unimplemented!()
    }

    /// Grants permissions to an account
    pub async fn grant_permissions(
        &self,
        _permissions: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, AccountError> {
        unimplemented!("grant_permissions is not implemented yet")
    }

    /// Loads accounts by address or credential ID
    pub async fn load_accounts(
        _address: Option<Address>,
        _credential_id: Option<String>,
        _permissions: Option<serde_json::Value>,
        _provider: P,
        _delegation_address: Address,
        _entry_point_address: Address,
        _chain_id: u64,
    ) -> Result<Vec<Self>, AccountError> {
        unimplemented!("load_accounts is not implemented yet")
    }

    /// Revokes permissions for an account
    pub async fn revoke_permissions(&self, _id: String) -> Result<(), AccountError> {
        unimplemented!("revoke_permissions is not implemented yet")
    }

    /// Signs a personal message
    pub async fn sign_personal_message<S>(
        &self,
        _data: String,
        _signer: Arc<S>,
    ) -> Result<String, AccountError>
    where
        S: alloy::signers::Signer + Send + Sync,
    {
        unimplemented!("sign_personal_message is not implemented yet")
    }

    /// Signs typed data
    pub async fn sign_typed_data<S>(
        &self,
        _data: String,
        _signer: Arc<S>,
    ) -> Result<String, AccountError>
    where
        S: alloy::signers::Signer + Send + Sync,
    {
        unimplemented!("sign_typed_data is not implemented yet")
    }

    /// Internal

    async fn authorize_with_eip7702<S, D>(
        &mut self,
        user_signer: &Arc<S>,
        deployer_signer: &Arc<D>,
    ) -> Result<B256, AccountError>
    where
        S: alloy::signers::Signer + Send + Sync,
        D: alloy::signers::Signer + Send + Sync,
    {
        let user_address = user_signer.address();
        self.address = user_address;

        let user_nonce = self
            .provider
            .get_transaction_count(user_address)
            .await
            .map_err(|e| AccountError::ProviderError(e.to_string()))?;

        let deployer_address = deployer_signer.address();
        let deployer_nonce = self
            .provider
            .get_transaction_count(deployer_address)
            .await
            .map_err(|e| AccountError::ProviderError(e.to_string()))?;

        let authorization = Authorization {
            chain_id: U256::from(self.chain_id),
            address: self.delegation_address,
            nonce: user_nonce,
        };

        let signature = user_signer
            .sign_hash(&authorization.signature_hash())
            .await
            .map_err(|e| AccountError::SignerError(e.to_string()))?;

        let signed_authorization = authorization.into_signed(signature);

        let eip_7702_tx = TxEip7702 {
            chain_id: self.chain_id,
            nonce: deployer_nonce,
            gas_limit: 0,
            to: Address::ZERO,
            value: U256::from(0_u64),
            input: Bytes::new(),
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            access_list: AccessList::default(),
            authorization_list: vec![signed_authorization],
        };

        let tx = TypedTransaction::Eip7702(eip_7702_tx);

        let tx_request = TransactionRequest::from_transaction(tx);

        let gas_estimate = self
            .provider
            .estimate_eip1559_fees(None)
            .await
            .map_err(|e| AccountError::ProviderError(e.to_string()))?;

        let gas_limit = self
            .provider
            .estimate_gas(&tx_request)
            .await
            .map_err(|e| AccountError::ProviderError(e.to_string()))?;

        let filled_tx_request = tx_request
            .with_from(deployer_address)
            .with_gas_limit(gas_limit)
            .with_max_fee_per_gas(gas_estimate.max_fee_per_gas)
            .with_max_priority_fee_per_gas(gas_estimate.max_priority_fee_per_gas)
            .with_nonce(deployer_nonce);

        let tx_envelope = self
            .provider
            .send_transaction(filled_tx_request)
            .await
            .map_err(|e| AccountError::TransactionError(e.to_string()))?;

        let tx_hash = tx_envelope.tx_hash();

        Ok(*tx_hash)
    }

    fn encode_calls(&self, calls: &[Call]) -> Bytes {
        let mut encoded = Vec::new();

        let calls_length = U256::from(calls.len());
        encoded.extend_from_slice(&calls_length.to_be_bytes_vec());

        let offset = U256::from(32);
        encoded.extend_from_slice(&offset.to_be_bytes_vec());

        for call in calls {
            let mut padded_address = [0u8; 32];

            padded_address[12..32].copy_from_slice(&call.to.to_vec());
            encoded.extend_from_slice(&padded_address);

            let value = call.value.unwrap_or(U256::ZERO);
            encoded.extend_from_slice(&value.to_be_bytes_vec());

            let bytes_offset = U256::from(64);
            encoded.extend_from_slice(&bytes_offset.to_be_bytes_vec());

            let data = call.data.clone().unwrap_or(Bytes::new());

            let data_len = U256::from(data.len());
            encoded.extend_from_slice(&data_len.to_be_bytes_vec());
            encoded.extend_from_slice(&data);

            let padding_needed = (32 - (data.len() % 32)) % 32;
            encoded.extend_from_slice(&vec![0u8; padding_needed]);
        }

        Bytes::from(encoded)
    }

    async fn format_signature_for_delegation<S>(
        &self,
        signature: &alloy::signers::Signature,
        signer: &Arc<S>,
    ) -> Bytes
    where
        S: alloy::signers::Signer + Send + Sync,
    {
        let r = signature.r().to_be_bytes_vec();
        let s = signature.s().to_be_bytes_vec();
        let v_value = if signature.v() { 28u8 } else { 27u8 };

        let inner_signature = Bytes::from([&r[..], &s[..], &[v_value]].concat());

        let signer_address = signer.address();
        let mut key_hash = [0u8; 32];
        key_hash[12..32].copy_from_slice(&signer_address.to_vec());

        let mut signature_bytes = Vec::new();
        signature_bytes.extend_from_slice(&inner_signature);
        signature_bytes.extend_from_slice(&key_hash);
        signature_bytes.push(0); // prehash_flag = false
        let signature_bytes = Bytes::from(signature_bytes);

        signature_bytes
    }

    fn prepare_execution_data(&self, encoded_calls: &Bytes, op_data: &Bytes) -> Bytes {
        let head_size = 64;
        let offset_calls = U256::from(head_size);
        let offset_opdata = U256::from(head_size + encoded_calls.len());

        let mut execution_data = Vec::new();
        execution_data.extend_from_slice(&offset_calls.to_be_bytes_vec());
        execution_data.extend_from_slice(&offset_opdata.to_be_bytes_vec());
        execution_data.extend_from_slice(encoded_calls);

        let opdata_len = U256::from(op_data.len());
        execution_data.extend_from_slice(&opdata_len.to_be_bytes_vec());
        execution_data.extend_from_slice(op_data);

        let padding_needed = (32 - (op_data.len() % 32)) % 32;
        execution_data.extend_from_slice(&vec![0u8; padding_needed]);

        Bytes::from(execution_data)
    }
}

//
// Offchain Relayer which can be used to submit UserOps to the EntryPoint
//
sol! {
    /// The user operation to be submitted to the entry point.
    #[derive(Debug)]
    struct UserOp {
        /// @dev The user's address.
        address eoa;
        /// @dev An encoded array of calls, using ERC7579 batch execution encoding.
        /// `abi.encode(calls)`, where `calls` is an array of type `Call[]`.
        /// This allows for more efficient safe forwarding to the EOA.
        bytes executionData;
        /// @dev Per delegated EOA.
        /// This nonce is a 4337-style 2D nonce with some specializations:
        /// - Upper 192 bits are used for the `seqKey` (sequence key).
        ///   The upper 16 bits of the `seqKey` is `MULTICHAIN_NONCE_PREFIX`,
        ///   then the UserOp EIP-712 hash will exclude the chain ID.
        /// - Lower 64 bits are used for the sequential nonce corresponding to the `seqKey`.
        uint256 nonce;
        /// @dev The account paying the payment token.
        /// If this is `address(0)`, it defaults to the `eoa`.
        address payer;
        /// @dev The ERC20 or native token used to pay for gas.
        address paymentToken;
        /// @dev The payment recipient for the ERC20 token.
        /// Excluded from signature. The filler can replace this with their own address.
        /// This enables multiple fillers, allowing for competitive filling, better uptime.
        /// If `address(0)`, the payment will be accrued by the entry point.
        address paymentRecipient;
        /// @dev The amount of the token to pay.
        /// Excluded from signature. This will be required to be less than `paymentMaxAmount`.
        uint256 paymentAmount;
        /// @dev The maximum amount of the token to pay.
        uint256 paymentMaxAmount;
        /// @dev The amount of ERC20 to pay per gas spent. For calculation of refunds.
        /// If this is left at zero, it will be treated as infinity (i.e. no refunds).
        uint256 paymentPerGas;
        /// @dev The combined gas limit for payment, verification, and calling the EOA.
        uint256 combinedGas;
        /// @dev The wrapped signature.
        /// `abi.encodePacked(innerSignature, keyHash, prehash)`.
        bytes signature;
    }
}

struct PseudoRelayer<P: Provider + Clone> {
    relayer_address: Address,
    user_address: Address,
    provider: P,
}

impl<P: Provider + Clone> PseudoRelayer<P> {

    pub async fn handle_response(&self, calls: Vec<Call>) -> Result<(), AccountError> {
        let user_ops = self.build_user_operations(calls).await?;

        let _tx_hash = self.submit_user_operations(user_ops).await?;

        Ok(())
    }

    pub async fn build_user_operations(&self, calls: Vec<Call>) -> Result<Vec<UserOp>, AccountError> {
        let mut user_ops = Vec::new();

        for call in calls {
            let payment_token = Address::ZERO;
            let signature = Bytes::new();

            let user_op = UserOp {
                eoa: self.user_address,
                executionData: self.encode_call(&call),
                nonce: U256::from(0),
                payer: self.relayer_address,
                paymentToken: payment_token,
                paymentRecipient: call.to,
                paymentAmount: call.value.unwrap_or(U256::ZERO),
                paymentMaxAmount: U256::from(0),
                paymentPerGas: U256::from(0),
                combinedGas: U256::from(0),
                signature: signature,
            };

            user_ops.push(user_op);
        }

        Ok(user_ops)
    }

    pub async fn submit_user_operations(&self, _user_operations: Vec<UserOp>) -> Result<B256, AccountError> {
        unimplemented!()
    }

    fn encode_call(&self, _call: &Call) -> Bytes {
        unimplemented!()   
    }
    
}