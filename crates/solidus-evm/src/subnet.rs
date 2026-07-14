//! The EVM subnet: a REVM instance whose precompile set is extended with
//! the three identity precompiles, bound to the latest bridge-verified
//! L1 roots. Contracts reach identity state with `STATICCALL` to the
//! precompile addresses — never by re-executing L1.

use std::sync::{Arc, RwLock};

use revm::precompile::{
    Precompile, PrecompileError, PrecompileErrors, PrecompileOutput, PrecompileResult,
    StatefulPrecompile,
};
use revm::primitives::{Address as EvmAddress, Bytes, Env, ExecutionResult, Output, TxKind};
use revm::{ContextPrecompile, Evm, InMemoryDB};
use solidus_state_tree::TreeId;
use solidus_subnet::{L1FinalizedRoots, Subnet, SubnetError};

use crate::precompiles::{
    is_did_active, verify_bbs_disclosure, verify_credential, ADDR_IS_DID_ACTIVE,
    ADDR_VERIFY_BBS_DISCLOSURE, ADDR_VERIFY_CREDENTIAL,
};
use crate::PrecompileFailure;

/// Flat gas costs (validator CPU cost is µs–ms; priced conservatively).
const GAS_DID_ACTIVE: u64 = 5_000;
const GAS_VERIFY_CREDENTIAL: u64 = 5_000;
const GAS_VERIFY_BBS: u64 = 120_000;

/// 20-byte precompile address: 18 zero bytes ++ [0x01, low].
pub fn precompile_address(low: u8) -> EvmAddress {
    let mut bytes = [0u8; 20];
    bytes[18] = 0x01;
    bytes[19] = low;
    EvmAddress::from(bytes)
}

type SharedRoots = Arc<RwLock<Option<L1FinalizedRoots>>>;

/// Which identity precompile a stateful entry dispatches to.
#[derive(Clone, Copy)]
enum Kind {
    DidActive,
    VerifyCredential,
    VerifyBbs,
}

struct IdentityPrecompile {
    kind: Kind,
    roots: SharedRoots,
}

impl IdentityPrecompile {
    fn run(&self, input: &[u8], gas_limit: u64) -> PrecompileResult {
        let (gas, tree) = match self.kind {
            Kind::DidActive => (GAS_DID_ACTIVE, TreeId::Dids),
            Kind::VerifyCredential => (GAS_VERIFY_CREDENTIAL, TreeId::Credentials),
            Kind::VerifyBbs => (GAS_VERIFY_BBS, TreeId::Credentials),
        };
        if gas > gas_limit {
            return Err(PrecompileErrors::Error(PrecompileError::OutOfGas));
        }

        let root = {
            #[allow(clippy::expect_used)]
            let guard = self.roots.read().expect("roots lock poisoned");
            guard
                .as_ref()
                .map(|r| r.subtree_root(tree))
                .ok_or_else(|| failure_to_error(&PrecompileFailure::NoRoots))?
        };

        let outcome = match self.kind {
            Kind::DidActive => is_did_active(&root, input),
            Kind::VerifyCredential => verify_credential(&root, input),
            Kind::VerifyBbs => verify_bbs_disclosure(&root, input),
        };
        match outcome {
            Ok(word) => Ok(PrecompileOutput::new(gas, Bytes::copy_from_slice(&word))),
            Err(failure) => Err(failure_to_error(&failure)),
        }
    }
}

fn failure_to_error(failure: &PrecompileFailure) -> PrecompileErrors {
    PrecompileErrors::Error(PrecompileError::Other(failure.to_string()))
}

impl StatefulPrecompile for IdentityPrecompile {
    fn call(&self, bytes: &Bytes, gas_limit: u64, _env: &Env) -> PrecompileResult {
        self.run(bytes, gas_limit)
    }
}

/// Errors from EVM-level calls into the subnet.
#[derive(thiserror::Error, Debug)]
pub enum EvmCallError {
    #[error("evm transact error: {0}")]
    Transact(String),

    #[error("execution reverted: {0}")]
    Reverted(String),
}

/// The EVM subnet: bridge-fed roots + a REVM database.
pub struct EvmSubnet {
    id: u64,
    latest: SharedRoots,
    db: InMemoryDB,
}

/// The subnet's internal caller for view/exec calls (funded so gas works).
const SUBNET_CALLER: [u8; 20] = [0xC0u8; 20];

/// One transaction's env for [`EvmSubnet::run`]. Internal-caller paths
/// (view/deploy/execute) use [`TxParams::internal`]; the raw-tx path fills in
/// the recovered sender, value, nonce and chain id.
struct TxParams {
    caller: EvmAddress,
    kind: TxKind,
    data: Vec<u8>,
    value: revm::primitives::U256,
    nonce: Option<u64>,
    gas_limit: u64,
    chain_id: Option<u64>,
}

impl TxParams {
    /// Defaults for the subnet's own trusted caller: no value, auto nonce,
    /// generous gas, chain-id check off (the internal caller isn't a
    /// signed-tx edge).
    fn internal(kind: TxKind, data: Vec<u8>) -> Self {
        Self {
            caller: EvmAddress::from(SUBNET_CALLER),
            kind,
            data,
            value: revm::primitives::U256::ZERO,
            nonce: None,
            gas_limit: 30_000_000,
            chain_id: None,
        }
    }
}

impl EvmSubnet {
    pub fn new(id: u64) -> Self {
        let mut db = InMemoryDB::default();
        // Fund the internal caller so gas-metered deploys/txs execute (the
        // subnet trusts its own execution path; identity reads are view
        // calls, contract deploy/transfer need a paying account).
        let info = revm::primitives::AccountInfo {
            balance: revm::primitives::U256::from(u128::MAX),
            ..Default::default()
        };
        db.insert_account_info(EvmAddress::from(SUBNET_CALLER), info);
        Self {
            id,
            latest: Arc::new(RwLock::new(None)),
            db,
        }
    }

    /// The subnet's chain id (used as the ETH-RPC `eth_chainId`).
    pub fn chain_id_or_default(&self) -> u64 {
        self.id
    }

    /// Latest bridged L1 height, or 0 if none delivered yet (ETH-RPC
    /// `eth_blockNumber` proxy — the subnet's identity view advances with
    /// L1 commits).
    pub fn latest_l1_height_or_zero(&self) -> u64 {
        use solidus_subnet::Subnet;
        self.latest_l1_height().unwrap_or(0)
    }

    /// Build a REVM instance over the subnet db with the 3 identity
    /// precompiles installed, run one transaction of the given kind, and
    /// (optionally) commit its state. Non-committing = a view call (used
    /// by [`call`](Self::call) / `eth_call`); committing = a state change
    /// (deploy, transfer).
    fn run(&mut self, tx: TxParams, commit: bool) -> Result<ExecutionResult, EvmCallError> {
        let roots = Arc::clone(&self.latest);
        let subnet_chain = self.id;
        let TxParams {
            caller,
            kind,
            data,
            value,
            nonce,
            gas_limit,
            chain_id,
        } = tx;
        let mut evm = Evm::builder()
            .with_db(&mut self.db)
            .append_handler_register_box(Box::new(move |handler| {
                let roots = Arc::clone(&roots);
                let prev = handler.pre_execution.load_precompiles.clone();
                // revm's handler field is Arc<dyn Fn() -> ContextPrecompiles<DB>>
                // with a non-Sync DB generic — the Arc shape is upstream's.
                #[allow(clippy::arc_with_non_send_sync)]
                let loader = Arc::new(move || {
                    let mut precompiles = prev();
                    precompiles.extend([
                        (
                            precompile_address(ADDR_IS_DID_ACTIVE),
                            ContextPrecompile::Ordinary(Precompile::Stateful(Arc::new(
                                IdentityPrecompile {
                                    kind: Kind::DidActive,
                                    roots: Arc::clone(&roots),
                                },
                            ))),
                        ),
                        (
                            precompile_address(ADDR_VERIFY_CREDENTIAL),
                            ContextPrecompile::Ordinary(Precompile::Stateful(Arc::new(
                                IdentityPrecompile {
                                    kind: Kind::VerifyCredential,
                                    roots: Arc::clone(&roots),
                                },
                            ))),
                        ),
                        (
                            precompile_address(ADDR_VERIFY_BBS_DISCLOSURE),
                            ContextPrecompile::Ordinary(Precompile::Stateful(Arc::new(
                                IdentityPrecompile {
                                    kind: Kind::VerifyBbs,
                                    roots: Arc::clone(&roots),
                                },
                            ))),
                        ),
                    ]);
                    precompiles
                });
                handler.pre_execution.load_precompiles = loader;
            }))
            .modify_cfg_env(move |cfg| {
                cfg.chain_id = subnet_chain;
            })
            .modify_tx_env(move |txe| {
                txe.caller = caller;
                txe.transact_to = kind;
                txe.data = data.into();
                txe.value = value;
                txe.gas_limit = gas_limit;
                // No fee market yet — the subnet meters gas but prices it 0
                // (a founder policy decision, like the L1 fee policy). So a
                // signed tx needs no native balance unless it moves value.
                txe.gas_price = revm::primitives::U256::ZERO;
                txe.nonce = nonce;
                txe.chain_id = chain_id;
            })
            .build();

        if commit {
            evm.transact_commit()
                .map_err(|e| EvmCallError::Transact(format!("{e:?}")))
        } else {
            evm.transact()
                .map(|out| out.result)
                .map_err(|e| EvmCallError::Transact(format!("{e:?}")))
        }
    }

    fn output_bytes(result: ExecutionResult) -> Result<Vec<u8>, EvmCallError> {
        match result {
            ExecutionResult::Success { output, .. } => Ok(match output {
                Output::Call(bytes) => bytes.to_vec(),
                Output::Create(bytes, _) => bytes.to_vec(),
            }),
            ExecutionResult::Revert { output, .. } => {
                Err(EvmCallError::Reverted(hex_snippet(&output)))
            }
            ExecutionResult::Halt { reason, .. } => {
                Err(EvmCallError::Reverted(format!("halt: {reason:?}")))
            }
        }
    }

    /// Execute a **view** call (non-committing). `to = precompile_address(x)`
    /// exercises the identity precompiles; a deployed contract address runs
    /// its code. This is the `eth_call` path.
    pub fn call(&mut self, to: EvmAddress, input: Vec<u8>) -> Result<Vec<u8>, EvmCallError> {
        let result = self.run(TxParams::internal(TxKind::Call(to), input), false)?;
        Self::output_bytes(result)
    }

    /// Execute a **state-changing** call (committing) — e.g. an ERC-20
    /// `transfer`. Returns the call output.
    pub fn execute(&mut self, to: EvmAddress, input: Vec<u8>) -> Result<Vec<u8>, EvmCallError> {
        let result = self.run(TxParams::internal(TxKind::Call(to), input), true)?;
        Self::output_bytes(result)
    }

    /// Deploy a contract from its creation bytecode (committing). Returns
    /// the deployed contract address.
    pub fn deploy(&mut self, init_code: Vec<u8>) -> Result<EvmAddress, EvmCallError> {
        let result = self.run(TxParams::internal(TxKind::Create, init_code), true)?;
        match result {
            ExecutionResult::Success {
                output: Output::Create(_, Some(addr)),
                ..
            } => Ok(addr),
            ExecutionResult::Success { .. } => {
                Err(EvmCallError::Transact("create produced no address".into()))
            }
            ExecutionResult::Revert { output, .. } => {
                Err(EvmCallError::Reverted(hex_snippet(&output)))
            }
            ExecutionResult::Halt { reason, .. } => {
                Err(EvmCallError::Reverted(format!("halt: {reason:?}")))
            }
        }
    }

    /// Execute a decoded, **sender-recovered** raw transaction (committing) —
    /// the back half of `eth_sendRawTransaction`. The caller is the recovered
    /// signer; the subnet checks nonce + chain-id (revm) exactly as a real
    /// EVM would. Returns the ETH tx hash on success, an error on revert/halt.
    pub fn submit_raw(&mut self, tx: &crate::raw_tx::DecodedTx) -> Result<[u8; 32], EvmCallError> {
        let kind = match tx.to {
            Some(to) => TxKind::Call(EvmAddress::from(to)),
            None => TxKind::Create,
        };
        let params = TxParams {
            caller: EvmAddress::from(tx.sender),
            kind,
            data: tx.data.clone(),
            value: tx.value,
            nonce: Some(tx.nonce),
            gas_limit: tx.gas_limit,
            chain_id: tx.chain_id,
        };
        match self.run(params, true)? {
            ExecutionResult::Success { .. } => Ok(tx.tx_hash),
            ExecutionResult::Revert { output, .. } => {
                Err(EvmCallError::Reverted(hex_snippet(&output)))
            }
            ExecutionResult::Halt { reason, .. } => {
                Err(EvmCallError::Reverted(format!("halt: {reason:?}")))
            }
        }
    }
}

fn hex_snippet(bytes: &[u8]) -> String {
    let n = bytes.len().min(64);
    bytes[..n].iter().map(|b| format!("{b:02x}")).collect()
}

impl Subnet for EvmSubnet {
    fn id(&self) -> u64 {
        self.id
    }

    fn on_l1_finalized(&mut self, roots: L1FinalizedRoots) -> Result<(), SubnetError> {
        #[allow(clippy::expect_used)]
        let mut guard = self.latest.write().expect("roots lock poisoned");
        if let Some(prev) = guard.as_ref() {
            if roots.l1_height < prev.l1_height {
                return Err(SubnetError::StaleRoots {
                    got: roots.l1_height,
                    latest: prev.l1_height,
                });
            }
        }
        *guard = Some(roots);
        Ok(())
    }

    fn latest_finalized(&self, tree: TreeId) -> Option<[u8; 32]> {
        #[allow(clippy::expect_used)]
        let guard = self.latest.read().expect("roots lock poisoned");
        guard.as_ref().map(|r| r.subtree_root(tree))
    }

    fn latest_l1_height(&self) -> Option<u64> {
        #[allow(clippy::expect_used)]
        let guard = self.latest.read().expect("roots lock poisoned");
        guard.as_ref().map(|r| r.l1_height)
    }
}

/// End-to-end proof that the subnet runs a **real foundry-compiled ERC-20**
/// (forge 1.7.1 + Solc 0.8.35; source `contracts/Token.sol`): deploy →
/// constructor mint → `transfer` → `balanceOf`, all through revm with the
/// identity precompiles installed. Closes the §4.8 / A5 "ERC-20 deploy +
/// transfer via foundry" acceptance.
#[cfg(test)]
mod erc20_e2e {
    use super::*;

    /// Creation bytecode of `contracts/Token.sol`, compiled by foundry
    /// (see `contracts/README.md` for the reproduce command).
    const ERC20_CREATION_HEX: &str = include_str!("../tests/fixtures/erc20_token.creation.hex");

    // Canonical ERC-20 selectors (keccak256(sig)[..4]).
    const SEL_BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31]; // balanceOf(address)
    const SEL_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb]; // transfer(address,uint256)

    fn u256_word(v: u128) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[16..].copy_from_slice(&v.to_be_bytes());
        w
    }

    fn addr_word(a: EvmAddress) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(a.as_slice());
        w
    }

    fn read_u128(word: &[u8]) -> u128 {
        assert_eq!(word.len(), 32, "expected a 32-byte ABI word");
        let mut b = [0u8; 16];
        b.copy_from_slice(&word[16..]);
        // Upper 16 bytes must be zero for our test-scale values.
        assert!(word[..16].iter().all(|&x| x == 0), "value overflows u128");
        u128::from_be_bytes(b)
    }

    fn balance_of(subnet: &mut EvmSubnet, token: EvmAddress, who: EvmAddress) -> u128 {
        let mut call = SEL_BALANCE_OF.to_vec();
        call.extend_from_slice(&addr_word(who));
        let out = subnet.call(token, call).expect("balanceOf view call");
        read_u128(&out)
    }

    #[test]
    fn erc20_deploy_transfer_balanceof() {
        let mut subnet = EvmSubnet::new(777);
        let deployer = EvmAddress::from(SUBNET_CALLER);
        let bob = EvmAddress::from([0xB0u8; 20]);

        let creation = hex::decode(ERC20_CREATION_HEX.trim()).expect("fixture is valid hex");
        let total: u128 = 1_000_000_000_000; // 10^12 raw units

        // Deploy: constructor(uint256 supply) => creation ++ abi.encode(supply).
        let mut init = creation;
        init.extend_from_slice(&u256_word(total));
        let token = subnet.deploy(init).expect("ERC-20 deploys");
        assert_ne!(token, EvmAddress::ZERO, "deployment yields an address");

        // Constructor minted the whole supply to the deployer; bob is empty.
        assert_eq!(
            balance_of(&mut subnet, token, deployer),
            total,
            "deployer holds total supply after constructor mint"
        );
        assert_eq!(balance_of(&mut subnet, token, bob), 0, "bob starts empty");

        // transfer(bob, amount) — a committing state change.
        let amount: u128 = 250_000;
        let mut call = SEL_TRANSFER.to_vec();
        call.extend_from_slice(&addr_word(bob));
        call.extend_from_slice(&u256_word(amount));
        let out = subnet.execute(token, call).expect("transfer executes");
        assert_eq!(read_u128(&out), 1, "ERC-20 transfer returns true");

        // Balances moved, supply conserved.
        assert_eq!(
            balance_of(&mut subnet, token, bob),
            amount,
            "bob credited by transfer"
        );
        assert_eq!(
            balance_of(&mut subnet, token, deployer),
            total - amount,
            "deployer debited by transfer"
        );
    }

    #[test]
    fn erc20_transfer_over_balance_reverts() {
        let mut subnet = EvmSubnet::new(777);
        let creation = hex::decode(ERC20_CREATION_HEX.trim()).expect("fixture is valid hex");
        let mut init = creation;
        init.extend_from_slice(&u256_word(1_000));
        let token = subnet.deploy(init).expect("ERC-20 deploys");

        // The deployer (subnet caller) holds the whole 1_000 supply; asking
        // to transfer 10_000 trips the contract's `require(balance >= value)`
        // and reverts — proving reverts propagate as errors, not silent
        // successes.
        let bob = EvmAddress::from([0xB0u8; 20]);
        let mut call = SEL_TRANSFER.to_vec();
        call.extend_from_slice(&addr_word(bob));
        call.extend_from_slice(&u256_word(10_000)); // > total supply 1_000
        let err = subnet
            .execute(token, call)
            .expect_err("over-balance reverts");
        assert!(
            matches!(err, EvmCallError::Reverted(_)),
            "insufficient-balance transfer reverts, got {err:?}"
        );
    }
}
