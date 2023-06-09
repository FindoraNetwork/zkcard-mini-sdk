#![allow(non_upper_case_globals)]

use eth_utils::fp_evm::{Precompile, PrecompileHandle, PrecompileResult};
use ethereum_types::U256;
use evm::{
    backend::Log,
    executor::stack::{PrecompileFailure, PrecompileOutput},
    ExitSucceed,
};
use evm_precompile_utils::{
    error, AsVec, Bytes, EvmDataReader2, EvmDataWriter2, EvmResult, Gasometer, ToBytes,
};
use num::Zero;
use slices::u8_slice;
use std::any::type_name;
use std::vec;
use tracing::debug;

// zkcard support
use ark_bn254::{g1::Config, Fr, G1Affine, G1Projective};
use ark_ec::{
    models::short_weierstrass::{Affine, Projective},
    AffineRepr,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::One;
use barnett_smart_card_protocol::{
    discrete_log_cards::{
        DLCards, MaskedCard as InMaskedCard, Parameters, RevealToken as InRevealToken,
    },
    BarnettSmartProtocol, Reveal,
};
use proof_essentials::{
    homomorphic_encryption::el_gamal::{ElGamal, Plaintext},
    vector_commitment::pedersen::PedersenCommitment,
    zkp::{
        arguments::shuffle::proof::Proof as InShuffleProof,
        proofs::{
            chaum_pedersen_dl_equality::proof::Proof as InRevealProof,
            schnorr_identification::proof::Proof as InKeyownershipProof,
        },
    },
};

type CConfig = Config;
type CProjective<T> = Projective<T>;
type CCurve = G1Projective;
type CCardProtocol<'a> = DLCards<'a, CCurve>;
type CCardParameters = Parameters<CProjective<CConfig>>;
type CPublicKey = Affine<CConfig>;
type CMaskedCard = InMaskedCard<CCurve>;
type CRevealToken = InRevealToken<CCurve>;
type CAggregatePublicKey = G1Affine;
type CRevealProof = InRevealProof<CCurve>;
type CShuffleProof = InShuffleProof<Fr, ElGamal<CCurve>, PedersenCommitment<CCurve>>;
type CKeyownershipProof = InKeyownershipProof<CProjective<CConfig>>;
type CCard = Plaintext<CProjective<CConfig>>;
type CScalar = Fr;

/// ZkCard transfer event selector, Keccak256("Transfer(address,address,uint256)")
///
/// event Transfer(address indexed from, address indexed to, uint256 value);
pub const TRANSFER_EVENT_SELECTOR: &[u8; 32] =
    u8_slice!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");

/// ZkCard approval event selector, Keccak256("Approval(address,address,uint256)")
///
/// event Approval(address indexed owner, address indexed spender, uint256 value);
pub const APPROVAL_EVENT_SELECTOR: &[u8; 32] =
    u8_slice!("0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925");

/// b"Findora"
pub const ZKCARD_NAME: &[u8; 96] = u8_slice!(
    "0x00000000000000000000000000000000000000000000000000000000000000200000000000000\
    00000000000000000000000000000000000000000000000000746696e646f7261000000000000000\
    00000000000000000000000000000000000"
);

/// b"FRA"
pub const ZKCARD_SYMBOL: &[u8; 96] = u8_slice!(
    "0x00000000000000000000000000000000000000000000000000000000000000200000000000000\
    00000000000000000000000000000000000000000000000000346524100000000000000000000000\
    00000000000000000000000000000000000"
);

// The gas used value is obtained according to the standard erc20 call.
// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.3.2/contracts/token/ERC20/ERC20.sol
const GAS_VERIFYKEYOWNERSHIP: u64 = 1000;
const GAS_COMPUTEAGGREGATEKEY: u64 = 1000;
const GAS_VERIFYSHUFFLE: u64 = 1000;
const GAS_VERIFYREVEAL: u64 = 1000;
const GAS_REVEAL: u64 = 1000;
const GAS_TEST: u64 = 1000;

pub struct ZkCard;

#[evm_precompile_utils::generate_function_selector]
#[derive(Debug, PartialEq, Eq, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
pub enum Call {
    VerifyKeyOwnership = "verifyKeyOwnership(bytes,bytes,bytes,bytes)",
    VerifyReveal = "verifyReveal(bytes,bytes,bytes,bytes,bytes)",
    ComputeAggregateKey = "computeAggregateKey(bytes[])",
    VerifyShuffle = "verifyShuffle(bytes,bytes,bytes[],bytes[],bytes)",
    Reveal = "reveal(bytes[],bytes)",
    Mask = "mask(bytes,bytes,bytes)",
    Test = "test(bytes,bytes[])",
}

impl Precompile for ZkCard {
    fn execute(handle: &mut impl PrecompileHandle) -> PrecompileResult {
        let input = handle.input();
        let target_gas = handle.gas_limit();
        let _context = handle.context();

        let mut input = EvmDataReader2::new(input);
        let selector = input
            .read_selector::<Call>()
            .map_err(|e| PrecompileFailure::Error { exit_status: e })?;

        match {
            match &selector {
                Call::VerifyKeyOwnership => Self::verify_key_ownership(input, target_gas),
                Call::ComputeAggregateKey => Self::compute_aggregate_key(input, target_gas),
                Call::VerifyShuffle => Self::verify_shuffle(input, target_gas),
                Call::VerifyReveal => Self::verify_reveal(input, target_gas),
                Call::Reveal => Self::reveal(input, target_gas),
                Call::Mask => Self::mask(input, target_gas),
                Call::Test => Self::test(input, target_gas),
            }
        } {
            Ok(v) => {
                handle.record_cost(v.1)?;
                for log in v.2 {
                    handle.log(log.address, log.topics, log.data)?;
                }
                Ok(v.0)
            }
            Err(e) => Err(PrecompileFailure::Error { exit_status: e }),
        }
    }
}

impl ZkCard {
    fn test(
        mut input: EvmDataReader2,
        target_gas: Option<u64>,
    ) -> EvmResult<(PrecompileOutput, u64, Vec<Log>)> {
        debug!(target: "evm", "ZkCard#name: Findora");

        let mut gasometer = Gasometer::new(target_gas);
        gasometer.record_cost(GAS_TEST)?;

        input.expect_arguments(2)?;
        let _: U256 = input.read()?;

        let res: Bytes = b"call test".to_bytes();

        let cost = gasometer.used_gas();
        let logs = vec![];

        Ok((
            PrecompileOutput {
                exit_status: ExitSucceed::Returned,
                output: EvmDataWriter2::new().write(res).build(),
            },
            cost,
            logs,
        ))
    }

    fn verify_key_ownership(
        mut input: EvmDataReader2,
        target_gas: Option<u64>,
    ) -> EvmResult<(PrecompileOutput, u64, Vec<Log>)> {
        debug!(target: "evm", "ZkCard#name: Findora");

        let mut gasometer = Gasometer::new(target_gas);
        gasometer.record_cost(GAS_VERIFYKEYOWNERSHIP)?;

        input.expect_arguments(4)?;

        let params = input.read::<Bytes>()?;
        let pub_key = input.read::<Bytes>()?;
        let memo = input.read::<Bytes>()?;
        let key_proof = input.read::<Bytes>()?;

        let params = debase64::<CCardParameters>(params.as_slice())?;
        let pub_key = debase64::<CPublicKey>(pub_key.as_slice())?;
        let memo = debase64::<Vec<u8>>(memo.as_slice())?;
        let key_proof = debase64::<CKeyownershipProof>(key_proof.as_slice())?;

        let params: CCardParameters = deserialize(params.as_slice())?;
        let pub_key: CPublicKey = deserialize(pub_key.as_slice())?;
        let memo: Vec<u8> = deserialize(memo.as_slice())?;
        let key_proof: CKeyownershipProof = deserialize(key_proof.as_slice())?;

        let res =
            CCardProtocol::verify_key_ownership(&params, &pub_key, &memo.to_vec(), &key_proof)
                .map(|v| {
                    println!("verify_key_ownership verify_key_ownership ok: {:?}", v);
                    v
                })
                .map_err(|e| {
                    println!("verify_key_ownership verify_key_ownership err: {:?}", e);
                    e
                })
                .is_ok();

        let cost = gasometer.used_gas();
        let logs = vec![];

        Ok((
            PrecompileOutput {
                exit_status: ExitSucceed::Returned,
                output: EvmDataWriter2::new().write(res).build(),
            },
            cost,
            logs,
        ))
    }

    fn compute_aggregate_key(
        mut input: EvmDataReader2,
        target_gas: Option<u64>,
    ) -> EvmResult<(PrecompileOutput, u64, Vec<Log>)> {
        debug!(target: "evm", "ZkCard#name: Findora");

        let mut gasometer = Gasometer::new(target_gas);
        gasometer.record_cost(GAS_COMPUTEAGGREGATEKEY)?;

        input.expect_arguments(1)?;

        let pub_keys = input.read::<Vec<Bytes>>()?;

        let mut pub_keys2: Vec<Vec<u8>> = Vec::new();
        for v_pub_key in pub_keys {
            let cur_deck = debase64::<CPublicKey>(v_pub_key.as_slice())?;
            pub_keys2.push(cur_deck);
        }

        let mut aggregate_pub_key = CAggregatePublicKey::zero();
        for v_pub_key in pub_keys2 {
            let v_pub_key: CPublicKey = deserialize(v_pub_key.as_slice())?;
            aggregate_pub_key = (aggregate_pub_key + v_pub_key).into();
        }

        let res = serialize(&aggregate_pub_key)?;
        let res = base64::encode(&res).into_bytes();
        let res: Bytes = res.to_bytes();

        let cost = gasometer.used_gas();
        let logs = vec![];

        Ok((
            PrecompileOutput {
                exit_status: ExitSucceed::Returned,
                output: EvmDataWriter2::new().write(res).build(),
            },
            cost,
            logs,
        ))
    }

    fn verify_shuffle(
        mut input: EvmDataReader2,
        target_gas: Option<u64>,
    ) -> EvmResult<(PrecompileOutput, u64, Vec<Log>)> {
        debug!(target: "evm", "ZkCard#name: Findora");

        let mut gasometer = Gasometer::new(target_gas);
        gasometer.record_cost(GAS_VERIFYSHUFFLE)?;

        input.expect_arguments(5)?;

        let params = input.read::<Bytes>()?;
        let shared_key = input.read::<Bytes>()?;
        let cur_decks = input.read::<Vec<Bytes>>()?;
        let new_decks = input.read::<Vec<Bytes>>()?;
        let shuffle_proof = input.read::<Bytes>()?;

        let params = debase64::<CCardParameters>(params.as_slice())?;
        let shared_key = debase64::<CPublicKey>(shared_key.as_slice())?;
        let mut cur_decks2: Vec<Vec<u8>> = Vec::new();
        for v_cur_deck in cur_decks {
            let cur_deck = debase64::<CMaskedCard>(v_cur_deck.as_slice())?;
            cur_decks2.push(cur_deck);
        }
        let mut new_decks2: Vec<Vec<u8>> = Vec::new();
        for v_new_deck in new_decks {
            let new_deck = debase64::<CMaskedCard>(v_new_deck.as_slice())?;
            new_decks2.push(new_deck);
        }
        let shuffle_proof = debase64::<CShuffleProof>(shuffle_proof.as_slice())?;

        let params: CCardParameters = deserialize(params.as_slice())?;
        let shared_key: CPublicKey = deserialize(shared_key.as_slice())?;
        let mut cur_decks3: Vec<CMaskedCard> = Vec::new();
        for v_cur_deck in cur_decks2 {
            let v_cur_deck: CMaskedCard = deserialize(v_cur_deck.as_slice())?;
            cur_decks3.push(v_cur_deck);
        }
        let mut new_decks3: Vec<CMaskedCard> = Vec::new();
        for v_new_deck in new_decks2 {
            let v_new_deck: CMaskedCard = deserialize(v_new_deck.as_slice())?;
            new_decks3.push(v_new_deck);
        }
        let shuffle_proof: CShuffleProof = deserialize(shuffle_proof.as_slice())?;

        let res = CCardProtocol::verify_shuffle(
            &params,
            &shared_key,
            &cur_decks3,
            &new_decks3,
            &shuffle_proof,
        )
        .map(|v| {
            println!("verify_shuffle verify_shuffle ok: {:?}", v);
            v
        })
        .map_err(|e| {
            println!("verify_shuffle verify_shuffle err: {:?}", e);
            e
        })
        .is_ok();

        let cost = gasometer.used_gas();
        let logs = vec![];

        Ok((
            PrecompileOutput {
                exit_status: ExitSucceed::Returned,
                output: EvmDataWriter2::new().write(res).build(),
            },
            cost,
            logs,
        ))
    }

    fn verify_reveal(
        mut input: EvmDataReader2,
        target_gas: Option<u64>,
    ) -> EvmResult<(PrecompileOutput, u64, Vec<Log>)> {
        debug!(target: "evm", "ZkCard#name: Findora");

        let mut gasometer = Gasometer::new(target_gas);
        gasometer.record_cost(GAS_VERIFYREVEAL)?;

        input.expect_arguments(5)?;

        let params = input.read::<Bytes>()?;
        let pub_key = input.read::<Bytes>()?;
        let reveal_token = input.read::<Bytes>()?;
        let masked = input.read::<Bytes>()?;
        let reveal_proof = input.read::<Bytes>()?;

        let params = debase64::<CCardParameters>(params.as_slice())?;
        let pub_key = debase64::<CPublicKey>(pub_key.as_slice())?;
        let reveal_token = debase64::<CRevealToken>(reveal_token.as_slice())?;
        let masked = debase64::<CMaskedCard>(masked.as_slice())?;
        let reveal_proof = debase64::<CRevealProof>(reveal_proof.as_slice())?;

        let params: CCardParameters = deserialize(params.as_slice())?;
        let pub_key: CPublicKey = deserialize(pub_key.as_slice())?;
        let reveal_token: CRevealToken = deserialize(reveal_token.as_slice())?;
        let masked: CMaskedCard = deserialize(masked.as_slice())?;
        let reveal_proof: CRevealProof = deserialize(reveal_proof.as_slice())?;

        let res =
            CCardProtocol::verify_reveal(&params, &pub_key, &reveal_token, &masked, &reveal_proof)
                .map(|v| {
                    println!("verify_reveal verify_reveal ok: {:?}", v);
                    v
                })
                .map_err(|e| {
                    println!("verify_reveal verify_reveal err: {:?}", e);
                    e
                })
                .is_ok();

        let cost = gasometer.used_gas();
        let logs = vec![];

        Ok((
            PrecompileOutput {
                exit_status: ExitSucceed::Returned,
                output: EvmDataWriter2::new().write(res).build(),
            },
            cost,
            logs,
        ))
    }

    fn reveal(
        mut input: EvmDataReader2,
        target_gas: Option<u64>,
    ) -> EvmResult<(PrecompileOutput, u64, Vec<Log>)> {
        debug!(target: "evm", "ZkCard#name: Findora");

        let mut gasometer = Gasometer::new(target_gas);
        gasometer.record_cost(GAS_REVEAL)?;

        input.expect_arguments(2)?;

        let reveal_tokens = input.read::<Vec<Bytes>>()?;
        let masked = input.read::<Bytes>()?;

        let mut reveal_tokens2: Vec<Vec<u8>> = Vec::new();
        for v_reveal_token in reveal_tokens {
            let reveal_token = debase64::<CRevealToken>(v_reveal_token.as_slice())?;
            reveal_tokens2.push(reveal_token);
        }
        let masked = debase64::<CMaskedCard>(masked.as_slice())?;

        let mut aggregate_reveal_token = CRevealToken::zero();
        for reveal_token in reveal_tokens2 {
            let reveal_token: CRevealToken = deserialize(reveal_token.as_slice())?;
            aggregate_reveal_token = aggregate_reveal_token + reveal_token;
        }
        let masked: CMaskedCard = deserialize(masked.as_slice())?;

        let decrypted = aggregate_reveal_token
            .reveal(&masked)
            .map(|v| {
                println!("reveal reveal ok: {:?}", v);
                v
            })
            .map_err(|e| {
                println!("reveal reveal err: {:?}", e);
                error(format!("reveal reveal error: {:?}", e))
            })?;

        let res = serialize(&decrypted)?;
        let res = base64::encode(&res).into_bytes();
        let res: Bytes = res.to_bytes();

        let cost = gasometer.used_gas();
        let logs = vec![];

        Ok((
            PrecompileOutput {
                exit_status: ExitSucceed::Returned,
                output: EvmDataWriter2::new().write(res).build(),
            },
            cost,
            logs,
        ))
    }

    fn mask(
        mut input: EvmDataReader2,
        target_gas: Option<u64>,
    ) -> EvmResult<(PrecompileOutput, u64, Vec<Log>)> {
        debug!(target: "evm", "ZkCard#name: Findora");

        let mut gasometer = Gasometer::new(target_gas);
        gasometer.record_cost(GAS_REVEAL)?;

        input.expect_arguments(2)?;

        let params = input.read::<Bytes>()?;
        let shared_key = input.read::<Bytes>()?;
        let encoded = input.read::<Bytes>()?;

        let params = debase64::<CCardParameters>(params.as_slice())?;
        let shared_key = debase64::<CAggregatePublicKey>(shared_key.as_slice())?;
        let encoded = debase64::<CCard>(encoded.as_slice())?;

        let params: CCardParameters = deserialize(params.as_slice())?;
        let shared_key: CAggregatePublicKey = deserialize(shared_key.as_slice())?;
        let encoded: CCard = deserialize(encoded.as_slice())?;

        let masked: CMaskedCard =
            CCardProtocol::mask_only(&params, &shared_key, &encoded, &CScalar::one())
                .map(|v| {
                    println!("mask mask_only deserialize ok: {:?}", v);
                    v
                })
                .map_err(|e| {
                    println!("mask mask_only error: {:?}", e);
                    error(format!("mask mask_only error: {:?}", e))
                })?;

        let res = serialize(&masked)?;
        let res = base64::encode(&res).into_bytes();
        let res: Bytes = res.to_bytes();

        let cost = gasometer.used_gas();
        let logs = vec![];

        Ok((
            PrecompileOutput {
                exit_status: ExitSucceed::Returned,
                output: EvmDataWriter2::new().write(res).build(),
            },
            cost,
            logs,
        ))
    }
}

fn deserialize<T: CanonicalDeserialize>(data: &[u8]) -> EvmResult<T> {
    let typename1 = type_name::<T>();
    CanonicalDeserialize::deserialize_compressed(data)
        .map(|v| {
            println!("{:?} deserialize ok: {:?}", typename1, data);
            v
        })
        .map_err(|e| {
            println!("{:?} deserialize error: {:?}", typename1, e);
            error(format!("{:?} deserialize error: {:?}", typename1, e))
        })
}

fn serialize<T: CanonicalSerialize>(data: &T) -> EvmResult<Vec<u8>> {
    let typename1 = type_name::<T>();
    let mut res = Vec::with_capacity(data.compressed_size());
    data.serialize_compressed(&mut res)
        .map(|v| {
            println!("{:?} serialize ok: {:?}", typename1, v);
            res
        })
        .map_err(|e| {
            println!("{:?} serialize error: {:?}", typename1, e);
            error(format!("{:?} serialize error: {:?}", typename1, e))
        })
}

fn debase64<T>(data: &[u8]) -> EvmResult<Vec<u8>> {
    let typename1 = type_name::<T>();
    base64::decode(data)
        .map(|v| {
            println!("{:?} debase64 ok: {:?}", typename1, data);
            v
        })
        .map_err(|e| {
            println!("{:?} debase64 error: {:?}", typename1, e);
            error(format!("{:?} debase64 error: {:?}", typename1, e))
        })
}
