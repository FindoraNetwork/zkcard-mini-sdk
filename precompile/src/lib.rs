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
        let selector = match input.read_selector::<Call>() {
            Ok(v) => v,
            Err(e) => {
                return Err(PrecompileFailure::Error { exit_status: e });
            }
        };

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

        let params: CCardParameters =
            match CCardParameters::deserialize_compressed(params.as_slice()) {
                Ok(v) => v,
                Err(e) => return Err(error(format!("params error: {:?}", e))),
            };
        let pub_key: CPublicKey = match CPublicKey::deserialize_compressed(pub_key.as_slice()) {
            Ok(v) => v,
            Err(e) => return Err(error(format!("pub_key error: {:?}", e))),
        };
        // let memo: Vec<u8> = match Vec::<u8>::deserialize_compressed(memo.as_slice()) {
        //     Ok(v) => v,
        //     Err(e) => return Err(error(format!("memo error: {:?}", e))),
        // };
        let key_proof: CKeyownershipProof =
            match CKeyownershipProof::deserialize_compressed(key_proof.as_slice()) {
                Ok(v) => v,
                Err(e) => return Err(error(format!("key_proof error: {:?}", e))),
            };
        let res =
            CCardProtocol::verify_key_ownership(&params, &pub_key, &memo.to_vec(), &key_proof)
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
        let mut gasometer = Gasometer::new(target_gas);
        gasometer.record_cost(GAS_COMPUTEAGGREGATEKEY)?;

        input.expect_arguments(1)?;

        let pub_keys = input.read::<Vec<Bytes>>()?;

        let mut aggregate_pub_key = CAggregatePublicKey::zero();
        for v_pub_key in pub_keys {
            let v_pub_key: CPublicKey =
                match CanonicalDeserialize::deserialize_compressed(v_pub_key.as_slice()) {
                    Ok(v) => v,
                    Err(e) => return Err(error(format!("pub_keys error: {:?}", e))),
                };
            aggregate_pub_key = (aggregate_pub_key + v_pub_key).into();
        }

        let mut res = Vec::with_capacity(aggregate_pub_key.compressed_size());
        match aggregate_pub_key.serialize_compressed(&mut res) {
            Ok(v) => v,
            Err(e) => return Err(error(format!("serialize error: {:?}", e))),
        };

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
        let mut gasometer = Gasometer::new(target_gas);
        gasometer.record_cost(GAS_VERIFYSHUFFLE)?;

        input.expect_arguments(5)?;

        let params = input.read::<Bytes>()?;
        let shared_key = input.read::<Bytes>()?;
        let cur_decks = input.read::<Vec<Bytes>>()?;
        let new_decks = input.read::<Vec<Bytes>>()?;
        let shuffle_proof = input.read::<Bytes>()?;

        let params: CCardParameters =
            match CanonicalDeserialize::deserialize_compressed(params.as_slice()) {
                Ok(v) => v,
                Err(e) => return Err(error(format!("params error: {:?}", e))),
            };
        let shared_key: CPublicKey =
            match CanonicalDeserialize::deserialize_compressed(shared_key.as_slice()) {
                Ok(v) => v,
                Err(e) => return Err(error(format!("shared_key error: {:?}", e))),
            };
        let mut cur_decks2: Vec<CMaskedCard> = Vec::new();
        for v_cur_deck in cur_decks {
            let v_cur_deck: CMaskedCard =
                match CanonicalDeserialize::deserialize_compressed(v_cur_deck.as_slice()) {
                    Ok(v) => v,
                    Err(e) => return Err(error(format!("cur_deck error: {:?}", e))),
                };
            cur_decks2.push(v_cur_deck);
        }
        let mut new_decks2: Vec<CMaskedCard> = Vec::new();
        for v_new_deck in new_decks {
            let v_new_deck: CMaskedCard =
                match CanonicalDeserialize::deserialize_compressed(v_new_deck.as_slice()) {
                    Ok(v) => v,
                    Err(e) => return Err(error(format!("new_deck error: {:?}", e))),
                };
            new_decks2.push(v_new_deck);
        }
        let shuffle_proof: CShuffleProof =
            match CanonicalDeserialize::deserialize_compressed(shuffle_proof.as_slice()) {
                Ok(v) => v,
                Err(e) => return Err(error(format!("shuffle_proof error: {:?}", e))),
            };

        let res = CCardProtocol::verify_shuffle(
            &params,
            &shared_key,
            &cur_decks2,
            &new_decks2,
            &shuffle_proof,
        )
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
        let mut gasometer = Gasometer::new(target_gas);
        gasometer.record_cost(GAS_VERIFYREVEAL)?;

        input.expect_arguments(5)?;

        let params = input.read::<Bytes>()?;
        let pub_key = input.read::<Bytes>()?;
        let reveal_token = input.read::<Bytes>()?;
        let masked = input.read::<Bytes>()?;
        let reveal_proof = input.read::<Bytes>()?;

        let params: CCardParameters =
            match CanonicalDeserialize::deserialize_compressed(params.as_slice()) {
                Ok(v) => v,
                Err(e) => return Err(error(format!("params error: {:?}", e))),
            };
        let pub_key: CPublicKey =
            match CanonicalDeserialize::deserialize_compressed(pub_key.as_slice()) {
                Ok(v) => v,
                Err(e) => return Err(error(format!("pub_key error: {:?}", e))),
            };
        let reveal_token: CRevealToken =
            match CanonicalDeserialize::deserialize_compressed(reveal_token.as_slice()) {
                Ok(v) => v,
                Err(e) => return Err(error(format!("reveal_token error: {:?}", e))),
            };
        let masked: CMaskedCard =
            match CanonicalDeserialize::deserialize_compressed(masked.as_slice()) {
                Ok(v) => v,
                Err(e) => return Err(error(format!("masked error: {:?}", e))),
            };
        let reveal_proof: CRevealProof =
            match CanonicalDeserialize::deserialize_compressed(reveal_proof.as_slice()) {
                Ok(v) => v,
                Err(e) => return Err(error(format!("reveal_proof error: {:?}", e))),
            };

        let res =
            CCardProtocol::verify_reveal(&params, &pub_key, &reveal_token, &masked, &reveal_proof)
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
        let mut gasometer = Gasometer::new(target_gas);
        gasometer.record_cost(GAS_REVEAL)?;

        input.expect_arguments(2)?;

        let reveal_tokens = input.read::<Vec<Bytes>>()?;
        let masked = input.read::<Bytes>()?;

        let mut aggregate_reveal_token = CRevealToken::zero();

        for reveal_token in reveal_tokens {
            let reveal_token: CRevealToken =
                match CanonicalDeserialize::deserialize_compressed(reveal_token.as_slice()) {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(error(format!("reveal_tokens error: {:?}", e)));
                    }
                };
            aggregate_reveal_token = aggregate_reveal_token + reveal_token;
        }
        let masked: CMaskedCard =
            match CanonicalDeserialize::deserialize_compressed(masked.as_slice()) {
                Ok(v) => v,
                Err(e) => return Err(error(format!("masked error: {:?}", e))),
            };

        let decrypted = match aggregate_reveal_token.reveal(&masked) {
            Ok(v) => v,
            Err(e) => return Err(error(format!("reveal error: {:?}", e))),
        };

        let mut res = Vec::with_capacity(decrypted.compressed_size());
        match decrypted.serialize_compressed(&mut res) {
            Ok(v) => v,
            Err(e) => return Err(error(format!("serialize error: {:?}", e))),
        };

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
        let mut gasometer = Gasometer::new(target_gas);
        gasometer.record_cost(GAS_REVEAL)?;

        input.expect_arguments(2)?;

        let params = input.read::<Bytes>()?;
        let shared_key = input.read::<Bytes>()?;
        let encoded = input.read::<Bytes>()?;

        let params: CCardParameters =
            match CanonicalDeserialize::deserialize_compressed(params.as_slice()) {
                Ok(v) => v,
                Err(e) => return Err(error(format!("reveal_token error: {:?}", e))),
            };
        let shared_key: CAggregatePublicKey =
            match CanonicalDeserialize::deserialize_compressed(shared_key.as_slice()) {
                Ok(v) => v,
                Err(e) => return Err(error(format!("masked error: {:?}", e))),
            };
        let encoded: CCard = match CanonicalDeserialize::deserialize_compressed(encoded.as_slice())
        {
            Ok(v) => v,
            Err(e) => return Err(error(format!("reveal_proof error: {:?}", e))),
        };

        let masked: CMaskedCard = match CCardProtocol::mask_only(&params, &shared_key, &encoded, &CScalar::one())
        {
            Ok(v) => v,
            Err(e) => return Err(error(format!("mask error: {:?}", e))),
        };

        let mut res = Vec::with_capacity(masked.compressed_size());
        match masked.serialize_compressed(&mut res) {
            Ok(v) => v,
            Err(e) => return Err(error(format!("serialize error: {:?}", e))),
        };

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
