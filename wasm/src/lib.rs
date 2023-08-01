#![allow(non_snake_case)]
#![allow(dead_code)]

use std::collections::VecDeque;

use ark_ec::AffineRepr;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use ark_std::{UniformRand, Zero};
use barnett_smart_card_protocol::Reveal;
use rand::{rngs::ThreadRng, thread_rng};
use serde_wasm_bindgen::to_value;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

#[cfg(feature = "js_log")]
use web_sys::console;

use ark_bn254::{fr::FrConfig, g1::Config, Fr, G1Affine, G1Projective};
use ark_ec::models::short_weierstrass::{Affine, Projective};
use ark_ff::fields::models::fp::{Fp, MontBackend};
use ark_std::One;
use barnett_smart_card_protocol::{
    discrete_log_cards::{
        DLCards, MaskedCard as InMaskedCard, Parameters, RevealToken as InRevealToken,
    },
    BarnettSmartProtocol,
};
use proof_essentials::{
    homomorphic_encryption::el_gamal::{ElGamal, Plaintext},
    utils::{permutation::Permutation as CPermutation, rand::sample_vector},
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

type CSecretKey = Fp<MontBackend<FrConfig, 4>, 4>;

#[derive(PartialEq, Clone, Copy, Eq)]
pub enum Suite {
    Greet,
    Poison,
}

#[derive(PartialEq, Clone, Eq, Copy)]
pub struct MurderCard {
    suite: Suite,
}

impl MurderCard {
    pub fn new(suite: Suite) -> Self {
        Self { suite }
    }
}

impl std::fmt::Debug for MurderCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let suite = match self.suite {
            Suite::Greet => "G",
            Suite::Poison => "P",
        };

        write!(f, "{}", suite)
    }
}

// Generate a public parameter to setup game instance
// @param {number] m- deck size in 1st dimension
// @param {number] n - deck size in 2nd dimension
// @returns [CardParameters]
#[wasm_bindgen]
pub fn setup(cardrand: &mut CardRand, m: usize, n: usize) -> Result<CardParameters, JsValue> {
    let rng = &mut cardrand.v;
    CCardProtocol::setup(rng, m, n)
        .map(|v| {
            let v = CardParameters { v };

            #[cfg(feature = "js_log")]
            console::log_1(&format!("setup ok: {:?}", v.serialAndEnbase64()).into());

            v
        })
        .map_err(|e| {
            #[cfg(feature = "js_log")]
            console::log_1(&format!("setup error: {:?}", e).into());

            JsValue::from_str(&e.to_string())
        })
}

// Generate a game key pair
// @param {string} name - Player name
// @returns [PublicKey, SecretKey]
#[wasm_bindgen]
pub fn keygen(
    cardrand: &mut CardRand,
    parameters: &CardParameters,
    name: &PlayerName,
) -> Result<GameKeyAndProof, JsValue> {
    let rng = &mut cardrand.v;
    let v = CCardProtocol::player_keygen(rng, &parameters.v)
        .map(|v| {
            #[cfg(feature = "js_log")]
            console::log_1(
                &format!(
                    "keygen ok: PublicKey: {:?} SecretKey: {:?}",
                    PublicKey { v: v.0 }.serialAndEnbase64(),
                    SecretKey { v: v.1 }.serialAndEnbase64()
                )
                .into(),
            );

            v
        })
        .map_err(|e| {
            #[cfg(feature = "js_log")]
            console::log_1(&format!("keygen error: {:?}", e).into());

            JsValue::from_str(&e.to_string())
        })?;

    let pubKey = PublicKey { v: v.0 };
    let secKey = SecretKey { v: v.1 };

    CCardProtocol::prove_key_ownership(
        rng,
        &parameters.v,
        &v.0,
        &v.1,
        &name.v.as_bytes().to_owned(),
    )
    .map(|v| {
        #[cfg(feature = "js_log")]
        console::log_1(&format!("keygen ok: {:?}", v).into());

        GameKeyAndProof {
            pubKey: pubKey,
            secKey: secKey,
            keyownershipProof: KeyownershipProof { v },
        }
    })
    .map_err(|e| {
        #[cfg(feature = "js_log")]
        console::log_1(&format!("keygen error: {:?}", e).into());

        JsValue::from_str(&e.to_string())
    })
}

// Mask encoded cards as masked cards
// Qparam {CardParameters] parameters- The public parameters of the game
// @param {AggregatePublicKey} sharedKey- The public aggregate key
// @param {Card} encoded - An initial encoded card
// @returns [MaskedCard}
#[wasm_bindgen]
pub fn mask(
    parameters: &CardParameters,
    sharedKey: &AggregatePublicKey,
    encoded: &Card,
) -> Result<MaskedCard, JsValue> {
    CCardProtocol::mask_only(&parameters.v, &sharedKey.v, &encoded.v, &CScalar::one())
        .map(|v| {
            #[cfg(feature = "js_log")]
            console::log_1(&format!("mask ok: {:?}", v).into());

            MaskedCard { v: v }
        })
        .map_err(|e| {
            #[cfg(feature = "js_log")]
            console::log_1(&format!("mask error: {:?}", e).into());

            JsValue::from_str(&e.to_string())
        })
}

// Shuffle and remask the deck of cards with a random permutation
// Qparam {CardParameters] parameters- The public parameters of the game
// Qparam {AggregatePublicKey} sharedKey- The public aggregate key
// @param {MaskedCard[]} deck - The deck of masked cards
// Qparam {Permutation} permutation - The deck of masked cards
// @returns [MaskedCard[], ProofShuffle]
#[wasm_bindgen]
pub fn shuffleAndRemask(
    cardrand: &mut CardRand,
    parameters: &CardParameters,
    sharedKey: &AggregatePublicKey,
    deck: &VMaskedCard,
    permutation: &Permutation,
) -> Result<MaskedCardsAndShuffleProof, JsValue> {
    let rng = &mut cardrand.v;
    let deck: Vec<CMaskedCard> = deck.v.iter().map(|v| v.v).collect();
    let masking_factors: Vec<CScalar> = sample_vector(rng, deck.len());

    CCardProtocol::shuffle_and_remask(
        rng,
        &parameters.v,
        &sharedKey.v,
        &deck,
        &masking_factors,
        &permutation.v,
    )
    .map(|v| {
        let deck: VecDeque<MaskedCard> = v.0.iter().map(|v| MaskedCard { v: v.clone() }).collect();
        let vdeck = VMaskedCard { v: deck };
        let shuffleProof = ShuffleProof { v: v.1 };

        #[cfg(feature = "js_log")]
        console::log_1(
            &format!(
                "shuffleAndRemask ok: VmaskedCard: {:?} ShuffleProof: {:?}",
                vdeck.serialAndEnbase64(),
                shuffleProof.serialAndEnbase64()
            )
            .into(),
        );

        MaskedCardsAndShuffleProof {
            vmaskedCard: vdeck,
            shuffleProof,
        }
    })
    .map_err(|e| {
        #[cfg(feature = "js_log")]
        console::log_1(&format!("shuffleAndRemask error: {:?}", e).into());

        JsValue::from_str(&e.to_string())
    })
}

// Compute reveal token for a given masked card
// @param [CardParameters] parameters- The public parameters of the game
// Qparam {SecretKey] parameters- A game secret key
// @param {PublicKey} secretKey- A game public key
// @param {MaskedCard} masked- A masked card
// @returns [RevealToken, ProofReveal]
#[wasm_bindgen]
pub fn computeRevealToken(
    cardrand: &mut CardRand,
    parameters: &CardParameters,
    secretKey: &SecretKey,
    publicKey: &PublicKey,
    masked: &MaskedCard,
) -> Result<RevealTokenAndProof, JsValue> {
    let rng = &mut cardrand.v;
    CCardProtocol::compute_reveal_token(rng, &parameters.v, &secretKey.v, &publicKey.v, &masked.v)
        .map(|v| {
            #[cfg(feature = "js_log")]
            console::log_1(&format!("computeRevealToken ok: {:?}", v).into());

            RevealTokenAndProof {
                revealToken: RevealToken { v: v.0 },
                revealProof: RevealProof { v: v.1 },
            }
        })
        .map_err(|e| {
            #[cfg(feature = "js_log")]
            console::log_1(&format!("computeRevealToken error: {:?}", e).into());

            JsValue::from_str(&e.to_string())
        })
}

// Reveal a masked card
// @param [RevealToken[]]- Reveal tokens for a masked card
// Qparam [MaskedCard}- A masked card
// @returns [MaskedCard]
#[wasm_bindgen]
pub fn reveal(revealTokens: VRevealToken, masked: &MaskedCard) -> Result<Card, JsValue> {
    let zero = CRevealToken::zero();
    let mut aggregate_token = zero;
    for revealToken in revealTokens.v {
        aggregate_token = aggregate_token + revealToken.v;
    }

    aggregate_token
        .reveal(&masked.v)
        .map(|v| {
            #[cfg(feature = "js_log")]
            console::log_1(&format!("reveal ok: {:?}", v).into());

            Card { v }
        })
        .map_err(|e| {
            #[cfg(feature = "js_log")]
            console::log_1(&format!("reveal error: {:?}", e).into());

            JsValue::from_str(&e.to_string())
        })
}

// Generate `num' of encoded cards
// @param {number] num - deck size
// @returns Card[]
#[wasm_bindgen]
pub fn encodeCards(cardrand: &mut CardRand, num: usize) -> VCard {
    let rng = &mut cardrand.v;

    // let mut map: HashMap<CCard, MurderCard> = HashMap::new();
    let plaintexts = (0..num).map(|_| CCard::rand(rng)).collect::<Vec<_>>();

    // // 4 guests
    // for i in 0..40 {
    //     let greet_card = MurderCard::new(Suite::Greet);
    //     map.insert(plaintexts[i], greet_card);
    // }

    // // 2 killers
    // for i in 0..2 {
    //     for j in 0..5 {
    //         // 5 poison cards
    //         let poison_card = MurderCard::new(Suite::Poison);
    //         map.insert(plaintexts[40 + i * 10 + j], poison_card);
    //     }
    //     for j in 5..10 {
    //         // 5 greet cards
    //         let greet_card = MurderCard::new(Suite::Greet);
    //         map.insert(plaintexts[40 + i * 10 + j], greet_card);
    //     }
    // }

    let vcard: VecDeque<Card> = plaintexts.iter().map(|v| Card { v: v.clone() }).collect();

    VCard { v: vcard }

    // (plaintexts, map)
}

#[wasm_bindgen]
pub struct PlayerName {
    v: String,
}

#[wasm_bindgen]
impl PlayerName {
    #[wasm_bindgen]
    pub fn NewPlayerName(name: &str) -> Self {
        Self {
            v: name.to_string(),
        }
    }

    #[wasm_bindgen]
    pub fn serialAndEnbase64(&self) -> Result<String, JsValue> {
        let mut data = Vec::with_capacity(self.v.compressed_size());
        self.v
            .serialize_compressed(&mut data)
            .map_err(|e| JsValue::from(&format!("serialAndEnbase64 err: {:?}", e)))?;
        Ok(base64::encode(data))
    }

    #[wasm_bindgen]
    pub fn debase64AndDeserial(data: &str) -> Result<PlayerName, JsValue> {
        let data = base64::decode(data)
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err1: {:?}", e)))?;
        let v = CanonicalDeserialize::deserialize_compressed(data.as_slice())
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err2: {:?}", e)))?;
        Ok(Self { v })
    }
}

#[wasm_bindgen]
pub struct CardRand {
    v: ThreadRng,
}

#[wasm_bindgen]
impl CardRand {
    #[wasm_bindgen]
    pub fn buildRand() -> Self {
        let rng = thread_rng();
        return Self { v: rng };
    }
}

// Public parameters of the game
#[wasm_bindgen]
pub struct CardParameters {
    v: CCardParameters,
}

// A game public key
#[wasm_bindgen]
#[derive(Clone)]
pub struct PublicKey {
    v: CPublicKey,
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct VPublicKey {
    v: VecDeque<PublicKey>,
}

#[wasm_bindgen]
impl VPublicKey {
    pub fn newVPublicKey() -> Self {
        return Self { v: VecDeque::new() };
    }

    #[wasm_bindgen]
    pub fn len(&self) -> usize {
        self.v.len()
    }

    #[wasm_bindgen]
    pub fn push(&mut self, d: &PublicKey) {
        self.v.push_back(d.clone());
    }

    #[wasm_bindgen]
    pub fn pop(&mut self) -> Result<PublicKey, JsValue> {
        self.v.pop_front().ok_or(JsValue::from("pop err!!!"))
    }

    #[wasm_bindgen]
    pub fn serialAndEnbase64(&self) -> Result<Box<[JsValue]>, JsValue> {
        let mut vs: Vec<JsValue> = Vec::new();
        for v in &self.v {
            vs.push(to_value(&v.serialAndEnbase64()?)?);
        }
        Ok(vs.into_boxed_slice())
    }
}

// A game secret key
#[wasm_bindgen]
#[derive(Clone)]
pub struct SecretKey {
    v: CSecretKey,
}

// Zero-knowledge proof of game key ownership
#[wasm_bindgen]
#[derive(Clone)]
pub struct KeyownershipProof {
    v: CKeyownershipProof,
}

// A game public key and secret key
#[wasm_bindgen]
pub struct GameKeyAndProof {
    pubKey: PublicKey,
    secKey: SecretKey,
    keyownershipProof: KeyownershipProof,
}

#[wasm_bindgen]
impl GameKeyAndProof {
    #[wasm_bindgen(js_name = getPubKey)]
    pub fn getPubKey(&self) -> PublicKey {
        return self.pubKey.clone();
    }
    #[wasm_bindgen(js_name = getSecKey)]
    pub fn getSecKey(&self) -> SecretKey {
        return self.secKey.clone();
    }
    #[wasm_bindgen(js_name = getProof)]
    pub fn getProof(&self) -> KeyownershipProof {
        return self.keyownershipProof.clone();
    }
}

// An aggregate public key
#[wasm_bindgen]
pub struct AggregatePublicKey {
    v: CAggregatePublicKey,
}

// An initial encoded card
#[wasm_bindgen]
#[derive(Clone)]
pub struct Card {
    v: CCard,
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct VCard {
    v: VecDeque<Card>,
}

#[wasm_bindgen]
impl VCard {
    #[wasm_bindgen]
    pub fn newVCard() -> Self {
        return Self { v: VecDeque::new() };
    }

    #[wasm_bindgen]
    pub fn len(&self) -> usize {
        self.v.len()
    }

    #[wasm_bindgen]
    pub fn push(&mut self, d: &Card) {
        self.v.push_back(d.clone());
    }

    #[wasm_bindgen]
    pub fn pop(&mut self) -> Result<Card, JsValue> {
        self.v.pop_front().ok_or(JsValue::from("pop err!!!"))
    }

    #[wasm_bindgen]
    pub fn serialAndEnbase64(&self) -> Result<Box<[JsValue]>, JsValue> {
        let mut vs: Vec<JsValue> = Vec::new();
        for v in &self.v {
            vs.push(to_value(&v.serialAndEnbase64()?)?);
        }
        Ok(vs.into_boxed_slice())
    }
}

// A masked card
#[wasm_bindgen]
#[derive(Clone)]
pub struct MaskedCard {
    v: CMaskedCard,
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct VMaskedCard {
    v: VecDeque<MaskedCard>,
}

#[wasm_bindgen]
impl VMaskedCard {
    #[wasm_bindgen]
    pub fn newVMaskedCard() -> Self {
        return Self { v: VecDeque::new() };
    }

    #[wasm_bindgen]
    pub fn push(&mut self, d: &MaskedCard) {
        self.v.push_back(d.clone());
    }

    #[wasm_bindgen]
    pub fn pop(&mut self) -> Result<MaskedCard, JsValue> {
        self.v.pop_front().ok_or(JsValue::from("pop err!!!"))
    }

    #[wasm_bindgen]
    pub fn len(&self) -> usize {
        self.v.len()
    }

    #[wasm_bindgen]
    pub fn serialAndEnbase64(&self) -> Result<Box<[JsValue]>, JsValue> {
        let mut vs: Vec<JsValue> = Vec::new();
        for v in &self.v {
            vs.push(to_value(&v.serialAndEnbase64()?)?);
        }
        Ok(vs.into_boxed_slice())
    }
}

// Zero-knowledge proof of deck shuffling
#[wasm_bindgen]
#[derive(Clone)]
pub struct ShuffleProof {
    v: CShuffleProof,
}

#[wasm_bindgen]
pub struct MaskedCardsAndShuffleProof {
    vmaskedCard: VMaskedCard,
    shuffleProof: ShuffleProof,
}

#[wasm_bindgen]
impl MaskedCardsAndShuffleProof {
    #[wasm_bindgen(js_name = getMaskedCards)]
    pub fn getMaskedCards(&self) -> VMaskedCard {
        self.vmaskedCard.clone()
    }
    #[wasm_bindgen(js_name = getShuffleProof)]
    pub fn getShuffleProof(&self) -> ShuffleProof {
        self.shuffleProof.clone()
    }
}

// A reveal token for a masked card
#[wasm_bindgen]
#[derive(Clone)]
pub struct RevealToken {
    v: CRevealToken,
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct VRevealToken {
    v: VecDeque<RevealToken>,
}

#[wasm_bindgen]
impl VRevealToken {
    pub fn newVRevealToken() -> Self {
        return Self { v: VecDeque::new() };
    }

    #[wasm_bindgen]
    pub fn len(&self) -> usize {
        self.v.len()
    }

    #[wasm_bindgen]
    pub fn push(&mut self, d: &RevealToken) {
        self.v.push_back(d.clone());
    }

    #[wasm_bindgen]
    pub fn pop(&mut self) -> Result<RevealToken, JsValue> {
        self.v.pop_front().ok_or(JsValue::from("pop err!!!"))
    }

    #[wasm_bindgen]
    pub fn serialAndEnbase64(&self) -> Result<Box<[JsValue]>, JsValue> {
        let mut vs: Vec<JsValue> = Vec::new();
        for v in &self.v {
            vs.push(to_value(&v.serialAndEnbase64()?)?);
        }
        Ok(vs.into_boxed_slice())
    }
}

// Zero-knowledge proof of card reveal token
#[wasm_bindgen]
#[derive(Clone)]
pub struct RevealProof {
    v: CRevealProof,
}

#[wasm_bindgen]
pub struct RevealTokenAndProof {
    revealToken: RevealToken,
    revealProof: RevealProof,
}

#[wasm_bindgen]
impl RevealTokenAndProof {
    #[wasm_bindgen(js_name = getRevealToken)]
    pub fn getRevealToken(&mut self) -> RevealToken {
        self.revealToken.clone()
    }
    #[wasm_bindgen(js_name = getRevealProof)]
    pub fn getRevealProof(&mut self) -> RevealProof {
        self.revealProof.clone()
    }
}

// A permutation for deck shuffling
#[wasm_bindgen]
pub struct Permutation {
    v: CPermutation,
}

#[wasm_bindgen]
impl Permutation {
    #[wasm_bindgen]
    pub fn newPermutation(cardrand: &mut CardRand, size: usize) -> Self {
        let rng = &mut cardrand.v;
        let v = CPermutation::new(rng, size);
        return Permutation { v };
    }
}

#[wasm_bindgen]
impl CardParameters {
    #[wasm_bindgen]
    pub fn serialAndEnbase64(&self) -> Result<String, JsValue> {
        let mut data = Vec::with_capacity(self.v.compressed_size());
        self.v
            .serialize_compressed(&mut data)
            .map_err(|e| JsValue::from(&format!("serialAndEnbase64 err: {:?}", e)))?;
        Ok(base64::encode(data))
    }

    #[wasm_bindgen]
    pub fn debase64AndDeserial(data: &str) -> Result<CardParameters, JsValue> {
        let data = base64::decode(data)
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err1: {:?}", e)))?;
        let v = CanonicalDeserialize::deserialize_compressed(data.as_slice())
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err2: {:?}", e)))?;
        Ok(Self { v })
    }
}

#[wasm_bindgen]
impl PublicKey {
    #[wasm_bindgen]
    pub fn serialAndEnbase64(&self) -> Result<String, JsValue> {
        let mut data = Vec::with_capacity(self.v.compressed_size());
        self.v
            .serialize_compressed(&mut data)
            .map_err(|e| JsValue::from(&format!("serialAndEnbase64 err: {:?}", e)))?;
        Ok(base64::encode(data))
    }

    #[wasm_bindgen]
    pub fn debase64AndDeserial(data: &str) -> Result<PublicKey, JsValue> {
        let data = base64::decode(data)
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err1: {:?}", e)))?;
        let v = CanonicalDeserialize::deserialize_compressed(data.as_slice())
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err2: {:?}", e)))?;
        Ok(Self { v })
    }
}

#[wasm_bindgen]
impl SecretKey {
    #[wasm_bindgen]
    pub fn serialAndEnbase64(&self) -> Result<String, JsValue> {
        let mut data = Vec::with_capacity(self.v.compressed_size());
        self.v
            .serialize_compressed(&mut data)
            .map_err(|e| JsValue::from(&format!("serialAndEnbase64 err: {:?}", e)))?;
        Ok(base64::encode(data))
    }

    #[wasm_bindgen]
    pub fn debase64AndDeserial(data: &str) -> Result<SecretKey, JsValue> {
        let data = base64::decode(data)
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err1: {:?}", e)))?;
        let v = CanonicalDeserialize::deserialize_compressed(data.as_slice())
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err2: {:?}", e)))?;
        Ok(Self { v })
    }
}

#[wasm_bindgen]
impl KeyownershipProof {
    #[wasm_bindgen]
    pub fn serialAndEnbase64(&self) -> Result<String, JsValue> {
        let mut data = Vec::with_capacity(self.v.compressed_size());
        self.v
            .serialize_compressed(&mut data)
            .map_err(|e| JsValue::from(&format!("serialAndEnbase64 err: {:?}", e)))?;
        Ok(base64::encode(data))
    }

    #[wasm_bindgen]
    pub fn debase64AndDeserial(data: &str) -> Result<KeyownershipProof, JsValue> {
        let data = base64::decode(data)
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err1: {:?}", e)))?;
        let v = CanonicalDeserialize::deserialize_compressed(data.as_slice())
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err2: {:?}", e)))?;
        Ok(Self { v })
    }
}

#[wasm_bindgen]
impl AggregatePublicKey {
    #[wasm_bindgen]
    pub fn serialAndEnbase64(&self) -> Result<String, JsValue> {
        let mut data = Vec::with_capacity(self.v.compressed_size());
        self.v
            .serialize_compressed(&mut data)
            .map_err(|e| JsValue::from(&format!("serialAndEnbase64 err: {:?}", e)))?;
        Ok(base64::encode(data))
    }

    #[wasm_bindgen]
    pub fn debase64AndDeserial(data: &str) -> Result<AggregatePublicKey, JsValue> {
        let data = base64::decode(data)
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err1: {:?}", e)))?;
        let v = CanonicalDeserialize::deserialize_compressed(data.as_slice())
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err2: {:?}", e)))?;
        Ok(Self { v })
    }
}

#[wasm_bindgen]
impl Card {
    #[wasm_bindgen]
    pub fn serialAndEnbase64(&self) -> Result<String, JsValue> {
        let mut data = Vec::with_capacity(self.v.compressed_size());
        self.v
            .serialize_compressed(&mut data)
            .map_err(|e| JsValue::from(&format!("serialAndEnbase64 err: {:?}", e)))?;
        Ok(base64::encode(data))
    }

    #[wasm_bindgen]
    pub fn debase64AndDeserial(data: &str) -> Result<Card, JsValue> {
        let data = base64::decode(data)
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err1: {:?}", e)))?;
        let v = CanonicalDeserialize::deserialize_compressed(data.as_slice())
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err2: {:?}", e)))?;
        Ok(Self { v })
    }
}

#[wasm_bindgen]
impl MaskedCard {
    #[wasm_bindgen]
    pub fn rand(cardrand: &mut CardRand) -> Self {
        return Self {
            v: CMaskedCard::rand(&mut cardrand.v),
        };
    }

    #[wasm_bindgen]
    pub fn serialAndEnbase64(&self) -> Result<String, JsValue> {
        let mut data = Vec::with_capacity(self.v.compressed_size());
        self.v
            .serialize_compressed(&mut data)
            .map_err(|e| JsValue::from(&format!("serialAndEnbase64 err: {:?}", e)))?;
        Ok(base64::encode(data))
    }

    #[wasm_bindgen]
    pub fn debase64AndDeserial(data: &str) -> Result<MaskedCard, JsValue> {
        let data = base64::decode(data)
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err1: {:?}", e)))?;
        let v = CanonicalDeserialize::deserialize_compressed(data.as_slice())
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err2: {:?}", e)))?;
        Ok(Self { v })
    }
}

#[wasm_bindgen]
impl ShuffleProof {
    #[wasm_bindgen]
    pub fn serialAndEnbase64(&self) -> Result<String, JsValue> {
        let mut data = Vec::with_capacity(self.v.compressed_size());
        self.v
            .serialize_compressed(&mut data)
            .map_err(|e| JsValue::from(&format!("serialAndEnbase64 err: {:?}", e)))?;
        Ok(base64::encode(data))
    }

    #[wasm_bindgen]
    pub fn debase64AndDeserial(data: &str) -> Result<ShuffleProof, JsValue> {
        let data = base64::decode(data)
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err1: {:?}", e)))?;
        let v = CanonicalDeserialize::deserialize_compressed(data.as_slice())
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err2: {:?}", e)))?;
        Ok(Self { v })
    }
}

#[wasm_bindgen]
impl RevealToken {
    #[wasm_bindgen]
    pub fn serialAndEnbase64(&self) -> Result<String, JsValue> {
        let mut data = Vec::with_capacity(self.v.compressed_size());
        self.v
            .serialize_compressed(&mut data)
            .map_err(|e| JsValue::from(&format!("serialAndEnbase64 err: {:?}", e)))?;
        Ok(base64::encode(data))
    }

    #[wasm_bindgen]
    pub fn debase64AndDeserial(data: &str) -> Result<RevealToken, JsValue> {
        let data = base64::decode(data)
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err1: {:?}", e)))?;
        let v = CanonicalDeserialize::deserialize_compressed(data.as_slice())
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err2: {:?}", e)))?;
        Ok(Self { v })
    }
}

#[wasm_bindgen]
impl RevealProof {
    #[wasm_bindgen]
    pub fn serialAndEnbase64(&self) -> Result<String, JsValue> {
        let mut data = Vec::with_capacity(self.v.compressed_size());
        self.v
            .serialize_compressed(&mut data)
            .map_err(|e| JsValue::from(&format!("serialAndEnbase64 err: {:?}", e)))?;
        Ok(base64::encode(data))
    }

    #[wasm_bindgen]
    pub fn debase64AndDeserial(data: &str) -> Result<RevealProof, JsValue> {
        let data = base64::decode(data)
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err1: {:?}", e)))?;
        let v = CanonicalDeserialize::deserialize_compressed(data.as_slice())
            .map_err(|e| JsValue::from(&format!("debase64AndDeserial err2: {:?}", e)))?;
        Ok(Self { v })
    }
}

#[wasm_bindgen]
pub fn contract_verify_key_ownership_mock(
    params: &CardParameters,
    pub_key: &PublicKey,
    name: &PlayerName,
    key_proof: &KeyownershipProof,
) -> Result<bool, JsValue> {
    let res = CCardProtocol::verify_key_ownership(
        &params.v,
        &pub_key.v,
        &name.v.as_bytes().to_owned(),
        &key_proof.v,
    )
    .map(|v| {
        println!("verify_key_ownership verify_key_ownership ok: {:?}", v);
        v
    })
    .map_err(|e| {
        println!("verify_key_ownership verify_key_ownership err: {:?}", e);
        e
    })
    .is_ok();

    Ok(res)
}

#[wasm_bindgen]
pub fn contract_compute_aggregate_key_mock(
    pub_keys: &VPublicKey,
) -> Result<AggregatePublicKey, JsValue> {
    let mut pub_keys2: Vec<CPublicKey> = Vec::new();
    for v_pub_key in &pub_keys.v {
        pub_keys2.push(v_pub_key.v)
    }

    let mut aggregate_pub_key = CAggregatePublicKey::zero();
    for v_pub_key in pub_keys2 {
        aggregate_pub_key = (aggregate_pub_key + v_pub_key).into();
    }

    let res = AggregatePublicKey {
        v: aggregate_pub_key,
    };

    Ok(res)
}

#[wasm_bindgen]
pub fn contract_verify_shuffle_mock(
    params: &CardParameters,
    shared_key: &PublicKey,
    cur_decks: &VMaskedCard,
    new_decks: &VMaskedCard,
    shuffle_proof: &ShuffleProof,
) -> Result<bool, JsValue> {
    let cur_decks: Vec<CMaskedCard> = cur_decks.v.iter().map(|v| v.v).collect();
    let new_decks: Vec<CMaskedCard> = new_decks.v.iter().map(|v| v.v).collect();

    let res = CCardProtocol::verify_shuffle(
        &params.v,
        &shared_key.v,
        &cur_decks,
        &new_decks,
        &shuffle_proof.v,
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

    Ok(res)
}

#[wasm_bindgen]
pub fn contract_verify_reveal_mock(
    params: &CardParameters,
    pub_key: &PublicKey,
    reveal_token: &RevealToken,
    masked: &MaskedCard,
    reveal_proof: &RevealProof,
) -> Result<bool, JsValue> {
    let res = CCardProtocol::verify_reveal(
        &params.v,
        &pub_key.v,
        &reveal_token.v,
        &masked.v,
        &reveal_proof.v,
    )
    .map(|v| {
        println!("verify_reveal verify_reveal ok: {:?}", v);
        v
    })
    .map_err(|e| {
        println!("verify_reveal verify_reveal err: {:?}", e);
        e
    })
    .is_ok();

    Ok(res)
}

#[wasm_bindgen]
pub fn contract_reveal_mock(
    revealTokens: VRevealToken,
    masked: &MaskedCard,
) -> Result<Card, JsValue> {
    reveal(revealTokens, masked)
}

#[wasm_bindgen]
pub fn contract_mask_mock(
    params: &CardParameters,
    shared_key: &AggregatePublicKey,
    encoded: &Card,
) -> Result<MaskedCard, JsValue> {
    mask(params, shared_key, &encoded)
}
