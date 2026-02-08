use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul};
use digest::{ExtendableOutput, Update};
use keccak::f1600;
use rand::rngs::OsRng;
use rand::RngCore;
use sha3::Shake128;
use std::slice;

// ---------------------------------------------------------------------------
// Scalar FFI
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn sigma_scalar_identity(out: *mut u8) {
    let zero = Scalar::ZERO;
    std::ptr::copy_nonoverlapping(zero.as_bytes().as_ptr(), out, 32);
}

#[no_mangle]
pub unsafe extern "C" fn sigma_scalar_add(a: *const u8, b: *const u8, out: *mut u8) {
    let sa = read_scalar(a);
    let sb = read_scalar(b);
    let result = sa + sb;
    std::ptr::copy_nonoverlapping(result.as_bytes().as_ptr(), out, 32);
}

#[no_mangle]
pub unsafe extern "C" fn sigma_scalar_mul(a: *const u8, b: *const u8, out: *mut u8) {
    let sa = read_scalar(a);
    let sb = read_scalar(b);
    let result = sa * sb;
    std::ptr::copy_nonoverlapping(result.as_bytes().as_ptr(), out, 32);
}

#[no_mangle]
pub unsafe extern "C" fn sigma_scalar_neg(a: *const u8, out: *mut u8) {
    let sa = read_scalar(a);
    let result = -sa;
    std::ptr::copy_nonoverlapping(result.as_bytes().as_ptr(), out, 32);
}

#[no_mangle]
pub unsafe extern "C" fn sigma_scalar_eq(a: *const u8, b: *const u8) -> i32 {
    let sa = read_scalar(a);
    let sb = read_scalar(b);
    if sa == sb { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn sigma_scalar_deserialize(input: *const u8, out: *mut u8) -> i32 {
    let mut bytes = [0u8; 32];
    std::ptr::copy_nonoverlapping(input, bytes.as_mut_ptr(), 32);
    match Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)) {
        Some(s) => {
            std::ptr::copy_nonoverlapping(s.as_bytes().as_ptr(), out, 32);
            0
        }
        None => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn sigma_scalar_from_wide_bytes(input: *const u8, out: *mut u8) {
    let mut wide = [0u8; 64];
    std::ptr::copy_nonoverlapping(input, wide.as_mut_ptr(), 64);
    let s = Scalar::from_bytes_mod_order_wide(&wide);
    std::ptr::copy_nonoverlapping(s.as_bytes().as_ptr(), out, 32);
}

unsafe fn read_scalar(ptr: *const u8) -> Scalar {
    let mut bytes = [0u8; 32];
    std::ptr::copy_nonoverlapping(ptr, bytes.as_mut_ptr(), 32);
    // We trust that the bytes are a valid canonical scalar (already deserialized)
    Scalar::from_bytes_mod_order(bytes)
}

// ---------------------------------------------------------------------------
// Group FFI (Ristretto255)
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn sigma_group_identity(out: *mut u8) {
    let id = RistrettoPoint::identity().compress();
    std::ptr::copy_nonoverlapping(id.as_bytes().as_ptr(), out, 32);
}

#[no_mangle]
pub unsafe extern "C" fn sigma_group_generator(out: *mut u8) {
    std::ptr::copy_nonoverlapping(
        RISTRETTO_BASEPOINT_COMPRESSED.as_bytes().as_ptr(),
        out,
        32,
    );
}

#[no_mangle]
pub unsafe extern "C" fn sigma_group_add(a: *const u8, b: *const u8, out: *mut u8) {
    let pa = decompress(a);
    let pb = decompress(b);
    let result = pa + pb;
    let compressed = result.compress();
    std::ptr::copy_nonoverlapping(compressed.as_bytes().as_ptr(), out, 32);
}

#[no_mangle]
pub unsafe extern "C" fn sigma_group_neg(a: *const u8, out: *mut u8) {
    let pa = decompress(a);
    let result = -pa;
    let compressed = result.compress();
    std::ptr::copy_nonoverlapping(compressed.as_bytes().as_ptr(), out, 32);
}

#[no_mangle]
pub unsafe extern "C" fn sigma_group_scalar_mul(point: *const u8, scalar: *const u8, out: *mut u8) {
    let p = decompress(point);
    let s = read_scalar(scalar);
    let result = p * s;
    let compressed = result.compress();
    std::ptr::copy_nonoverlapping(compressed.as_bytes().as_ptr(), out, 32);
}

#[no_mangle]
pub unsafe extern "C" fn sigma_group_eq(a: *const u8, b: *const u8) -> i32 {
    let pa = decompress(a);
    let pb = decompress(b);
    if pa == pb { 1 } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn sigma_group_deserialize(input: *const u8, out: *mut u8) -> i32 {
    let mut bytes = [0u8; 32];
    std::ptr::copy_nonoverlapping(input, bytes.as_mut_ptr(), 32);
    let compressed = CompressedRistretto(bytes);
    match compressed.decompress() {
        Some(_p) => {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, 32);
            0
        }
        None => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn sigma_group_msm(
    n: usize,
    scalars_ptr: *const u8,
    points_ptr: *const u8,
    out: *mut u8,
) {
    let mut scalars = Vec::with_capacity(n);
    let mut points = Vec::with_capacity(n);
    for i in 0..n {
        scalars.push(read_scalar(scalars_ptr.add(i * 32)));
        points.push(decompress(points_ptr.add(i * 32)));
    }
    let result = RistrettoPoint::multiscalar_mul(&scalars, &points);
    let compressed = result.compress();
    std::ptr::copy_nonoverlapping(compressed.as_bytes().as_ptr(), out, 32);
}

#[no_mangle]
pub unsafe extern "C" fn sigma_group_from_uniform_bytes(input: *const u8, out: *mut u8) {
    let mut wide = [0u8; 64];
    std::ptr::copy_nonoverlapping(input, wide.as_mut_ptr(), 64);
    let point = RistrettoPoint::from_uniform_bytes(&wide);
    let compressed = point.compress();
    std::ptr::copy_nonoverlapping(compressed.as_bytes().as_ptr(), out, 32);
}

unsafe fn decompress(ptr: *const u8) -> RistrettoPoint {
    let mut bytes = [0u8; 32];
    std::ptr::copy_nonoverlapping(ptr, bytes.as_mut_ptr(), 32);
    CompressedRistretto(bytes)
        .decompress()
        .expect("invalid Ristretto point")
}

// ---------------------------------------------------------------------------
// SHAKE128 FFI
// ---------------------------------------------------------------------------

pub struct ShakeSponge {
    state: Shake128,
}

#[no_mangle]
pub unsafe extern "C" fn sigma_shake128_new(
    iv_ptr: *const u8,
    iv_len: usize,
) -> *mut ShakeSponge {
    let iv_bytes = slice::from_raw_parts(iv_ptr, iv_len);
    // Pad IV to 168 bytes (SHAKE128 rate)
    let mut padded = vec![0u8; 168];
    let copy_len = iv_len.min(168);
    padded[..copy_len].copy_from_slice(&iv_bytes[..copy_len]);
    let mut hasher = Shake128::default();
    hasher.update(&padded);
    let sponge = ShakeSponge { state: hasher };
    Box::into_raw(Box::new(sponge))
}

#[no_mangle]
pub unsafe extern "C" fn sigma_shake128_clone_and_absorb(
    sponge: *const ShakeSponge,
    data: *const u8,
    len: usize,
) -> *mut ShakeSponge {
    let s = &*sponge;
    let mut cloned = s.state.clone();
    let bytes = slice::from_raw_parts(data, len);
    cloned.update(bytes);
    Box::into_raw(Box::new(ShakeSponge { state: cloned }))
}

#[no_mangle]
pub unsafe extern "C" fn sigma_shake128_squeeze_bytes(
    sponge: *const ShakeSponge,
    len: usize,
    out: *mut u8,
) {
    let s = &*sponge;
    // Clone so the original state is unchanged
    let cloned = s.state.clone();
    let reader = cloned.finalize_xof();
    let mut buf = vec![0u8; len];
    digest::XofReader::read(&mut { reader }, &mut buf);
    std::ptr::copy_nonoverlapping(buf.as_ptr(), out, len);
}

#[no_mangle]
pub unsafe extern "C" fn sigma_shake128_clone(sponge: *const ShakeSponge) -> *mut ShakeSponge {
    let s = &*sponge;
    let cloned = ShakeSponge {
        state: s.state.clone(),
    };
    Box::into_raw(Box::new(cloned))
}

#[no_mangle]
pub unsafe extern "C" fn sigma_shake128_free(sponge: *mut ShakeSponge) {
    if !sponge.is_null() {
        drop(Box::from_raw(sponge));
    }
}

// ---------------------------------------------------------------------------
// Keccak Duplex Sponge FFI
// ---------------------------------------------------------------------------

const KECCAK_RATE: usize = 136;
const KECCAK_STATE_SIZE: usize = 200;

/// Keccak duplex sponge matching sigma-rs's KeccakDuplexSponge exactly.
/// State is [u64; 25] (200 bytes), with absorb_index and squeeze_index
/// tracking positions within the rate portion [0..136).
pub struct KeccakState {
    state: [u64; 25],
    absorb_index: usize,
    squeeze_index: usize,
}

impl KeccakState {
    fn state_as_bytes(&self) -> &[u8; KECCAK_STATE_SIZE] {
        unsafe { &*(self.state.as_ptr() as *const [u8; KECCAK_STATE_SIZE]) }
    }

    fn state_as_bytes_mut(&mut self) -> &mut [u8; KECCAK_STATE_SIZE] {
        unsafe { &mut *(self.state.as_mut_ptr() as *mut [u8; KECCAK_STATE_SIZE]) }
    }

    fn permute(&mut self) {
        f1600(&mut self.state);
    }

    fn new_from_iv(iv: &[u8]) -> Self {
        let mut state = [0u64; 25];
        // Copy IV into capacity bytes [RATE..200)
        let bytes = unsafe {
            &mut *(state.as_mut_ptr() as *mut [u8; KECCAK_STATE_SIZE])
        };
        let capacity_size = KECCAK_STATE_SIZE - KECCAK_RATE; // 64
        let copy_len = iv.len().min(capacity_size);
        bytes[KECCAK_RATE..KECCAK_RATE + copy_len].copy_from_slice(&iv[..copy_len]);
        KeccakState {
            state,
            absorb_index: 0,
            squeeze_index: KECCAK_RATE,
        }
    }

    fn absorb(&mut self, data: &[u8]) {
        // On entry, reset squeeze_index to RATE
        self.squeeze_index = KECCAK_RATE;
        for &byte in data {
            if self.absorb_index == KECCAK_RATE {
                self.permute();
                self.absorb_index = 0;
            }
            // Copy (overwrite), not XOR
            let idx = self.absorb_index;
            self.state_as_bytes_mut()[idx] = byte;
            self.absorb_index += 1;
        }
    }

    fn squeeze(&mut self, output: &mut [u8]) {
        // On entry, reset absorb_index to 0 only at permutation boundaries
        for out_byte in output.iter_mut() {
            if self.squeeze_index == KECCAK_RATE {
                self.absorb_index = 0;
                self.permute();
                self.squeeze_index = 0;
            }
            *out_byte = self.state_as_bytes()[self.squeeze_index];
            self.squeeze_index += 1;
        }
    }
}

impl Clone for KeccakState {
    fn clone(&self) -> Self {
        KeccakState {
            state: self.state,
            absorb_index: self.absorb_index,
            squeeze_index: self.squeeze_index,
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn sigma_keccak_new(iv: *const u8) -> *mut KeccakState {
    // IV is always 64 bytes (capacity size)
    let iv_bytes = slice::from_raw_parts(iv, 64);
    let state = KeccakState::new_from_iv(iv_bytes);
    Box::into_raw(Box::new(state))
}

#[no_mangle]
pub unsafe extern "C" fn sigma_keccak_clone_and_absorb(
    state: *const KeccakState,
    data: *const u8,
    len: usize,
) -> *mut KeccakState {
    let s = &*state;
    let mut cloned = s.clone();
    let bytes = slice::from_raw_parts(data, len);
    cloned.absorb(bytes);
    Box::into_raw(Box::new(cloned))
}

#[no_mangle]
pub unsafe extern "C" fn sigma_keccak_clone_and_squeeze(
    state: *const KeccakState,
    len: usize,
    out: *mut u8,
) -> *mut KeccakState {
    let s = &*state;
    let mut cloned = s.clone();
    let output = slice::from_raw_parts_mut(out, len);
    cloned.squeeze(output);
    Box::into_raw(Box::new(cloned))
}

#[no_mangle]
pub unsafe extern "C" fn sigma_keccak_free(state: *mut KeccakState) {
    if !state.is_null() {
        drop(Box::from_raw(state));
    }
}

// ---------------------------------------------------------------------------
// sigma-rs cross-compatibility FFI
// ---------------------------------------------------------------------------

use sigma_proofs::LinearRelation;

/// Helper: build a dlog linear relation in canonical element order.
/// Elements are allocated per-equation: basis first, then image.
///   scalar 0 = x
///   element 0 = generator (basis for eq 0)
///   element 1 = pubkey    (image of eq 0)
///   equation: element[1] = scalar[0] * element[0]
unsafe fn build_dlog_relation(
    generator_ptr: *const u8,
    pubkey_ptr: *const u8,
    witness: Option<Scalar>,
) -> Result<(LinearRelation<RistrettoPoint>, Option<Vec<Scalar>>), ()> {
    let generator = decompress(generator_ptr);
    let pubkey = decompress(pubkey_ptr);

    let mut rel = LinearRelation::<RistrettoPoint>::new();
    let x = rel.allocate_scalar();
    let g = rel.allocate_element();  // element 0 (basis)
    let p = rel.allocate_element();  // element 1 (image)
    rel.set_element(g, generator);
    rel.set_element(p, pubkey);
    rel.append_equation(p, x * g);

    if let Some(w) = witness {
        let witness_vec = vec![w];
        Ok((rel, Some(witness_vec)))
    } else {
        Ok((rel, None))
    }
}

/// Helper: build a DLEQ linear relation in canonical element order.
/// Elements are allocated per-equation: basis first, then image.
///   scalar 0 = x
///   element 0 = G  (basis for eq 0)
///   element 1 = X  (image of eq 0)
///   element 2 = H  (basis for eq 1)
///   element 3 = Y  (image of eq 1)
///   equation 0: element[1] = scalar[0] * element[0]
///   equation 1: element[3] = scalar[0] * element[2]
unsafe fn build_dleq_relation(
    g1_ptr: *const u8,
    p1_ptr: *const u8,
    g2_ptr: *const u8,
    p2_ptr: *const u8,
    witness: Option<Scalar>,
) -> Result<(LinearRelation<RistrettoPoint>, Option<Vec<Scalar>>), ()> {
    let g1 = decompress(g1_ptr);
    let p1 = decompress(p1_ptr);
    let g2 = decompress(g2_ptr);
    let p2 = decompress(p2_ptr);

    let mut rel = LinearRelation::<RistrettoPoint>::new();
    let x = rel.allocate_scalar();
    // Eq 0: basis then image
    let g1_var = rel.allocate_element();  // element 0 (basis for eq 0)
    let p1_var = rel.allocate_element();  // element 1 (image of eq 0)
    // Eq 1: basis then image
    let g2_var = rel.allocate_element();  // element 2 (basis for eq 1)
    let p2_var = rel.allocate_element();  // element 3 (image of eq 1)
    rel.set_element(g1_var, g1);
    rel.set_element(p1_var, p1);
    rel.set_element(g2_var, g2);
    rel.set_element(p2_var, p2);
    rel.append_equation(p1_var, x * g1_var);
    rel.append_equation(p2_var, x * g2_var);

    if let Some(w) = witness {
        let witness_vec = vec![w];
        Ok((rel, Some(witness_vec)))
    } else {
        Ok((rel, None))
    }
}

// --- DLOG batchable ---

#[no_mangle]
pub unsafe extern "C" fn sigma_rs_prove_batchable_dlog(
    generator: *const u8,
    pubkey: *const u8,
    witness: *const u8,
    session_id: *const u8,
    sid_len: usize,
    proof_out: *mut u8,
    proof_len_out: *mut usize,
) -> i32 {
    let w = read_scalar(witness);
    let sid = slice::from_raw_parts(session_id, sid_len);

    let (rel, witness_vec) = match build_dlog_relation(generator, pubkey, Some(w)) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let nizk = match rel.into_nizk(sid) {
        Ok(n) => n,
        Err(_) => return -2,
    };

    let proof = match nizk.prove_batchable(&witness_vec.unwrap(), &mut OsRng) {
        Ok(p) => p,
        Err(_) => return -3,
    };

    std::ptr::copy_nonoverlapping(proof.as_ptr(), proof_out, proof.len());
    *proof_len_out = proof.len();
    0
}

#[no_mangle]
pub unsafe extern "C" fn sigma_rs_verify_batchable_dlog(
    generator: *const u8,
    pubkey: *const u8,
    session_id: *const u8,
    sid_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    let sid = slice::from_raw_parts(session_id, sid_len);
    let proof_bytes = slice::from_raw_parts(proof, proof_len);

    let (rel, _) = match build_dlog_relation(generator, pubkey, None) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let nizk = match rel.into_nizk(sid) {
        Ok(n) => n,
        Err(_) => return -2,
    };

    match nizk.verify_batchable(proof_bytes) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

// --- DLOG compact ---

#[no_mangle]
pub unsafe extern "C" fn sigma_rs_prove_compact_dlog(
    generator: *const u8,
    pubkey: *const u8,
    witness: *const u8,
    session_id: *const u8,
    sid_len: usize,
    proof_out: *mut u8,
    proof_len_out: *mut usize,
) -> i32 {
    let w = read_scalar(witness);
    let sid = slice::from_raw_parts(session_id, sid_len);

    let (rel, witness_vec) = match build_dlog_relation(generator, pubkey, Some(w)) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let nizk = match rel.into_nizk(sid) {
        Ok(n) => n,
        Err(_) => return -2,
    };

    let proof = match nizk.prove_compact(&witness_vec.unwrap(), &mut OsRng) {
        Ok(p) => p,
        Err(_) => return -3,
    };

    std::ptr::copy_nonoverlapping(proof.as_ptr(), proof_out, proof.len());
    *proof_len_out = proof.len();
    0
}

#[no_mangle]
pub unsafe extern "C" fn sigma_rs_verify_compact_dlog(
    generator: *const u8,
    pubkey: *const u8,
    session_id: *const u8,
    sid_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    let sid = slice::from_raw_parts(session_id, sid_len);
    let proof_bytes = slice::from_raw_parts(proof, proof_len);

    let (rel, _) = match build_dlog_relation(generator, pubkey, None) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let nizk = match rel.into_nizk(sid) {
        Ok(n) => n,
        Err(_) => return -2,
    };

    match nizk.verify_compact(proof_bytes) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

// --- DLEQ batchable ---

#[no_mangle]
pub unsafe extern "C" fn sigma_rs_prove_batchable_dleq(
    g1: *const u8,
    p1: *const u8,
    g2: *const u8,
    p2: *const u8,
    witness: *const u8,
    session_id: *const u8,
    sid_len: usize,
    proof_out: *mut u8,
    proof_len_out: *mut usize,
) -> i32 {
    let w = read_scalar(witness);
    let sid = slice::from_raw_parts(session_id, sid_len);

    let (rel, witness_vec) = match build_dleq_relation(g1, p1, g2, p2, Some(w)) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let nizk = match rel.into_nizk(sid) {
        Ok(n) => n,
        Err(_) => return -2,
    };

    let proof = match nizk.prove_batchable(&witness_vec.unwrap(), &mut OsRng) {
        Ok(p) => p,
        Err(_) => return -3,
    };

    std::ptr::copy_nonoverlapping(proof.as_ptr(), proof_out, proof.len());
    *proof_len_out = proof.len();
    0
}

#[no_mangle]
pub unsafe extern "C" fn sigma_rs_verify_batchable_dleq(
    g1: *const u8,
    p1: *const u8,
    g2: *const u8,
    p2: *const u8,
    session_id: *const u8,
    sid_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    let sid = slice::from_raw_parts(session_id, sid_len);
    let proof_bytes = slice::from_raw_parts(proof, proof_len);

    let (rel, _) = match build_dleq_relation(g1, p1, g2, p2, None) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let nizk = match rel.into_nizk(sid) {
        Ok(n) => n,
        Err(_) => return -2,
    };

    match nizk.verify_batchable(proof_bytes) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

// --- DLEQ compact ---

#[no_mangle]
pub unsafe extern "C" fn sigma_rs_prove_compact_dleq(
    g1: *const u8,
    p1: *const u8,
    g2: *const u8,
    p2: *const u8,
    witness: *const u8,
    session_id: *const u8,
    sid_len: usize,
    proof_out: *mut u8,
    proof_len_out: *mut usize,
) -> i32 {
    let w = read_scalar(witness);
    let sid = slice::from_raw_parts(session_id, sid_len);

    let (rel, witness_vec) = match build_dleq_relation(g1, p1, g2, p2, Some(w)) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let nizk = match rel.into_nizk(sid) {
        Ok(n) => n,
        Err(_) => return -2,
    };

    let proof = match nizk.prove_compact(&witness_vec.unwrap(), &mut OsRng) {
        Ok(p) => p,
        Err(_) => return -3,
    };

    std::ptr::copy_nonoverlapping(proof.as_ptr(), proof_out, proof.len());
    *proof_len_out = proof.len();
    0
}

#[no_mangle]
pub unsafe extern "C" fn sigma_rs_verify_compact_dleq(
    g1: *const u8,
    p1: *const u8,
    g2: *const u8,
    p2: *const u8,
    session_id: *const u8,
    sid_len: usize,
    proof: *const u8,
    proof_len: usize,
) -> i32 {
    let sid = slice::from_raw_parts(session_id, sid_len);
    let proof_bytes = slice::from_raw_parts(proof, proof_len);

    let (rel, _) = match build_dleq_relation(g1, p1, g2, p2, None) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let nizk = match rel.into_nizk(sid) {
        Ok(n) => n,
        Err(_) => return -2,
    };

    match nizk.verify_compact(proof_bytes) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

// --- Instance label ---

#[no_mangle]
pub unsafe extern "C" fn sigma_rs_dlog_instance_label(
    generator: *const u8,
    pubkey: *const u8,
    label_out: *mut u8,
    label_len_out: *mut usize,
) -> i32 {
    let (rel, _) = match build_dlog_relation(generator, pubkey, None) {
        Ok(v) => v,
        Err(_) => return -1,
    };

    let canonical = match rel.canonical() {
        Ok(c) => c,
        Err(_) => return -2,
    };

    let label = canonical.label();
    std::ptr::copy_nonoverlapping(label.as_ptr(), label_out, label.len());
    *label_len_out = label.len();
    0
}

// ---------------------------------------------------------------------------
// Random bytes FFI
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn sigma_random_bytes(out: *mut u8, len: usize) {
    let buf = slice::from_raw_parts_mut(out, len);
    OsRng.fill_bytes(buf);
}
