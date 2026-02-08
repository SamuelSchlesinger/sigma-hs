use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul};
use digest::{ExtendableOutput, Update};
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
// Random bytes FFI
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn sigma_random_bytes(out: *mut u8, len: usize) {
    let buf = slice::from_raw_parts_mut(out, len);
    OsRng.fill_bytes(buf);
}
