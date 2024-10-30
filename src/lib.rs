use std::arch::x86_64::{
    __m128i, _mm_aesdec_si128, _mm_aesdeclast_si128, _mm_aesenc_si128, _mm_aesenclast_si128,
    _mm_aeskeygenassist_si128, _mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128,
};

/// The block size in bytes for AES.
const AES_BLOCK_SIZE: usize = 16;

const NUM_ROUNDS_128: usize = 10;
const NUM_ROUNDS_192: usize = 12;
const NUM_ROUNDS_256: usize = 14;

const AES_128_KEY: usize = 16;
const AES_192_KEY: usize = 24;
const AES_256_KEY: usize = 32;

#[inline(always)]
pub fn aes_128_encrypt(input_data: &Vec<u8>, key: [u8; AES_128_KEY]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input_data.len());

    let round_keys = expand_key(128, &key);

    for chunk in input_data.chunks(AES_BLOCK_SIZE) {
        let mut state = initialize_state(&mut chunk.to_vec());

        add_round_key(&mut state, &round_keys[0]);

        for round in 1..NUM_ROUNDS_128 {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &round_keys[round]);
        }

        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &round_keys[NUM_ROUNDS_128]);

        for i in 0..4 {
            output.extend_from_slice(&state[i]);
        }
    }

    output
}

pub fn aes_ni_128_encrypt(input_data: &Vec<u8>, key: [u8; AES_128_KEY]) -> Vec<u8> {
    let output: Vec<u8> = Vec::with_capacity(16);

    unsafe {
        let mut input_data = _mm_loadu_si128(input_data.as_slice().as_ptr() as *const __m128i);
        let mut round_key = _mm_loadu_si128(key.as_ptr() as *const __m128i);

        input_data = _mm_xor_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[0] as i32);
        input_data = _mm_aesenc_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[1] as i32);
        input_data = _mm_aesenc_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[2] as i32);
        input_data = _mm_aesenc_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[3] as i32);
        input_data = _mm_aesenc_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[4] as i32);
        input_data = _mm_aesenc_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[5] as i32);
        input_data = _mm_aesenc_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[6] as i32);
        input_data = _mm_aesenc_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[7] as i32);
        input_data = _mm_aesenc_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[8] as i32);
        input_data = _mm_aesenc_si128(input_data, round_key);

        // Final round (without MixColumns)
        input_data = _mm_aesenclast_si128(
            input_data,
            _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[9] as i32),
        );

        _mm_storeu_si128(output.as_ptr() as *mut __m128i, input_data)
    }
    output.to_vec()
}

#[inline(always)]
pub fn aes_128_decrypt(input_data: &Vec<u8>, key: [u8; AES_128_KEY]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input_data.len());

    let round_keys = expand_key(128, &key);

    for chunk in input_data.chunks(AES_BLOCK_SIZE) {
        let mut state = initialize_state(&mut chunk.to_vec());

        add_round_key(&mut state, &round_keys[NUM_ROUNDS_128]);

        for round in (1..=NUM_ROUNDS_128).rev() {
            inv_sub_bytes(&mut state);
            inv_shift_rows(&mut state);
            add_round_key(&mut state, &round_keys[round]);
            inv_mix_columns(&mut state);
        }

        inv_sub_bytes(&mut state);
        inv_shift_rows(&mut state);
        add_round_key(&mut state, &round_keys[0]);

        for i in 0..4 {
            output.extend_from_slice(&state[i]);
        }
    }

    output
}

pub fn aes_ni_128_decrypt(input_data: &Vec<u8>, key: [u8; AES_128_KEY]) -> Vec<u8> {
    unsafe {
        let mut input_data = _mm_loadu_si128(input_data.as_slice().as_ptr() as *const __m128i);
        let mut round_key = _mm_loadu_si128(key.as_ptr() as *const __m128i);

        input_data = _mm_xor_si128(input_data, round_key);

        // AES-128 encryption with explicit round calls
        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[9] as i32);
        input_data = _mm_aesdec_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[8] as i32);
        input_data = _mm_aesdec_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[7] as i32);
        input_data = _mm_aesdec_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[6] as i32);
        input_data = _mm_aesdec_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[5] as i32);
        input_data = _mm_aesdec_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[4] as i32);
        input_data = _mm_aesdec_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[3] as i32);
        input_data = _mm_aesdec_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[2] as i32);
        input_data = _mm_aesdec_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[1] as i32);
        input_data = _mm_aesdec_si128(input_data, round_key);

        input_data = _mm_aesdeclast_si128(
            input_data,
            _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[0] as i32),
        );
    }
    input_data.to_vec()
}

pub fn aes_192_encrypt(input_data: &Vec<u8>, key: [u8; AES_192_KEY]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input_data.len());

    let round_keys = expand_key_192(&key);

    for mut chunk in input_data.chunks_exact(AES_BLOCK_SIZE) {
        let mut state = initialize_state(&mut chunk);

        add_round_key(&mut state, &round_keys[0]);

        for round in 1..NUM_ROUNDS_192 {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &round_keys[round]);
        }

        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &round_keys[NUM_ROUNDS_192]);

        for col in state.iter() {
            output.extend_from_slice(col);
        }
    }

    output
}

pub fn aes_ni_192_encrypt(input_data: &Vec<u8>, key: [u8; AES_192_KEY]) -> Vec<u8> {
    let output: Vec<u8> = Vec::with_capacity(16);

    unsafe {
        let mut input_data = _mm_loadu_si128(input_data.as_slice().as_ptr() as *const __m128i);
        let mut round_key = _mm_loadu_si128(key.as_ptr() as *const __m128i);

        input_data = _mm_xor_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[0] as i32);
        input_data = _mm_aesenc_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[1] as i32);
        input_data = _mm_aesenc_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[2] as i32);
        input_data = _mm_aesenc_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[3] as i32);
        input_data = _mm_aesenc_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[4] as i32);
        input_data = _mm_aesenc_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[5] as i32);
        input_data = _mm_aesenc_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[6] as i32);
        input_data = _mm_aesenc_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[7] as i32);
        input_data = _mm_aesenc_si128(input_data, round_key);

        round_key = _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[8] as i32);
        input_data = _mm_aesenc_si128(input_data, round_key);

        // Final round (without MixColumns)
        input_data = _mm_aesenclast_si128(
            input_data,
            _mm_aeskeygenassist_si128(round_key, ROUND_CONSTANTS[9] as i32),
        );

        _mm_storeu_si128(output.as_ptr() as *mut __m128i, input_data)
    }
    output.to_vec();

    vec![]
}

pub fn aes_192_decrypt(input_data: &Vec<u8>, key: [u8; AES_192_KEY]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input_data.len());

    let round_keys = expand_key_192(&key);

    for chunk in input_data.chunks(AES_BLOCK_SIZE) {
        let mut state = initialize_state(&mut chunk.to_vec());

        add_round_key(&mut state, &round_keys[NUM_ROUNDS_192]);

        for round in (1..NUM_ROUNDS_192).rev() {
            inv_shift_rows(&mut state);
            inv_sub_bytes(&mut state);
            add_round_key(&mut state, &round_keys[round]);
            inv_mix_columns(&mut state);
        }

        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &round_keys[0]);

        for i in 0..4 {
            output.extend_from_slice(&state[i]);
        }
    }

    output
}

pub fn aes_256_encrypt(input_data: &Vec<u8>, key: [u8; AES_256_KEY]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input_data.len());

    let round_keys = expand_key_256(&key);

    for chunk in input_data.chunks(AES_BLOCK_SIZE) {
        let mut state = initialize_state(&mut chunk.to_vec());

        add_round_key(&mut state, &round_keys[0]);

        for round in 1..NUM_ROUNDS_256 {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &round_keys[round]);
        }

        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &round_keys[NUM_ROUNDS_256]);

        for i in 0..4 {
            output.extend_from_slice(&state[i]);
        }
    }

    output
}

pub fn aes_256_decrypt(input_data: &Vec<u8>, key: [u8; AES_256_KEY]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input_data.len());

    let round_keys = expand_key_256(&key);

    for chunk in input_data.chunks(AES_BLOCK_SIZE) {
        let mut state = initialize_state(&mut chunk.to_vec());

        add_round_key(&mut state, &round_keys[NUM_ROUNDS_256]);

        for round in (1..NUM_ROUNDS_256).rev() {
            inv_shift_rows(&mut state);
            inv_sub_bytes(&mut state);
            add_round_key(&mut state, &round_keys[round]);
            inv_mix_columns(&mut state);
        }

        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &round_keys[0]);

        for i in 0..4 {
            output.extend_from_slice(&state[i]);
        }
    }

    output
}

#[inline(always)]
fn initialize_state(input_data: &[u8]) -> [[u8; 4]; 4] {
    assert_eq!(input_data.len(), 16, "NOT 16!!!");

    let mut state: [[u8; 4]; 4] = Default::default();

    for (i, &byte) in input_data.iter().enumerate() {
        state[i % 4][i / 4] = byte;
    }
    state
}

#[inline(always)]
fn expand_key(key_size: usize, original_key: &[u8]) -> Vec<Vec<u8>> {
    let num_rounds = match key_size {
        128 => NUM_ROUNDS_128,
        192 => NUM_ROUNDS_192,
        256 => NUM_ROUNDS_256,
        _ => panic!("Invalid key size"),
    };

    let word_size = 4;
    let key_words = key_size / 32;
    let total_words = (num_rounds + 1) * word_size;

    let mut round_keys: Vec<u8> = Vec::with_capacity(total_words * 4);
    round_keys.extend_from_slice(original_key);

    for i in key_words..total_words {
        let mut temp = round_keys[(i - 1) * 4..i * 4].to_vec();

        if i % key_words == 0 {
            temp.rotate_left(1);
            for byte in &mut temp {
                *byte = S_BOX[*byte as usize];
            }
            temp[0] ^= ROUND_CONSTANTS[i / key_words - 1];
        } else if key_size == 256 && i % key_words == 4 {
            for byte in &mut temp {
                *byte = S_BOX[*byte as usize];
            }
        }

        for j in 0..4 {
            temp[j] ^= round_keys[(i - key_words) * 4 + j];
        }

        round_keys.extend_from_slice(&temp);
    }

    // Split flat array into chunks of 16 bytes (AES block size) to return
    round_keys.chunks(16).map(|chunk| chunk.to_vec()).collect()
}

fn expand_key_192(original_key: &[u8; 24]) -> Vec<[u8; 16]> {
    let mut round_keys = vec![[0u8; 16]; 13]; // AES-192 requires 13 keys
    round_keys[0][..16].copy_from_slice(&original_key[0..16]);
    round_keys[1][..8].copy_from_slice(&original_key[16..24]);

    for round in 2..13 {
        let mut temp = round_keys[round - 1];
        temp.rotate_left(4);

        for byte in temp.iter_mut() {
            *byte = S_BOX[*byte as usize];
        }
        temp[0] ^= ROUND_CONSTANTS[round - 1];

        for i in 0..4 {
            temp[i] ^= round_keys[round - 2][i];
        }
        round_keys[round] = temp;
    }

    round_keys
}

/* #[inline(always)]
fn expand_key_192(original_key: &[u8; 24]) -> Vec<[u8; 16]> {
    let mut round_keys: Vec<[u8; 16]> = Vec::with_capacity(13);

    // Copy initial key segments into round keys
    let mut current_key = [0u8; 16];
    current_key.copy_from_slice(&original_key[..16]);
    round_keys.push(current_key);

    current_key.copy_from_slice(&original_key[8..24]);
    round_keys.push(current_key);

    // Start expanding keys for AES-192
    for round in 2..13 {
        let mut temp = round_keys[round - 1].clone();

        // Rotate and substitute bytes for the first word
        temp.rotate_left(4);
        for byte in temp.iter_mut() {
            *byte = S_BOX[*byte as usize];
        }

        // XOR with round constant
        temp[0] ^= ROUND_CONSTANTS[round - 1];

        // Generate the new round key by XORing with previous round keys
        for i in 0..16 {
            temp[i] ^= round_keys[round - 2][i];
        }

        round_keys.push(temp);
    }

    round_keys
} */

/// Key expansion function for AES-256
#[inline(always)]
fn expand_key_256(original_key: &[u8; AES_256_KEY]) -> Vec<[u8; AES_256_KEY]> {
    let mut round_keys: Vec<[u8; AES_256_KEY]> = Vec::with_capacity(NUM_ROUNDS_256 + 1);
    round_keys.push(*original_key);

    for round in 1..=NUM_ROUNDS_256 {
        let mut new_key = round_keys[round - 1];

        // RotWord
        new_key.rotate_left(1);

        // SubWord
        new_key
            .iter_mut()
            .for_each(|byte| *byte = S_BOX[*byte as usize]);

        // XOR with round constant
        new_key[0] ^= ROUND_CONSTANTS[round - 1];

        round_keys.push(new_key);
    }

    round_keys
}

/// Substitutes each byte in the state with its corresponding value from the S-box.
#[inline(always)]
fn sub_bytes(state: &mut [[u8; 4]; 4]) {
    for i in 0..4 {
        for j in 0..4 {
            state[i][j] = S_BOX[state[i][j] as usize];
        }
    }
}

/* #[inline(always)]
fn s_bytes(state: &mut [u8; 16]) {
    for i in 0..16 {
        state[i] = S_BOX[state[i] as usize];
    }
} */

/// Shifts the rows of the state array.
#[inline(always)]
fn shift_rows(state: &mut [[u8; 4]; 4]) {
    state[1].rotate_left(1);
    state[2].rotate_left(2);
    state[3].rotate_left(3);
}

#[inline(always)]
fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }

    let s = (LTABLE[a as usize] as usize + LTABLE[b as usize] as usize) % 255;
    let s = ATABLE[s];
    s as u8
}

#[inline(always)]
fn mix_columns(state: &mut [[u8; 4]; 4]) {
    for i in 0..4 {
        let a0 = state[0][i];
        let a1 = state[1][i];
        let a2 = state[2][i];
        let a3 = state[3][i];

        state[0][i] = mul(0x02, a0) ^ mul(0x03, a1) ^ a2 ^ a3;
        state[1][i] = a0 ^ mul(0x02, a1) ^ mul(0x03, a2) ^ a3;
        state[2][i] = a0 ^ a1 ^ mul(0x02, a2) ^ mul(0x03, a3);
        state[3][i] = mul(0x03, a0) ^ a1 ^ a2 ^ mul(0x02, a3);
    }
}

fn add_round_key(state: &mut [[u8; 4]; 4], round_key: &[u8]) {
    // AES typically operates with a 4x4 state array for 128-bit blocks
    for col in 0..4 {
        for row in 0..4 {
            let index = col * 4 + row;
            state[row][col] ^= round_key[index];
        }
    }
}

/// Substitutes each byte in the state with its corresponding value from the inverse S-box.
fn inv_sub_bytes(state: &mut [[u8; 4]; 4]) {
    for i in 0..4 {
        for j in 0..4 {
            state[i][j] = INV_S_BOX[state[i][j] as usize];
        }
    }
}

/// Shifts the rows of the state array in the inverse direction.
fn inv_shift_rows(state: &mut [[u8; 4]; 4]) {
    state[1].rotate_right(1);
    state[2].rotate_right(2);
    state[3].rotate_right(3);
}

/// Mixes the columns of the state array in the inverse direction.
fn inv_mix_columns(state: &mut [[u8; 4]; 4]) {
    for i in 0..4 {
        let a0 = state[0][i];
        let a1 = state[1][i];
        let a2 = state[2][i];
        let a3 = state[3][i];

        state[0][i] = mul(0x0e, a0) ^ mul(0x0b, a1) ^ mul(0x0d, a2) ^ mul(0x09, a3);
        state[1][i] = mul(0x09, a0) ^ mul(0x0e, a1) ^ mul(0x0b, a2) ^ mul(0x0d, a3);
        state[2][i] = mul(0x0d, a0) ^ mul(0x09, a1) ^ mul(0x0e, a2) ^ mul(0x0b, a3);
        state[3][i] = mul(0x0b, a0) ^ mul(0x0d, a1) ^ mul(0x09, a2) ^ mul(0x0e, a3);
    }
}

/* /// Multiplies a number in the finite field of AES (Galois Field 2^8) by its multiplicative inverse.
fn inv_mul(a: u8, b: u8) -> u8 {
    let mut result = 0;

    let mut temp_b = b;
    let mut temp_result = a;

    for _ in 0..8 {
        if temp_b & 1 == 1 {
            result ^= temp_result;
        }

        let high_bit_set = temp_result & 0x80 != 0;
        temp_result <<= 1;

        if high_bit_set {
            temp_result ^= 0x1b; // XOR with irreducible polynomial in GF(2^8)
        }

        temp_b >>= 1;
    }

    result
} */

/// The inverse S-box substitution values for AES-128 decryption.
const INV_S_BOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// The S-box substitution values for AES-128 encryption.
const S_BOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// The round constants used in the key schedule of AES-128 encryption.
const ROUND_CONSTANTS: [u8; NUM_ROUNDS_256] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
];

const LTABLE: [u8; 256] = [
    0x00, 0xff, 0xc8, 0x08, 0x91, 0x10, 0xd0, 0x36, 0x5a, 0x3e, 0xd8, 0x43, 0x99, 0x77, 0xfe, 0x18,
    0x23, 0x20, 0x07, 0x70, 0xa1, 0x6c, 0x0c, 0x7f, 0x62, 0x8b, 0x40, 0x46, 0xc7, 0x4b, 0xe0, 0x0e,
    0xeb, 0x16, 0xe8, 0xad, 0xcf, 0xcd, 0x39, 0x53, 0x6a, 0x27, 0x35, 0x93, 0xd4, 0x4e, 0x48, 0xc3,
    0x2b, 0x79, 0x54, 0x28, 0x09, 0x78, 0x0f, 0x21, 0x90, 0x87, 0x14, 0x2a, 0xa9, 0x9c, 0xd6, 0x74,
    0xb4, 0x7c, 0xde, 0xed, 0xb1, 0x86, 0x76, 0xa4, 0x98, 0xe2, 0x96, 0x8f, 0x02, 0x32, 0x1c, 0xc1,
    0x33, 0xee, 0xef, 0x81, 0xfd, 0x30, 0x5c, 0x13, 0x9d, 0x29, 0x17, 0xc4, 0x11, 0x44, 0x8c, 0x80,
    0xf3, 0x73, 0x42, 0x1e, 0x1d, 0xb5, 0xf0, 0x12, 0xd1, 0x5b, 0x41, 0xa2, 0xd7, 0x2c, 0xe9, 0xd5,
    0x59, 0xcb, 0x50, 0xa8, 0xdc, 0xfc, 0xf2, 0x56, 0x72, 0xa6, 0x65, 0x2f, 0x9f, 0x9b, 0x3d, 0xba,
    0x7d, 0xc2, 0x45, 0x82, 0xa7, 0x57, 0xb6, 0xa3, 0x7a, 0x75, 0x4f, 0xae, 0x3f, 0x37, 0x6d, 0x47,
    0x61, 0xbe, 0xab, 0xd3, 0x5f, 0xb0, 0x58, 0xaf, 0xca, 0x5e, 0xfa, 0x85, 0xe4, 0x4d, 0x8a, 0x05,
    0xfb, 0x60, 0xb7, 0x7b, 0xb8, 0x26, 0x4a, 0x67, 0xc6, 0x1a, 0xf8, 0x69, 0x25, 0xb3, 0xdb, 0xbd,
    0x66, 0xdd, 0xf1, 0xd2, 0xdf, 0x03, 0x8d, 0x34, 0xd9, 0x92, 0x0d, 0x63, 0x55, 0xaa, 0x49, 0xec,
    0xbc, 0x95, 0x3c, 0x84, 0x0b, 0xf5, 0xe6, 0xe7, 0xe5, 0xac, 0x7e, 0x6e, 0xb9, 0xf9, 0xda, 0x8e,
    0x9a, 0xc9, 0x24, 0xe1, 0x0a, 0x15, 0x6b, 0x3a, 0xa0, 0x51, 0xf4, 0xea, 0xb2, 0x97, 0x9e, 0x5d,
    0x22, 0x88, 0x94, 0xce, 0x19, 0x01, 0x71, 0x4c, 0xa5, 0xe3, 0xc5, 0x31, 0xbb, 0xcc, 0x1f, 0x2d,
    0x3b, 0x52, 0x6f, 0xf6, 0x2e, 0x89, 0xf7, 0xc0, 0x68, 0x1b, 0x64, 0x04, 0x06, 0xbf, 0x83, 0x38,
];

const ATABLE: [u8; 256] = [
    0x01, 0xe5, 0x4c, 0xb5, 0xfb, 0x9f, 0xfc, 0x12, 0x03, 0x34, 0xd4, 0xc4, 0x16, 0xba, 0x1f, 0x36,
    0x05, 0x5c, 0x67, 0x57, 0x3a, 0xd5, 0x21, 0x5a, 0x0f, 0xe4, 0xa9, 0xf9, 0x4e, 0x64, 0x63, 0xee,
    0x11, 0x37, 0xe0, 0x10, 0xd2, 0xac, 0xa5, 0x29, 0x33, 0x59, 0x3b, 0x30, 0x6d, 0xef, 0xf4, 0x7b,
    0x55, 0xeb, 0x4d, 0x50, 0xb7, 0x2a, 0x07, 0x8d, 0xff, 0x26, 0xd7, 0xf0, 0xc2, 0x7e, 0x09, 0x8c,
    0x1a, 0x6a, 0x62, 0x0b, 0x5d, 0x82, 0x1b, 0x8f, 0x2e, 0xbe, 0xa6, 0x1d, 0xe7, 0x9d, 0x2d, 0x8a,
    0x72, 0xd9, 0xf1, 0x27, 0x32, 0xbc, 0x77, 0x85, 0x96, 0x70, 0x08, 0x69, 0x56, 0xdf, 0x99, 0x94,
    0xa1, 0x90, 0x18, 0xbb, 0xfa, 0x7a, 0xb0, 0xa7, 0xf8, 0xab, 0x28, 0xd6, 0x15, 0x8e, 0xcb, 0xf2,
    0x13, 0xe6, 0x78, 0x61, 0x3f, 0x89, 0x46, 0x0d, 0x35, 0x31, 0x88, 0xa3, 0x41, 0x80, 0xca, 0x17,
    0x5f, 0x53, 0x83, 0xfe, 0xc3, 0x9b, 0x45, 0x39, 0xe1, 0xf5, 0x9e, 0x19, 0x5e, 0xb6, 0xcf, 0x4b,
    0x38, 0x04, 0xb9, 0x2b, 0xe2, 0xc1, 0x4a, 0xdd, 0x48, 0x0c, 0xd0, 0x7d, 0x3d, 0x58, 0xde, 0x7c,
    0xd8, 0x14, 0x6b, 0x87, 0x47, 0xe8, 0x79, 0x84, 0x73, 0x3c, 0xbd, 0x92, 0xc9, 0x23, 0x8b, 0x97,
    0x95, 0x44, 0xdc, 0xad, 0x40, 0x65, 0x86, 0xa2, 0xa4, 0xcc, 0x7f, 0xec, 0xc0, 0xaf, 0x91, 0xfd,
    0xf7, 0x4f, 0x81, 0x2f, 0x5b, 0xea, 0xa8, 0x1c, 0x02, 0xd1, 0x98, 0x71, 0xed, 0x25, 0xe3, 0x24,
    0x06, 0x68, 0xb3, 0x93, 0x2c, 0x6f, 0x3e, 0x6c, 0x0a, 0xb8, 0xce, 0xae, 0x74, 0xb1, 0x42, 0xb4,
    0x1e, 0xd3, 0x49, 0xe9, 0x9c, 0xc8, 0xc6, 0xc7, 0x22, 0x6e, 0xdb, 0x20, 0xbf, 0x43, 0x51, 0x52,
    0x66, 0xb2, 0x76, 0x60, 0xda, 0xc5, 0xf3, 0xf6, 0xaa, 0xcd, 0x9a, 0xa0, 0x75, 0x54, 0x0e, 0x01,
];
