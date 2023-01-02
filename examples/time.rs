use rand::rngs::StdRng;
use rand::SeedableRng;
use rust_elgamal::{DecryptionKey, Scalar, GENERATOR_TABLE};
use std::time::Instant;
// Library definitions for rust-elgamal.
// Copyright 2021 Eleanor McMurtry
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


use curve25519_dalek::constants::{RISTRETTO_BASEPOINT_POINT, RISTRETTO_BASEPOINT_TABLE, RISTRETTO_BASEPOINT_COMPRESSED};
use curve25519_dalek::ristretto::RistrettoBasepointTable;

pub use curve25519_dalek::ristretto::RistrettoPoint;
pub use curve25519_dalek::ristretto::CompressedRistretto;

pub use curve25519_dalek::traits::Identity;
pub use curve25519_dalek::traits::IsIdentity;
pub use curve25519_dalek::traits::MultiscalarMul;

/// The group generator as a single point.
/// If you're trying to create a scalar multiple of the generator, you probably want
/// [GENERATOR_TABLE](crate::GENERATOR_TABLE) instead.
pub const GENERATOR_POINT: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;

/// The group generator as a single point, compressed for transit.
/// If you're trying to create a scalar multiple of the generator, you probably want
/// [GENERATOR_TABLE](crate::GENERATOR_TABLE) instead.
pub const GENERATOR_POINT_COMPRESSED: CompressedRistretto = RISTRETTO_BASEPOINT_COMPRESSED;

/// The group generator as a table of precomputed multiples. This is the most efficient way to
/// produce a scalar multiple of the generator.


const N: usize = 100;
fn main(){
let mut rng = StdRng::from_entropy();
let dec_key = DecryptionKey::new(&mut rng);
let enc_key = dec_key.encryption_key();

let message = &Scalar::from(5u32) * &GENERATOR_TABLE;
let t1 = Instant::now();
let encrypted = enc_key.encrypt(message, &mut rng);
let t1 = t1.elapsed();

let t2 = Instant::now();
let decrypted = dec_key.decrypt(encrypted);
let t2 = t2.elapsed();

let mm = &Scalar::from(6u32) * &GENERATOR_TABLE;
assert_eq!(mm, decrypted);


let mut rng = StdRng::from_entropy();
let dk = DecryptionKey::new(&mut rng);
let ek = dk.encryption_key();

let m1 = RistrettoPoint::random(&mut rng);
let m2 = RistrettoPoint::random(&mut rng);
let sum = m1 + m2;


let ct1 = ek.encrypt(m1, &mut rng);
let ct2 = ek.encrypt(m2, &mut rng);

let t3 = Instant::now();
let ct_sum = ct1 + ct2;
let t3 = t3.elapsed();

let decrypted = dk.decrypt(ct_sum);
assert_eq!(sum, decrypted);

println!("encryption time: {:?}", t1);
println!("decryption time: {:?}", t2);
println!("addition time: {:?}", t3);
}