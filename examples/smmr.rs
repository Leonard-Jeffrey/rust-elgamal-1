extern crate rand;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use rust_elgamal::{DecryptionKey, Scalar, GENERATOR_TABLE};
use std::time::Instant;
use std::convert::TryInto;
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


const N:usize=100;
fn main(){


for j in 6..16 {
    println!("=================== j = {} ===================", j);
    let t0 = Instant::now();
    // 用户预处理数据
    let k = 1;
    //let n = 2u128.pow(16);
    //let n = 2_usize.pow(16);
    let n = 2_usize.pow(j);
    let m = 2;
    let mut data: Vec<u64> = Vec::new();
    let mut rng = rand::thread_rng(); // 随机数生成器
    for i in 0..k {
        let mut da:usize = rng.gen();
        da = &da % n;
        //println!("{}", da);
        data.push((da as usize).try_into().unwrap());
    }
    let t0 = t0.elapsed();

    let mut rng = StdRng::from_entropy();
    let dec_key = DecryptionKey::new(&mut rng);
    let enc_key = dec_key.encryption_key();

    // 用户数据处理
    let tt = Instant::now();
    let t1 = Instant::now();

    let zero = &Scalar::from(0 as u32) * &GENERATOR_TABLE;
    let one = &Scalar::from(1 as u32) * &GENERATOR_TABLE;
    let mut v = vec![zero; n as usize];
    for i in 0..k {
        if data[i] > 0 {
            v[data[i] as usize] = one;
        }
    }

    let mut cipher = Vec::new();
    for i in 0..n {
        let encrypted = enc_key.encrypt(v[i as usize], &mut rng);
        cipher.push(encrypted);
    }


    let t1 = t1.elapsed();

    // let mut plain = Vec::new();
    // for i in 0..n {
    //     let decrypted = dec_key.decrypt(cipher[i as usize]);
    //     plain.push(decrypted);
        
    // }
    // assert_eq!(v[(n-1) as usize], plain[(n-1) as usize]);
    // let t1 = t1.elapsed();
    // let t2 = Instant::now();
    // let decrypted = dec_key.decrypt(encrypted);
    // let t2 = t2.elapsed();
    
    // 用户结果生成
    let t2 = Instant::now();
    let mut cipher_sum = Vec::new();
    for i in 0..n {
        if i == 0 {
            cipher_sum.push(cipher[i as usize]);
        }
        else {
            cipher_sum.push(&cipher[(i-1) as usize] + &cipher_sum[(i-1) as usize]);
        }
    }
    let t2 = t2.elapsed();

    // 用户结果恢复
    let t3 = Instant::now();
    let mut plain = Vec::new();
    for i in 0..k {
        let p = dec_key.decrypt(cipher_sum[data[i] as usize]);
        plain.push(p);
    }
    let t3 = t3.elapsed();
    let tt = tt.elapsed();

    println!("用户预处理数据: {:?}", t0);
    println!("用户数据处理: {:?}", t1);
    println!("用户结果生成: {:?} ", t2);
    println!("用户结果恢复: {:?}", t3);
    println!("用户总时间: {:?}", tt);
}
}