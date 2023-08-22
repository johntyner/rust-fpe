extern crate bencher;

fn encrypt(b: &mut bencher::Bencher) {
    let ff1 = fpe::ff1::FF1::new(&[0; 32], None, 0, 0, 26, None).unwrap();
    b.iter(|| ff1.encrypt("0123456789", None));
}

fn decrypt(b: &mut bencher::Bencher) {
    let ff1 = fpe::ff1::FF1::new(&[0; 32], None, 0, 0, 26, None).unwrap();
    let ct = ff1.encrypt("0123456789", None).unwrap();
    b.iter(|| ff1.decrypt(&ct, None));
}

bencher::benchmark_group!(benches, encrypt, decrypt);
bencher::benchmark_main!(benches);
