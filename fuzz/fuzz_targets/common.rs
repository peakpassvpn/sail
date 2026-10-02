use sail::sniff::Sniff;

/// Checks `sniff` on `data` and on a prefix of it: what a prefix decides,
/// the whole decides the same, for sniffing reads a connection a piece at
/// a time.
pub fn check_prefixes(data: &[u8], sniff: fn(&[u8]) -> Sniff) {
    let whole = sniff(data);
    let Some(&first) = data.first() else {
        return;
    };
    let cut = first as usize * 31 % (data.len() + 1);
    match sniff(&data[..cut]) {
        Sniff::NeedMore => {}
        decided => assert_eq!(decided, whole, "decided on {} of {} bytes", cut, data.len()),
    }
}
