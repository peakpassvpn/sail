#![no_main]

//! The SACK scoreboard read in one pass (`lost_prefix`, `pipe`) against
//! RFC 6675's `IsLost` asked of each chunk over every chunk above it, as
//! sail had it: on any queue of chunks, any lengths, SACKed and
//! retransmitted at random, the same chunks are lost and the pipe is the
//! same.

use std::collections::VecDeque;

use libfuzzer_sys::fuzz_target;
use sail_netstack::tcp::sack_fuzzing::{lost_prefix, pipe, Chunk};

const MAX_CHUNKS: usize = 1_024;

/// IsLost(i): three SACKed chunks above it, or three segments' bytes of
/// them. The queue has no gaps, so every chunk after i is above it.
fn is_lost(chunks: &VecDeque<Chunk>, index: usize, max_segment: usize) -> bool {
    let (mut sacked, mut bytes) = (0_usize, 0_usize);
    for chunk in chunks.iter().skip(index + 1) {
        if chunk.sacked {
            sacked += 1;
            bytes = bytes.saturating_add(chunk.len);
        }
    }
    sacked >= 3 || bytes >= max_segment.saturating_mul(3)
}

fuzz_target!(|data: &[u8]| {
    let Some((&first, rest)) = data.split_first() else {
        return;
    };
    let max_segment = [1, 536, 1_460, 8_960, 65_535][usize::from(first % 5)];
    let chunks: VecDeque<Chunk> = rest
        .chunks_exact(3)
        .take(MAX_CHUNKS)
        .map(|c| Chunk {
            len: usize::from(u16::from_le_bytes([c[0], c[1]])) % 9_001,
            sacked: c[2] & 1 != 0,
            retransmitted: c[2] & 2 != 0,
        })
        .collect();

    let prefix = lost_prefix(&chunks, max_segment);
    assert!(prefix <= chunks.len());
    let mut expected_pipe = 0_usize;
    for (index, chunk) in chunks.iter().enumerate() {
        let lost = is_lost(&chunks, index, max_segment);
        assert_eq!(
            index < prefix,
            lost,
            "chunk {index} of {}: one pass says {}, IsLost says {lost}",
            chunks.len(),
            index < prefix
        );
        if !chunk.sacked {
            expected_pipe += if lost { 0 } else { chunk.len };
            expected_pipe += if chunk.retransmitted { chunk.len } else { 0 };
        }
    }
    assert_eq!(pipe(&chunks, max_segment), expected_pipe);
});
