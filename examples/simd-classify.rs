#![feature(portable_simd)]
use std::error::Error;
use std::marker::PhantomData;
use std::simd::{LaneCount, Mask, Simd, SimdPartialEq, SupportedLaneCount, SimdElement};

fn main() -> Result<(), Box<dyn Error>> {
    let data: &[u8] = &[1, 2, 3, 4];
    let is_ipv4 = gather_enet_ipv4::<16>(data, Simd::splat(0));

    // Select ipv4 packets
    // (and drop non-ipv4 by putting new item on fill ring)

    // Select TCP segments
    // (and drop non-tcp segments by putting new item on fill ring)

    // Lookup specific values of TCP state in hashmap (can this be done with SIMD?)

    Ok(())
}

struct VectorIndex<const N: usize>
where
    LaneCount<N>: SupportedLaneCount,
{
    frames: Simd<usize, N>,
}

impl<const N: usize> VectorIndex<N>
where
    LaneCount<N>: SupportedLaneCount,
{
  /// Create a new packet vector from an array of indices into a byte buffer.
  /// These are interpreted as the pointing to the start of the frame headers.
  pub fn new(frames: [usize; N]) -> Self {
    Self { frames: Simd::from_array(frames) }
  }
}

struct Proto;

trait Field {
  type VecElem: SimdElement;
}

impl Field for Proto {
  type VecElem = u8;
}

struct FieldVec<const N: usize, T: Field>
where
  LaneCount<N>: SupportedLaneCount,
{
  vec: Simd<T::VecElem, N>,
  marker: PhantomData<T>,
}

fn gather_protos<const N: usize>(data: &[u8], indices: &VectorIndex<N>) -> FieldVec<N, Proto>
where
  LaneCount<N>: SupportedLaneCount
{
  let all = Mask::splat(true);
  let fallback = Simd::splat(0);
  let protocols = Simd::gather_select(data, all, indices.frames, fallback);
  todo!()
}

fn gather_enet_protocols<const N: usize>(data: &[u8], frames: Simd<usize, N>) -> Mask<i8, N>
where
    LaneCount<N>: SupportedLaneCount,
{
    let all = Mask::splat(true);
    let fallback = Simd::splat(0);
    let protocols = Simd::gather_select(data, all, frames, fallback);

    let ipv4 = Simd::splat(0x8u8);
    protocols.simd_eq(ipv4)
}

// Select which frames hold IPv4-over-ethernet packets. Is able to read
// [Simd<u8, N>] despite the ethertype field being a u16 because the network is
// big endian and the IPv4 magic bits 0x800 are all located in the first byte.
// "frames" indexes in to the data buffer.
fn gather_enet_ipv4<const N: usize>(data: &[u8], frames: Simd<usize, N>) -> Mask<i8, N>
where
    LaneCount<N>: SupportedLaneCount,
{
    let all = Mask::splat(true);
    let fallback = Simd::splat(0);
    let protocols = Simd::gather_select(data, all, frames, fallback);

    let ipv4 = Simd::splat(0x8u8);
    protocols.simd_eq(ipv4)
}
