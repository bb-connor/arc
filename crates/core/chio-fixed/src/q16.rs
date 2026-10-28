/// A signed Q16.16 fixed-point number: the value is `bits / 2^16`.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Q16_16(i32);

const ONE_BITS: i32 = 0x0001_0000;
const BPS_PER_ONE: u32 = 10_000;

const _: () = assert!(Q16_16::ONE.0 == 0x0001_0000);
const _: () = assert!(Q16_16::MAX.0 == 0x7FFF_FFFF);
const _: () = assert!(Q16_16::MIN.0 == -0x7FFF_FFFF - 1);
const _: () = assert!(Q16_16::ZERO.0 == 0);

impl Q16_16 {
    /// Number of fractional bits.
    pub const FRAC_BITS: u32 = 16;
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(ONE_BITS);
    pub const MAX: Self = Self(i32::MAX);
    pub const MIN: Self = Self(i32::MIN);

    pub const fn from_bits(bits: i32) -> Self {
        Self(bits)
    }

    pub const fn to_bits(self) -> i32 {
        self.0
    }

    /// Exact for every `i16`: the integer occupies the high 16 bits.
    pub const fn from_int(v: i16) -> Self {
        let [hi, lo] = v.to_be_bytes();
        Self(i32::from_be_bytes([hi, lo, 0, 0]))
    }

    /// `floor(bps * 2^16 / 10_000)`; `None` when `bps > 10_000`.
    pub fn from_bps(bps: u16) -> Option<Self> {
        let bps = u32::from(bps);
        if bps > BPS_PER_ONE {
            return None;
        }
        let scaled = bps.checked_mul(ONE_BITS.unsigned_abs())?;
        let bits = scaled.checked_div(BPS_PER_ONE)?;
        i32::try_from(bits).ok().map(Self)
    }

    pub fn checked_add(self, o: Self) -> Option<Self> {
        self.0.checked_add(o.0).map(Self)
    }

    pub fn checked_sub(self, o: Self) -> Option<Self> {
        self.0.checked_sub(o.0).map(Self)
    }

    /// `floor(a * b / 2^16)`, computed exactly in `i64`.
    pub fn checked_mul(self, o: Self) -> Option<Self> {
        let product = i64::from(self.0).checked_mul(i64::from(o.0))?;
        let floored = product.checked_shr(Self::FRAC_BITS)?;
        i32::try_from(floored).ok().map(Self)
    }

    /// `floor(a * 2^16 / b)`, computed exactly in `i64`; `None` when `b == 0`.
    pub fn checked_div(self, o: Self) -> Option<Self> {
        let numerator = i64::from(self.0).checked_mul(i64::from(ONE_BITS))?;
        let denominator = i64::from(o.0);
        let quotient = numerator.checked_div(denominator)?;
        let remainder = numerator.checked_rem(denominator)?;
        let floored = if remainder != 0 && ((remainder < 0) != (denominator < 0)) {
            quotient.checked_sub(1)?
        } else {
            quotient
        };
        i32::try_from(floored).ok().map(Self)
    }

    pub fn checked_neg(self) -> Option<Self> {
        self.0.checked_neg().map(Self)
    }

    /// The greatest integer not above the value; total over every `Q16_16`.
    pub fn floor_to_int(self) -> i16 {
        let [hi, lo, _, _] = self.0.to_be_bytes();
        i16::from_be_bytes([hi, lo])
    }
}

/// Left-to-right checked sum; the order is part of the contract.
///
/// `None` as soon as any prefix sum leaves the `i32` bit range, even when a
/// later term would bring it back.
pub fn checked_sum(terms: &[Q16_16]) -> Option<Q16_16> {
    terms
        .iter()
        .try_fold(Q16_16::ZERO, |acc, term| acc.checked_add(*term))
}

/// Left-to-right checked dot product of floored products.
///
/// `None` on a length mismatch, on any product overflow and on any prefix sum
/// overflow.
pub fn checked_dot(a: &[Q16_16], b: &[Q16_16]) -> Option<Q16_16> {
    if a.len() != b.len() {
        return None;
    }
    a.iter().zip(b).try_fold(Q16_16::ZERO, |acc, (x, y)| {
        acc.checked_add(x.checked_mul(*y)?)
    })
}

#[cfg(feature = "serde")]
impl serde::Serialize for Q16_16 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i32(self.0)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Q16_16 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <i32 as serde::Deserialize>::deserialize(deserializer).map(Self)
    }
}
