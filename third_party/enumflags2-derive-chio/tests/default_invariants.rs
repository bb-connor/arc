use enumflags2::{bitflags, BitFlags};

macro_rules! check_width {
    ($name:ident, $repr:ident) => {
        mod $name {
            use super::*;

            #[bitflags(default = A | LAST)]
            #[repr($repr)]
            #[derive(Copy, Clone, Debug, PartialEq)]
            enum Flag {
                A = 1,
                B = 2,
                Last = 1 << ($repr::BITS - 1),
            }

            impl Flag {
                const LAST: Self = Self::Last;
            }

            #[test]
            fn typed_defaults_preserve_valid_bits() {
                let value = BitFlags::<Flag>::default();
                assert_eq!(value.bits(), 1 | (1 << ($repr::BITS - 1)));
                assert_eq!(value.iter().collect::<Vec<_>>(), vec![Flag::A, Flag::Last]);
                assert_eq!(BitFlags::from(Flag::A).exactly_one(), Some(Flag::A));
                assert!(value.exactly_one().is_none());
                assert_eq!(BitFlags::<Flag>::from_bits_truncate(3).bits(), 3);
                assert!(BitFlags::<Flag>::from_bits(4).is_err());

                #[bitflags]
                #[repr($repr)]
                #[derive(Copy, Clone)]
                enum EmptyDefault {
                    A = 1,
                }
                assert_eq!(BitFlags::<EmptyDefault>::default().bits(), 0);
            }
        }
    };
}

check_width!(bits8, u8);
check_width!(bits16, u16);
check_width!(bits32, u32);
check_width!(bits64, u64);
check_width!(bits128, u128);
