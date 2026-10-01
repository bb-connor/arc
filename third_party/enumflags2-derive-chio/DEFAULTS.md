Custom defaults must have the declared enum type before conversion to its
integer representation. Numeric associated constants are rejected, including
the original declaration that could introduce a bit outside the enum.

```compile_fail,E0308
use enumflags2::{bitflags, BitFlags};
#[bitflags(default = INVALID_DEFAULT)]
#[repr(u8)]
#[derive(Copy, Clone)]
enum Flag { A = 1 }
impl Flag { const INVALID_DEFAULT: u8 = 128; }
let _ = BitFlags::<Flag>::default();
```

A numeric constant matching a valid bit is still the wrong type.

```compile_fail,E0308
use enumflags2::{bitflags, BitFlags};
#[bitflags(default = NUMERIC)]
#[repr(u128)]
#[derive(Copy, Clone)]
enum Flag { A = 1 }
impl Flag { const NUMERIC: u128 = 1; }
let _ = BitFlags::<Flag>::default();
```

A constant from another enum must also be rejected before its representation
can be cast into this bitset.

```compile_fail,E0308
use enumflags2::{bitflags, BitFlags};
#[repr(u8)]
enum Other { A = 128 }
#[bitflags(default = FOREIGN)]
#[repr(u8)]
#[derive(Copy, Clone)]
enum Flag { A = 1 }
impl Flag { const FOREIGN: Other = Other::A; }
let _ = BitFlags::<Flag>::default();
```
