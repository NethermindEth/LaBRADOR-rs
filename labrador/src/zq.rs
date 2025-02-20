use std::fmt;
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
/// Represents an element in the ring Z/qZ where q = 2^32.
/// Uses native u32 operations with automatic modulo reduction through wrapping arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Zq {
    /// Stored value is always in [0, q-1] due to u32's wrapping behavior
    value: u32,
}

impl Zq {
    /// Modulus q = 2^32 (stored as 0 in u32 due to wrapping behavior)
    pub const Q: u32 = u32::MAX.wrapping_add(1);

    /// Creates a new Zq element from a raw u32 value.
    /// No explicit modulo needed as u32 automatically wraps
    pub fn new(value: u32) -> Self {
        Self { value }
    }

    /// Zero element (additive identity)
    pub fn zero() -> Self {
        Self { value: 0 }
    }

    /// Multiplicative identity
    pub fn one() -> Self {
        Self { value: 1 }
    }

    /// Returns the raw u32 value. Use with caution as it's modulo q.
    pub fn value(&self) -> u32 {
        self.value
    }
}

// Macro to generate arithmetic trait implementations
macro_rules! impl_arithmetic {
    ($trait:ident, $assign_trait:ident, $method:ident, $assign_method:ident, $op:ident) => {
        impl $trait for Zq {
            type Output = Self;

            fn $method(self, rhs: Self) -> Self::Output {
                Self::new(self.value.$op(rhs.value))
            }
        }

        impl $assign_trait for Zq {
            fn $assign_method(&mut self, rhs: Self) {
                self.value = self.value.$op(rhs.value);
            }
        }
    };
}

impl_arithmetic!(Add, AddAssign, add, add_assign, wrapping_add);
impl_arithmetic!(Sub, SubAssign, sub, sub_assign, wrapping_sub);
impl_arithmetic!(Mul, MulAssign, mul, mul_assign, wrapping_mul);

impl From<u32> for Zq {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for Zq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Shows value with modulus for clarity
        write!(f, "{} (mod 2^32)", self.value())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_arithmetic() {
        let a = Zq::new(5);
        let b = Zq::new(3);

        // Addition
        assert_eq!((a + b).value(), 8, "5 + 3 should be 8");
        // Subtraction
        assert_eq!((a - b).value(), 2, "5 - 3 should be 2");
        // Multiplication
        assert_eq!((a * b).value(), 15, "5 * 3 should be 15");
    }

    #[test]
    fn test_wrapping_arithmetic() {
        let a = Zq::new(u32::MAX);
        let b = Zq::new(1);

        assert_eq!((a + b).value(), 0, "u32::MAX + 1 should wrap to 0");
        assert_eq!(
            (b - a).value(),
            2,
            "1 - u32::MAX should wrap to 2 (mod 2^32)"
        );
    }

    #[test]
    fn test_subtraction_edge_cases() {
        let max = Zq::new(u32::MAX);
        let one = Zq::new(1);
        let two = Zq::new(2);

        assert_eq!((one - max).value(), 2);
        assert_eq!((two - max).value(), 3);
        assert_eq!((max - max).value(), 0);
    }

    #[test]
    fn test_multiplication_wrapping() {
        let a = Zq::new(1 << 31);
        let two = Zq::new(2);

        // Multiplication wraps when exceeding u32 range
        assert_eq!((a * two).value(), 0, "2^31 * 2 should wrap to 0");
    }

    #[test]
    fn test_assignment_operators() {
        let mut a = Zq::new(5);
        let b = Zq::new(3);

        a += b;
        assert_eq!(a.value(), 8, "5 += 3 should be 8");

        a -= b;
        assert_eq!(a.value(), 5, "8 -= 3 should be 5");

        a *= b;
        assert_eq!(a.value(), 15, "5 *= 3 should be 15");
    }

    #[test]
    fn test_conversion_from_u32() {
        let a: Zq = 5_u32.into();
        assert_eq!(a.value(), 5, "Conversion from u32 should preserve value");
    }

    #[test]
    fn test_negative_arithmetic() {
        let small = Zq::new(3);
        let large = Zq::new(5);

        // Test underflow handling (3 - 5 in u32 terms)
        let result = small - large;
        assert_eq!(
            result.value(),
            u32::MAX - 1,
            "3 - 5 should wrap to 2^32 - 2"
        );

        // Test compound negative operations
        let mut x = Zq::new(10);
        x -= Zq::new(15);
        assert_eq!(x.value(), u32::MAX - 4, "10 -= 15 should wrap to 2^32 - 5");

        // Test negative equivalent value in multiplication
        let a = Zq::new(u32::MAX); // Represents -1 in mod 2^32 arithmetic
        let b = Zq::new(2);
        assert_eq!(
            (a * b).value(),
            u32::MAX - 1,
            "(-1) * 2 should be -2 ≡ 2^32 - 2"
        );
    }

    #[test]
    fn test_display_implementation() {
        let a = Zq::new(5);
        let max = Zq::new(u32::MAX);

        assert_eq!(format!("{}", a), "5 (mod 2^32)");
        assert_eq!(format!("{}", max), "4294967295 (mod 2^32)");
    }
}
