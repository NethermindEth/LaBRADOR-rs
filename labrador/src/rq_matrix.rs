use crate::rq::Rq;

/// Matrix of polynomials in Rq
#[derive(Debug, Clone)]
pub struct RqMatrix<const M: usize, const N: usize, const D: usize> {
    elements: [[Rq<D>; N]; M],
}

impl<const M: usize, const N: usize, const D: usize> RqMatrix<M, N, D> {
    /// Create a random matrix of polynomials
    pub fn random() -> Self {
        let matrix = std::array::from_fn(|_| std::array::from_fn(|_| Rq::random_small()));
        Self { elements: matrix }
    }

    /// Matrix-vector multiplication
    pub fn mul_vec(&self, vec: &[Rq<D>; N]) -> [Rq<D>; M] {
        let mut result = std::array::from_fn(|_| Rq::zero());

        // TODO: Needs benchmarking with and without chunking for different
        // matrix sizes and degrees ⁠D to confirm if it provides a tangible
        // performance benefit in the target use cases.  Micro-benchmarking
        // might be helpful here.
        for (i, row) in self.elements.iter().enumerate() {
            result[i] = row
                .iter()
                .zip(vec.iter())
                .map(|(a, b)| a.clone() * b.clone())
                .fold(Rq::zero(), |acc, x| acc + x);
        }

        result
    }
}
