use rand::thread_rng;
//use labrador::rq::Rq;

use rand::prelude::*;

pub fn generate_random_projection_matrix(d: usize, m: usize) -> Vec<Vec<i32>> {
    let mut rng = thread_rng();

    // Initialize a 2D vector with dimensions (d, m)
    let mut matrix = vec![vec![0; m]; d];

    // Fill the matrix with random values from {-1, 0, 1}
    for row in matrix.iter_mut() {
        for elem in row.iter_mut() {
            let rand_val: f64 = rng.gen();
            *elem = if rand_val < 0.25 {
                -1
            } else if rand_val < 0.75 {
                0
            } else {
                1
            };
        }
    }

    matrix
}
