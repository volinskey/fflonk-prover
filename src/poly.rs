//! Polynomial evaluation utilities.
//!
//! Polynomials are represented as a `&[Fr]` of coefficients with `c[0]` the
//! constant term and `c[n-1]` the leading coefficient:
//!
//!   `P(X) = c_0 + c_1·X + c_2·X^2 + ... + c_{n-1}·X^{n-1}`

use ark_bn254::Fr;
use ark_ff::{Field, One, Zero};

/// Evaluate `P(x)` via Horner's method: `((c_{n-1}·x + c_{n-2})·x + ...)·x + c_0`.
/// Returns `0` for an empty polynomial (the zero poly).
pub fn eval_horner(coeffs: &[Fr], x: &Fr) -> Fr {
    let mut acc = Fr::zero();
    for c in coeffs.iter().rev() {
        acc = acc * x + c;
    }
    acc
}

/// P mod (X^n − β) in coefficient form (length `n`).
/// Uses the identity `X^{kn+r} ≡ β^k · X^r (mod X^n − β)`.
pub fn mod_x_n_minus_beta(coefs: &[Fr], n: usize, beta: &Fr) -> Vec<Fr> {
    let mut r = vec![Fr::zero(); n];
    let mut beta_k = Fr::one();
    for (i, c) in coefs.iter().enumerate() {
        r[i % n] += *c * beta_k;
        if i % n == n - 1 {
            beta_k *= beta;
        }
    }
    r
}

/// P / (X^n − β). Returns `None` if the division has nonzero remainder
/// (up to the `n` highest coefficients of the in-place quotient, which
/// must be zero for exact divisibility).
pub fn div_by_x_n_minus_beta(coefs: &[Fr], n: usize, beta: &Fr) -> Option<Vec<Fr>> {
    let l = coefs.len();
    if l < n {
        return None;
    }
    let inv_beta = beta.inverse()?;
    let neg_inv_beta = -inv_beta;

    let mut q = vec![Fr::zero(); l];
    for (i, c) in coefs.iter().enumerate().take(n) {
        q[i] = neg_inv_beta * c;
    }
    for i in n..l {
        q[i] = inv_beta * (q[i - n] - coefs[i]);
    }
    for q_i in q.iter().skip(l - n) {
        if !q_i.is_zero() {
            return None;
        }
    }
    q.truncate(l - n);
    Some(q)
}

/// Divide P by (X − a), returning the quotient of length `coefs.len() − 1`.
/// Fails (returns None) if division has a nonzero remainder, i.e. P(a) ≠ 0.
pub fn div_by_linear(coefs: &[Fr], a: &Fr) -> Option<Vec<Fr>> {
    let l = coefs.len();
    if l == 0 {
        return Some(vec![]);
    }
    // P(X) = (X − a)·Q(X) + r. Synthetic division from the top.
    // q_{l-2} = p_{l-1}; q_{i-1} = p_i + a·q_i. Remainder = p_0 + a·q_0.
    let mut q = vec![Fr::zero(); l - 1];
    let mut carry = Fr::zero();
    for i in (0..l).rev() {
        let new_carry = coefs[i] + *a * carry;
        if i > 0 {
            q[i - 1] = new_carry;
        }
        carry = new_carry;
    }
    // At i=0 after the loop body, `carry` is the remainder. Actually the loop
    // as written stores q[i-1] = new_carry for i > 0, and for i = 0 we skip,
    // but `carry` after the i=0 iteration is p_0 + a·q_0, which is the
    // remainder — we expect this to be zero.
    // Actually let me re-derive: P = (X-a)Q + r. From the top:
    //   q_{l-2} = p_{l-1}
    //   q_{i-1} = p_i + a·q_i   for 1 <= i <= l-2
    //   r = p_0 + a·q_0
    // The cleanest form: scan high-to-low, maintaining the running "what goes here".
    // My loop above stores q[i-1] but the remainder at the bottom isn't surfaced.
    // Re-derive: the final iteration i=0 computed new_carry = p_0 + a·q_0 which is r.
    // We need to return None if r ≠ 0.
    // Since the final `carry` after the loop IS the remainder, check it.
    if !carry.is_zero() {
        return None;
    }
    Some(q)
}

/// Lagrange interpolation: given n distinct `points` (x_i, y_i), returns the
/// unique polynomial P of degree < n with P(x_i) = y_i, in coefficient form
/// (length n).
pub fn lagrange_interpolate(points: &[(Fr, Fr)]) -> Vec<Fr> {
    let n = points.len();
    let mut result = vec![Fr::zero(); n];
    for (i, &(xi, yi)) in points.iter().enumerate() {
        // Basis polynomial L_i(X) = Π_{j≠i} (X − x_j) / (x_i − x_j).
        let mut basis = vec![Fr::one()];
        let mut denom = Fr::one();
        for (j, &(xj, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            // Multiply `basis` by (X − x_j): new_basis[k] = basis[k−1] − x_j · basis[k].
            let mut new_basis = vec![Fr::zero(); basis.len() + 1];
            new_basis[0] = -xj * basis[0];
            for k in 1..basis.len() {
                new_basis[k] = basis[k - 1] - xj * basis[k];
            }
            new_basis[basis.len()] = basis[basis.len() - 1];
            basis = new_basis;
            denom *= xi - xj;
        }
        let inv_denom = denom.inverse().expect("points must be distinct");
        for (k, &b) in basis.iter().enumerate() {
            result[k] += yi * b * inv_denom;
        }
    }
    result
}

/// In-place: `a += b` (polynomial addition, with `a` growing as needed).
pub fn add_assign(a: &mut Vec<Fr>, b: &[Fr]) {
    if a.len() < b.len() {
        a.resize(b.len(), Fr::zero());
    }
    for (i, &bi) in b.iter().enumerate() {
        a[i] += bi;
    }
}

/// In-place: `a -= b`.
pub fn sub_assign(a: &mut Vec<Fr>, b: &[Fr]) {
    if a.len() < b.len() {
        a.resize(b.len(), Fr::zero());
    }
    for (i, &bi) in b.iter().enumerate() {
        a[i] -= bi;
    }
}

/// In-place: `a *= s` (scalar multiplication).
pub fn scalar_mul_assign(a: &mut [Fr], s: &Fr) {
    for c in a.iter_mut() {
        *c *= s;
    }
}

/// In-place: subtract scalar from the constant term.
pub fn sub_scalar_assign(a: &mut Vec<Fr>, s: &Fr) {
    if a.is_empty() {
        a.push(-*s);
    } else {
        a[0] -= s;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_poly_is_zero() {
        assert_eq!(eval_horner(&[], &Fr::from(7u64)), Fr::zero());
    }

    #[test]
    fn constant_poly_is_that_constant() {
        let coeffs = [Fr::from(42u64)];
        assert_eq!(eval_horner(&coeffs, &Fr::from(1000u64)), Fr::from(42u64));
    }

    #[test]
    fn linear_poly_at_one_is_sum_of_coeffs() {
        let coeffs = [Fr::from(2u64), Fr::from(3u64)];
        assert_eq!(eval_horner(&coeffs, &Fr::one()), Fr::from(5u64));
    }

    #[test]
    fn cubic_at_two() {
        let coeffs = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        assert_eq!(eval_horner(&coeffs, &Fr::from(2u64)), Fr::from(49u64));
    }

    #[test]
    fn mod_x2_minus_3_reduces_powers() {
        // P(X) = 1 + 2X + 3X^2 + 4X^3 + 5X^4 mod (X^2 - 3)
        // X^2 ≡ 3, X^3 ≡ 3X, X^4 ≡ 9
        // = 1 + 2X + 3·3 + 4·3X + 5·9 = (1 + 9 + 45) + (2 + 12)X = 55 + 14X
        let p = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
            Fr::from(5u64),
        ];
        let r = mod_x_n_minus_beta(&p, 2, &Fr::from(3u64));
        assert_eq!(r, vec![Fr::from(55u64), Fr::from(14u64)]);
    }

    #[test]
    fn div_by_x2_minus_3_recovers_quotient() {
        // P = (X^2 - 3) · (2 + 5X) = 2X^2 + 5X^3 - 6 - 15X = -6 - 15X + 2X^2 + 5X^3
        let p = [
            -Fr::from(6u64),
            -Fr::from(15u64),
            Fr::from(2u64),
            Fr::from(5u64),
        ];
        let q = div_by_x_n_minus_beta(&p, 2, &Fr::from(3u64)).unwrap();
        assert_eq!(q, vec![Fr::from(2u64), Fr::from(5u64)]);
    }

    #[test]
    fn div_by_x_minus_a_recovers_quotient() {
        // P = (X - 5)·(X^2 + 2X + 3) = X^3 + 2X^2 + 3X - 5X^2 - 10X - 15
        //   = -15 - 7X - 3X^2 + X^3
        let p = [
            -Fr::from(15u64),
            -Fr::from(7u64),
            -Fr::from(3u64),
            Fr::from(1u64),
        ];
        let q = div_by_linear(&p, &Fr::from(5u64)).unwrap();
        assert_eq!(q, vec![Fr::from(3u64), Fr::from(2u64), Fr::from(1u64)]);
    }

    #[test]
    fn lagrange_interpolates_3_points() {
        // Interpolate P(0) = 1, P(1) = 4, P(2) = 9 → expect P(X) = (X+1)^2 = 1 + 2X + X^2
        let pts = [
            (Fr::zero(), Fr::from(1u64)),
            (Fr::one(), Fr::from(4u64)),
            (Fr::from(2u64), Fr::from(9u64)),
        ];
        let p = lagrange_interpolate(&pts);
        assert_eq!(p, vec![Fr::from(1u64), Fr::from(2u64), Fr::from(1u64)]);
    }
}
