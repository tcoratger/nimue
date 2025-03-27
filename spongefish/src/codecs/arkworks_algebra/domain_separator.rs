use ark_ec::CurveGroup;
use ark_ff::{Field, Fp, FpConfig, PrimeField};

use super::{
    ByteDomainSeparator, DomainSeparator, DuplexSpongeInterface, FieldDomainSeparator,
    GroupDomainSeparator,
};
use crate::codecs::{bytes_modp, bytes_uniform_modp};

impl<F, H> FieldDomainSeparator<F> for DomainSeparator<H>
where
    F: Field,
    H: DuplexSpongeInterface,
{
    fn add_scalars(self, count: usize, label: &str) -> Self {
        self.add_bytes(
            count
                * F::extension_degree() as usize
                * bytes_modp(F::BasePrimeField::MODULUS_BIT_SIZE),
            label,
        )
    }

    fn challenge_scalars(self, count: usize, label: &str) -> Self {
        self.challenge_bytes(
            count
                * F::extension_degree() as usize
                * bytes_uniform_modp(F::BasePrimeField::MODULUS_BIT_SIZE),
            label,
        )
    }
}

impl<F, C, H, const N: usize> FieldDomainSeparator<F> for DomainSeparator<H, Fp<C, N>>
where
    F: Field<BasePrimeField = Fp<C, N>>,
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    fn add_scalars(self, count: usize, label: &str) -> Self {
        self.absorb(count * F::extension_degree() as usize, label)
    }

    fn challenge_scalars(self, count: usize, label: &str) -> Self {
        self.squeeze(count * F::extension_degree() as usize, label)
    }
}

impl<C, H, const N: usize> ByteDomainSeparator for DomainSeparator<H, Fp<C, N>>
where
    C: FpConfig<N>,
    H: DuplexSpongeInterface<Fp<C, N>>,
{
    /// Add `count` bytes to the transcript, encoding each of them as an element of the field `Fp`.
    fn add_bytes(self, count: usize, label: &str) -> Self {
        self.absorb(count, label)
    }

    fn challenge_bytes(self, count: usize, label: &str) -> Self {
        let n = crate::codecs::random_bits_in_random_modp(Fp::<C, N>::MODULUS) / 8;
        self.squeeze(count.div_ceil(n), label)
    }
}

impl<G, H> GroupDomainSeparator<G> for DomainSeparator<H>
where
    G: CurveGroup,
    H: DuplexSpongeInterface,
{
    fn add_points(self, count: usize, label: &str) -> Self {
        self.add_bytes(count * G::default().compressed_size(), label)
    }
}

impl<G, H, C, const N: usize> GroupDomainSeparator<G> for DomainSeparator<H, Fp<C, N>>
where
    G: CurveGroup<BaseField = Fp<C, N>>,
    H: DuplexSpongeInterface<Fp<C, N>>,
    C: FpConfig<N>,
    Self: FieldDomainSeparator<Fp<C, N>>,
{
    fn add_points(self, count: usize, label: &str) -> Self {
        self.absorb(count * 2, label)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Fq2, Fr};
    use ark_curve25519::EdwardsProjective as Curve;
    use ark_ff::{Fp2, Fp2Config, Fp64, MontBackend, MontConfig, MontFp, PrimeField};

    use super::*;
    use crate::DefaultHash;

    #[test]
    fn test_domain_separator() {
        // OPTION 1 (fails)
        // let domain_separator = DomainSeparator::new("github.com/mmaker/spongefish")
        //     .absorb_points(1, "g")
        //     .absorb_points(1, "pk")
        //     .ratchet()
        //     .absorb_points(1, "com")
        //     .squeeze_scalars(1, "chal")
        //     .absorb_scalars(1, "resp");

        // // OPTION 2
        fn add_schnorr_domain_separator<G: ark_ec::CurveGroup, H: DuplexSpongeInterface<u8>>(
        ) -> DomainSeparator<H, u8>
        where
            DomainSeparator<H, u8>: GroupDomainSeparator<G> + FieldDomainSeparator<G::ScalarField>,
        {
            DomainSeparator::new("github.com/mmaker/spongefish")
                .add_points(1, "g")
                .add_points(1, "pk")
                .ratchet()
                .add_points(1, "com")
                .challenge_scalars(1, "chal")
                .add_scalars(1, "resp")
        }
        let domain_separator =
            add_schnorr_domain_separator::<ark_curve25519::EdwardsProjective, crate::DefaultHash>();

        // OPTION 3 (extra type, trait extensions should be on DomainSeparator or AlgebraicDomainSeparator?)
        // let domain_separator =
        //     ArkGroupDomainSeparator::<ark_curve25519::EdwardsProjective>::new("github.com/mmaker/spongefish")
        //         .add_points(1, "g")
        //         .add_points(1, "pk")
        //         .ratchet()
        //         .add_points(1, "com")
        //         .challenge_scalars(1, "chal")
        //         .add_scalars(1, "resp");

        assert_eq!(
            domain_separator.as_bytes(),
            b"github.com/mmaker/spongefish\0A32g\0A32pk\0R\0A32com\0S47chal\0A32resp"
        );
    }

    #[test]
    fn test_scalar_vs_byte_equivalence_field_modp() {
        type F = Fr;

        let label = "same-scalar";
        // Compute number of bytes needed to represent one scalar
        let scalar_bytes = bytes_modp(F::MODULUS_BIT_SIZE);

        // Add one scalar to the transcript using the scalar API
        let scalar_sep = <DomainSeparator as FieldDomainSeparator<F>>::add_scalars(
            DomainSeparator::<DefaultHash>::new("label"),
            1,
            label,
        );

        // Add the same number of bytes directly
        let byte_sep = DomainSeparator::<DefaultHash>::new("label").add_bytes(scalar_bytes, label);

        // Ensure the encodings are equal
        assert_eq!(scalar_sep.as_bytes(), byte_sep.as_bytes());
    }

    #[test]
    fn test_challenge_scalars_vs_bytes_equivalence() {
        type F = Fr;

        let label = "challenge";
        // Compute the number of bytes needed for one uniform scalar
        let uniform_bytes = bytes_uniform_modp(F::MODULUS_BIT_SIZE);

        // Request 2 scalar challenges
        let sep_scalar = <DomainSeparator as FieldDomainSeparator<F>>::challenge_scalars(
            DomainSeparator::<DefaultHash>::new("L"),
            2,
            label,
        );

        // Request 2 * bytes directly
        let sep_bytes =
            DomainSeparator::<DefaultHash>::new("L").challenge_bytes(2 * uniform_bytes, label);

        // Ensure the encodings match
        assert_eq!(sep_scalar.as_bytes(), sep_bytes.as_bytes());
    }

    #[test]
    fn test_domain_separator_fq2_bytes_are_expected() {
        type F = Fq2;

        // Construct the separator with one Fq2 absorbed and one Fq2 squeezed
        let sep = <DomainSeparator as FieldDomainSeparator<F>>::challenge_scalars(
            <DomainSeparator as FieldDomainSeparator<F>>::add_scalars(
                DomainSeparator::<DefaultHash>::new("ark-fq2"),
                1,
                "a",
            ),
            1,
            "b",
        );

        // Explanation of the expected encoding:
        // "ark-fq2"             → domain label
        // "\0A96a"              → absorb 96 bytes (Fq2 = 2 × 48)
        // "\0S126b"             → squeeze 126 bytes (Fq2 = 2 × 63 uniform bytes)
        let expected_bytes = b"ark-fq2\0A96a\0S126b";
        assert_eq!(sep.as_bytes(), expected_bytes);
    }

    #[test]
    fn test_group_point_encoding_vs_bytes_direct() {
        type G = Curve;

        // Add 2 group elements to the transcript (compressed size = 32 each)
        let point_sep = <DomainSeparator as GroupDomainSeparator<G>>::add_points(
            DomainSeparator::<DefaultHash>::new("G"),
            2,
            "X",
        );

        // Add 64 raw bytes directly instead
        let byte_sep = DomainSeparator::<DefaultHash>::new("G").add_bytes(64, "X");

        // Ensure they are equivalent
        assert_eq!(point_sep.as_bytes(), byte_sep.as_bytes());
    }

    #[test]
    fn test_domain_separator_determinism() {
        type G = Curve;
        type F = Fr;

        // First sequence: add group point, absorb scalar, squeeze scalar
        let add_pts = <DomainSeparator as GroupDomainSeparator<G>>::add_points(
            DomainSeparator::<DefaultHash>::new("proof"),
            1,
            "pk",
        );
        let add_scalars =
            <DomainSeparator as FieldDomainSeparator<F>>::add_scalars(add_pts, 1, "x");
        let d1 =
            <DomainSeparator as FieldDomainSeparator<F>>::challenge_scalars(add_scalars, 1, "y");

        // Repeat the same sequence again
        let add_pts_2 = <DomainSeparator as GroupDomainSeparator<G>>::add_points(
            DomainSeparator::<DefaultHash>::new("proof"),
            1,
            "pk",
        );
        let add_scalars_2 =
            <DomainSeparator as FieldDomainSeparator<F>>::add_scalars(add_pts_2, 1, "x");
        let d2 =
            <DomainSeparator as FieldDomainSeparator<F>>::challenge_scalars(add_scalars_2, 1, "y");

        // Resulting byte encodings must be the same
        assert_eq!(d1.as_bytes(), d2.as_bytes());
    }

    #[test]
    fn test_group_and_field_mixed_usage_structure() {
        type G = Curve;
        type F = Fr;

        // Add one group element (compressed 32 bytes)
        let step1 = <DomainSeparator as GroupDomainSeparator<G>>::add_points(
            DomainSeparator::<DefaultHash>::new("joint"),
            1,
            "pk",
        );
        // Ratchet separator state
        let step2 = step1.ratchet();
        // Add two scalars → 2 × 32 bytes = 64
        let step3 = <DomainSeparator as FieldDomainSeparator<F>>::add_scalars(step2, 2, "resp");
        // Squeeze one scalar → 32 bytes uniform modp = 47
        let sep = <DomainSeparator as FieldDomainSeparator<F>>::challenge_scalars(step3, 1, "c");

        // "joint"          → domain label
        // "\0A32pk"        → absorb 32 bytes (1 group point)
        // "\0R"            → ratchet
        // "\0A64resp"      → absorb 64 bytes (2 Fr)
        // "\0S47c"         → squeeze 47 bytes (1 Fr uniform)
        assert_eq!(sep.as_bytes(), b"joint\0A32pk\0R\0A64resp\0S47c");
    }

    #[test]
    fn test_field_domain_separator_for_custom_fp() {
        #[derive(MontConfig)]
        #[modulus = "18446744069414584321"]
        #[generator = "7"]
        pub struct FConfig64;
        pub type Field64 = Fp64<MontBackend<FConfig64, 1>>;

        pub type Field64_2 = Fp2<F2Config64>;
        pub struct F2Config64;
        impl Fp2Config for F2Config64 {
            type Fp = Field64;

            const NONRESIDUE: Self::Fp = MontFp!("7");

            const FROBENIUS_COEFF_FP2_C1: &'static [Self::Fp] = &[
                // Fq(7)**(((q^0) - 1) / 2)
                MontFp!("1"),
                // Fq(7)**(((q^1) - 1) / 2)
                MontFp!("18446744069414584320"),
            ];
        }

        // First absorb 3 Field64 elements:
        // - Fp64 has MODULUS_BIT_SIZE = 64
        // - bytes_modp(64) = 8
        // - 3 scalars × 8 bytes = 24 bytes
        // → \0A24foo
        let sep = <DomainSeparator as FieldDomainSeparator<Field64>>::add_scalars(
            DomainSeparator::new("test-fp"),
            3,
            "foo",
        );

        // Then squeeze 1 Field64_2 element:
        // - Fp2 has extension_degree = 2 (since it's two Field64 elements)
        // - bytes_uniform_modp(64) = 24
        // - 2 × 24 = 48 bytes
        // → \0S48bar
        let sep =
            <DomainSeparator as FieldDomainSeparator<Field64_2>>::challenge_scalars(sep, 1, "bar");

        // Final byte encoding is:
        // - "test-fp" domain label
        // - \0A24foo → absorb 24 bytes labeled "foo"
        // - \0S48bar → squeeze 48 bytes labeled "bar"
        let expected = b"test-fp\0A24foo\0S48bar";
        assert_eq!(sep.as_bytes(), expected);
    }
}
