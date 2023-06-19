use crate::{
    gates::flex_gate::{FlexGateConfig, GateInstructions, GateStrategy, MAX_PHASE},
    halo2_proofs::{
        circuit::{Layouter, Value},
        plonk::{
            Advice, Column, ConstraintSystem, Error, SecondPhase, Selector, TableColumn, ThirdPhase,
        },
        poly::Rotation,
    },
    utils::{
        ScalarField,
    },
    Context,
    QuantumCell::{self, Constant},
};

use super::flex_gate::GateChip;

/// Specifies the gate strategy for the range chip
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SBOXStrategy {
    /// a + b * c == d
    Vertical, // vanilla implementation with vertical basic gate(s)
}

/// Configuration for SBOX Chip
#[derive(Clone, Debug)]
pub struct SBOXConfig<F: ScalarField> {
     /// gate
    pub gate: FlexGateConfig<F>,
    /// lookup_advice
    pub lookup_advice: [Vec<Column<Advice>>; MAX_PHASE], 
    /// q_lookup
    pub q_lookup: Vec<Option<Selector>>, 
    /// lookup table
    pub lookup: TableColumn, 
    /// strategy
    _strategy: SBOXStrategy,
}

impl<F: ScalarField> SBOXConfig<F> {
    /// Generates a new [RangeConfig] with the specified parameters.
    ///
    /// If `num_columns` is 0, then we assume you do not want to perform any lookups in that phase.
    ///
    /// * `meta`: [ConstraintSystem] of the circuit
    /// * `range_strategy`: [GateStrategy] of the range chip
    /// * `num_advice`: Number of [Advice] [Column]s without lookup enabled in each phase
    /// * `num_lookup_advice`: Number of `lookup_advice` [Column]s in each phase
    /// * `num_fixed`: Number of fixed [Column]s in each phase
    /// * `circuit_degree`: Degree that expresses the size of circuit (i.e., 2^<sup>circuit_degree</sup> is the number of rows in the circuit)
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        sbox_strategy: SBOXStrategy,
        num_advice: &[usize],
        num_lookup_advice: &[usize],
        num_fixed: usize,
        circuit_degree: usize,
    ) -> Self {
        let lookup = meta.lookup_table_column();

        let gate = FlexGateConfig::configure(
            meta,
            match sbox_strategy {
                SBOXStrategy::Vertical => GateStrategy::Vertical,
            },
            num_advice,
            num_fixed,
            circuit_degree,
        );

        // For now, we apply the same range lookup table to each phase
        let mut q_lookup = Vec::new();
        let mut lookup_advice = [(); MAX_PHASE].map(|_| Vec::new());
        for (phase, &num_columns) in num_lookup_advice.iter().enumerate() {
            // if num_columns is set to 0, then we assume you do not want to perform any lookups in that phase
            if num_advice[phase] == 1 && num_columns != 0 {
                q_lookup.push(Some(meta.complex_selector()));
            } else {
                q_lookup.push(None);
                for _ in 0..num_columns {
                    let a = match phase {
                        0 => meta.advice_column(),
                        1 => meta.advice_column_in(SecondPhase),
                        2 => meta.advice_column_in(ThirdPhase),
                        _ => panic!("Currently RangeConfig only supports {MAX_PHASE} phases"),
                    };
                    meta.enable_equality(a);
                    lookup_advice[phase].push(a);
                }
            }
        }

        let mut config =
            Self { lookup_advice, q_lookup, lookup, gate, _strategy: sbox_strategy };

        // sanity check: only create lookup table if there are lookup_advice columns
        if !num_lookup_advice.is_empty() {
            config.create_lookup(meta);
        }
        config.gate.max_rows = (1 << circuit_degree) - meta.minimum_rows();
        config
    }

    /// Instantiates the lookup table of the circuit.
    /// * `meta`: [ConstraintSystem] of the circuit
    fn create_lookup(&self, meta: &mut ConstraintSystem<F>) {
        for (phase, q_l) in self.q_lookup.iter().enumerate() {
            if let Some(q) = q_l {
                meta.lookup("lookup", |meta| {
                    let q = meta.query_selector(*q);
                    // there should only be 1 advice column in phase `phase`
                    let a =
                        meta.query_advice(self.gate.basic_gates[phase][0].value, Rotation::cur());
                    vec![(q * a, self.lookup)]
                });
            }
        }
        //if multiple columns
        for la in self.lookup_advice.iter().flat_map(|advices| advices.iter()) {
            meta.lookup("lookup wo selector", |meta| {
                let a = meta.query_advice(*la, Rotation::cur());
                vec![(a, self.lookup)]
            });
        }
    }

    /// Loads the lookup table into the circuit using the provided `layouter`.
    /// * `layouter`: layouter for the circuit
    pub fn load_lookup_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let sbox : Vec<u64> = vec![
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
        ];
        layouter.assign_table(
            || "SBOX table",
            |mut table| {
                for idx in 0..256 {
                    table.assign_cell(
                        || "lookup table",
                        self.lookup,
                        idx as usize,
                        || Value::known(F::from(((idx as u64 + 1) * 256 + sbox[idx]) as u64)),
                    )?;
                }
                table.assign_cell(
                    || "lookup table",
                    self.lookup,
                    256, 
                    || Value::known(F::from(0))
                )?;
                for idx1 in 0..256 {
                    for idx2 in 0..256 {
                        table.assign_cell(
                            || "lookup table",
                            self.lookup,
                            256 + 1 + idx1 * 256 + idx2, 
                            || Value::known(F::from(((1 << 24) + (1 << 16) * (idx1 ^ idx2) + (1 << 8) * idx2 + idx1) as u64))
                        )?;
                    }
                }
                for idx in 0..256 {
                    let xtime = if (idx & 0x80) == 0x80 {
                        ((idx << 1) ^ 0x1B) & 0xFF
                    } else {
                        idx << 1
                    };
                    table.assign_cell(
                        || "lookup table",
                        self.lookup, 
                        257 + 256 * 256 + idx,
                        || Value::known(F::from(((1 << 25) + idx * 256 + xtime) as u64)) 
                    )?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

/// Trait that implements methods to constrain a field element number `x` is within a range of bits.
pub trait SBOXInstructions<F: ScalarField> {
    /// The type of Gate used within the instructions.
    type Gate: GateInstructions<F>;

    /// Returns the type of gate used.
    fn gate(&self) -> &Self::Gate;

    /// Returns the [GateStrategy] for this range.
    fn strategy(&self) -> SBOXStrategy;

    /// constrains the sbox via lookups
    fn verify_sbox(&self, ctx: &mut Context<F>, a: impl Into<QuantumCell<F>>, sbox_a: impl Into<QuantumCell<F>>);

    /// constrains the xor via lookups
    fn verify_xor(&self, ctx: &mut Context<F>, a: QuantumCell<F>, b: QuantumCell<F>, c: QuantumCell<F>);

    /// constrains the xtime via lookups
    fn verify_xtime(&self, ctx: &mut Context<F>, a: QuantumCell<F>, xtime_a: QuantumCell<F>);
}

/// A chip that implements SBOXInstructions
#[derive(Clone, Debug)]
pub struct SBOXChip<F: ScalarField> {
    /// [GateStrategy] for advice values in this chip.
    strategy: SBOXStrategy,
    /// Underlying [GateChip] for this chip.
    pub gate: GateChip<F>,
}

impl<F: ScalarField> SBOXChip<F> {
    /// Creates a new [SBOXChip] with the given strategy
    pub fn new(strategy: SBOXStrategy) -> Self {
        let gate = GateChip::new(match strategy {
            SBOXStrategy::Vertical => GateStrategy::Vertical,
        });
        Self { strategy, gate }
    }

    /// Creates default [SBOXChip]
    pub fn default() -> Self {
        Self::new(SBOXStrategy::Vertical)
    }
}

impl<F: ScalarField> SBOXInstructions<F> for SBOXChip<F> {
    type Gate = GateChip<F>;

    fn gate(&self) -> &Self::Gate {
        &self.gate
    }

    fn strategy(&self) -> SBOXStrategy {
        self.strategy
    }

    fn verify_sbox(&self, ctx: &mut Context<F>, a: impl Into<QuantumCell<F>>, sbox_a: impl Into<QuantumCell<F>>) {
        // already know that a, sbox_a \in [0, 256)
        let value = self.gate().mul_add(ctx, a, Constant(F::from(256)), sbox_a);
        let value = self.gate().add(ctx, value, Constant(F::from(256)));
        ctx.cells_to_lookup.push(value);
    } 


    fn verify_xor(&self, ctx: &mut Context<F>, a: QuantumCell<F>, b: QuantumCell<F>, c: QuantumCell<F>) {
        // already knows that a, b, c \in [0, 256)
        let inner_product_left = [a, b, c, Constant(F::from(1))];
        let inner_product_right = [Constant(F::from(1)), Constant(F::from(1 << 8)), Constant(F::from(1 << 16)), Constant(F::from(1 << 24))];
        let value = self.gate().inner_product(ctx, inner_product_left, inner_product_right);
        ctx.cells_to_lookup.push(value);
    }

    fn verify_xtime(&self, ctx: &mut Context<F>, a: QuantumCell<F>, xtime_a: QuantumCell<F>) {
        // 256 * a + xtime_a + (1 << 25)
        let value = self.gate().mul_add(ctx, a, Constant(F::from(256)),xtime_a);
        let value = self.gate().add(ctx, value, Constant(F::from(1u64 << 25)));
        ctx.cells_to_lookup.push(value);
    }
}