// impl taken from https://github.com/scroll-tech/halo2-snark-aggregator/tree/main/halo2-snark-aggregator-api/src/hash

use ::poseidon2::{Spec, State};
use halo2_base::halo2_proofs::plonk::Error;
use halo2_base::{
    gates::GateInstructions,
    utils::ScalarField,
    AssignedValue, Context,
    QuantumCell::{Constant, Existing},
};

struct Poseidon2State<F: ScalarField, const T: usize, const RATE: usize> {
    s: [AssignedValue<F>; T],
}

impl<F: ScalarField, const T: usize, const RATE: usize> Poseidon2State<F, T, RATE> {
    fn x_power5_with_constant(
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        x: AssignedValue<F>,
        constant: &F,
    ) -> AssignedValue<F> {
        let x = gate.add(ctx, x, Constant(*constant));
        let x2 = gate.mul(ctx, x, x);
        let x4 = gate.mul(ctx, x2, x2);
        gate.mul(ctx, x, x4)
    }

    fn sbox_full(
        &mut self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        constants: &[F; T],
    ) {
        for (x, constant) in self.s.iter_mut().zip(constants.iter()) {
            *x = Self::x_power5_with_constant(ctx, gate, *x, constant);
        }
    }

    fn sbox_part(&mut self, ctx: &mut Context<F>, gate: &impl GateInstructions<F>, constant: &F) {
        let x = &mut self.s[0];
        *x = Self::x_power5_with_constant(ctx, gate, *x, constant);
    }
    
    fn apply_mds_external(
        &mut self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        _mds: &[[F; T]; T],
    ) {
        let mut res = vec![];
        match T {
            2 => {
                res.push(gate.mul_add(ctx, Constant(F::from(2)), Existing(self.s[0]), Existing(self.s[1])));
                res.push(gate.mul_add(ctx, Constant(F::from(2)), Existing(self.s[1]), Existing(self.s[0])));
            }
            3 => {
                let sum = gate.sum(ctx, self.s.into_iter());
                res.push(gate.add(ctx, sum, self.s[0]));
                res.push(gate.add(ctx, sum, self.s[1]));
                res.push(gate.add(ctx, sum, self.s[2]));
            }
            t => {
                assert_eq!(t % 4, 0);
                let mut calc_init = vec![];
                for i in 0..t/4 { // begin computation on [4*i, 4*i+4)
                    let t0 = gate.add(ctx, self.s[4 * i], self.s[4 * i + 1]);
                    let t1 = gate.add(ctx, self.s[4 * i + 2], self.s[4 * i + 3]);
                    let t2 = gate.mul_add(ctx, Constant(F::from(2)), self.s[4 * i + 1], t1);
                    let t3 = gate.mul_add(ctx, Constant(F::from(2)), self.s[4 * i + 3], t0);
                    let t4 = gate.mul_add(ctx, Constant(F::from(4)), t1, t3);
                    let t5 = gate.mul_add(ctx, Constant(F::from(4)), t0, t2);
                    let t6 = gate.add(ctx, t3, t5);
                    let t7 = gate.add(ctx, t2, t4); 
                    calc_init.extend_from_slice(&[t6, t5, t7, t4]);
                }
                let sums = (0..4).map(|index| {
                    gate.sum(ctx, (0..t/4).map(|index_internal| calc_init[4 * index_internal + index]))
                }).collect::<Vec<_>>();
                if t == 4 {
                    res = calc_init;
                }
                else {
                    for i in 0..t {
                        res.push(gate.add(ctx, sums[i % 4], calc_init[i]));
                    }
                }
            }
        };
        self.s = res.try_into().unwrap();
    }

    fn apply_mds_internal(
        &mut self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        mds: &[[F; T]; T],
    ) {
        let mut res = vec![];
        match T {
            2 => {
                res.push(gate.mul_add(ctx, Constant(F::from(2)), Existing(self.s[0]), Existing(self.s[1])));
                res.push(gate.mul_add(ctx, Constant(F::from(3)), Existing(self.s[1]), Existing(self.s[0])));
            }
            3 => {
                let sum = gate.sum(ctx, self.s.into_iter());
                res.push(gate.add(ctx, sum, self.s[0]));
                res.push(gate.add(ctx, sum, self.s[1]));
                res.push(gate.mul_add(ctx, Constant(F::from(2)), self.s[2], sum));
            }
            t => {
                assert_eq!(t % 4, 0);
                let sum = gate.sum(ctx, self.s);
                for i in 0..t {
                    res.push(gate.mul_add(ctx, Constant(mds[i][i] - F::from(1)), self.s[i], sum));
                }
            }
        };
        self.s = res.try_into().unwrap();
    }
}

pub struct Poseidon2Chip<F: ScalarField, const T: usize, const RATE: usize> {
    init_state: [AssignedValue<F>; T],
    state: Poseidon2State<F, T, RATE>,
    spec: Spec<F, T, RATE>,
    absorbing: Vec<AssignedValue<F>>,
}

impl<F: ScalarField, const T: usize, const RATE: usize> Poseidon2Chip<F, T, RATE> {
    pub fn new(ctx: &mut Context<F>, r_f: usize, r_p: usize) -> Result<Self, Error> {
        let init_state = State::<F, T>::default()
            .words()
            .into_iter()
            .map(|x| ctx.load_constant(x))
            .collect::<Vec<AssignedValue<F>>>();
        Ok(Self {
            spec: Spec::new(r_f, r_p),
            init_state: init_state.clone().try_into().unwrap(),
            state: Poseidon2State { s: init_state.try_into().unwrap() },
            absorbing: Vec::new(),
        })
    }

    pub fn clear(&mut self) {
        self.state = Poseidon2State { s: self.init_state };
        self.absorbing.clear();
    }

    pub fn update(&mut self, elements: &[AssignedValue<F>]) {
        self.absorbing.extend_from_slice(elements);
    }

    pub fn squeeze(
        &mut self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
    ) -> Result<AssignedValue<F>, Error> {
        let mut input_elements = vec![];
        input_elements.append(&mut self.absorbing);

        let mut padding_offset = 0;

        for chunk in input_elements.chunks(RATE) {
            padding_offset = RATE - chunk.len();
            self.permutation(ctx, gate, chunk.to_vec());
        }

        if padding_offset == 0 {
            self.permutation(ctx, gate, vec![]);
        }

        Ok(self.state.s[1])
    }

    fn permutation(
        &mut self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        inputs: Vec<AssignedValue<F>>,
    ) {
        if inputs.len() == RATE {
            for i in 1..T {
                self.state.s[i] = gate.add(ctx, self.state.s[i], inputs[i - 1]);
            }
        }

        let mds_external = &self.spec.mds_matrices().mds_external().rows();
        let mds_internal = &self.spec.mds_matrices().mds_internal().rows();

        let constants = self.spec.constants().start();
        self.state.apply_mds_external(ctx, gate, mds_external);
 
        for constants in constants.iter() {
            self.state.sbox_full(ctx, gate, constants);
            self.state.apply_mds_external(ctx, gate, mds_external);
        }

        let constants = self.spec.constants().partial();
        for constant in constants.iter() {
            self.state.sbox_part(ctx, gate, constant);
            self.state.apply_mds_internal(ctx, gate, mds_internal);
        }

        let constants = &self.spec.constants().end();
        for constants in constants.iter() {
            self.state.sbox_full(ctx, gate, constants);
            self.state.apply_mds_external(ctx, gate, mds_external);
        }
    }
}
