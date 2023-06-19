use halo2_base::halo2_proofs::plonk::Error;
use halo2_base::{
    gates::{GateInstructions, SBOXInstructions},
    utils::{
        decompose_fe_to_u64_limbs, 
        ScalarField,
    },
    AssignedValue, Context,
    QuantumCell::{Constant, Witness, Existing},
};

const DEBUG: bool = false;

#[derive(Clone, Copy)]
struct Byte<F: ScalarField>  {
    pub value: AssignedValue<F>
}

impl<F: ScalarField> Byte<F>{
    pub fn new(
        ctx: &mut Context<F>, 
        gate: &impl GateInstructions<F>, 
        byte: AssignedValue<F>
    ) -> Self {
        gate.num_to_bits(ctx, byte, 8);
        Byte {
            value: byte
        }
    }

    pub fn get_value_as_u8(
        &self
    ) -> u8 {
        self.value.value().get_lower_128() as u8
    }
    
    pub fn apply_sbox(
        &self, 
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>, 
        sbox_gate: &impl SBOXInstructions<F>,
        sbox: &Vec<u8>
    ) -> Byte<F> {
        let val = self.value;
        let val_u8 = self.get_value_as_u8();
        let sbox_val = ctx.load_witness(F::from(sbox[val_u8 as usize] as u64));
        sbox_gate.verify_sbox(ctx, val, sbox_val);
        Byte::<F>::new(ctx, gate, sbox_val)
    }

/* 
    pub fn xor_bits(
        ctx: &mut Context<F>, 
        gate: &impl GateInstructions<F>, 
        bit1: impl Into<QuantumCell<F>>,
        bit2: AssignedValue<F>
    ) -> AssignedValue<F> {
        let not2 = gate.not(ctx, bit2);
        gate.select(ctx, not2, bit2, bit1)
    }
*/

    pub fn xor_assign(
        ctx: &mut Context<F>, 
        gate: &impl GateInstructions<F>, 
        sbox_gate: &impl SBOXInstructions<F>,
        byte1: Byte<F>,
        byte2: Byte<F>
    ) -> Self {
        let val1 = byte1.value;
        let val2 = byte2.value;
        let val1_u8 = byte1.get_value_as_u8();
        let val2_u8 = byte2.get_value_as_u8();
        let ret = ctx.load_witness(F::from((val1_u8 ^ val2_u8) as u64));

        sbox_gate.verify_xor(ctx, Existing(val1), Existing(val2), Existing(ret));
        Byte::<F>::new(ctx, gate, ret)
    }

    pub fn xor_constant(
        ctx: &mut Context<F>, 
        gate: &impl GateInstructions<F>, 
        sbox_gate: &impl SBOXInstructions<F>,
        byte1: Byte<F>,
        byte2: u8
    ) -> Self {
        let val1 = byte1.value;
        let val1_u8 = byte1.get_value_as_u8();
        let ret = ctx.load_witness(F::from((val1_u8 ^ byte2) as u64));

        sbox_gate.verify_xor(ctx, Existing(val1), Constant(F::from(byte2 as u64)), Existing(ret));
        Byte::<F>::new(ctx, gate, ret)
    }

    pub fn xtime(
        &self, 
        ctx: &mut Context<F>, 
        gate: &impl GateInstructions<F>, 
        sbox_gate: &impl SBOXInstructions<F>,
    ) -> Byte<F> {
        let val = self.value;
        let val_u8 = self.get_value_as_u8();
        let xtime = if (val_u8 & 0x80) == 0x80 {
            ((val_u8 << 1) ^ 0x1B) & 0xFF
        } else {
            val_u8 << 1
        };
        let ret = ctx.load_witness(F::from(xtime as u64));
        sbox_gate.verify_xtime(ctx, Existing(val), Existing(ret));
        Byte::<F>::new(ctx, gate, ret)
    }
}

struct AESState<F: ScalarField> {
    s: Vec<Vec<Byte<F>>>,
}

impl<F: ScalarField> AESState<F> {
    pub fn new(
        ctx: &mut Context<F>, 
        gate: &impl GateInstructions<F>, 
        values: Vec<AssignedValue<F>>
    ) -> Self {
        assert_eq!(values.len(), 16);
        let s = (0..4).map(|i|
             (0..4).map(|j| 
                Byte::<F>::new(ctx, gate, values[4 * i + j])
            ).collect::<Vec<_>>())
        .collect::<Vec<_>>();
        assert_eq!(s.len(), 4);
        for i in 0..4 {
            assert_eq!(s[i].len(), 4);
        }
        AESState { s }
    }

    pub fn new_from_128(
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        value: AssignedValue<F>
    ) -> Self {
        let limbs = decompose_fe_to_u64_limbs(value.value(), 16, 8).into_iter().map(|x| Witness(F::from(x)));
        let row_offset = ctx.advice.len() as isize;
        let acc = gate.inner_product(
            ctx,
            limbs,
            (0..16).map(|idx| Constant(gate.pow_of_two()[8 * idx]))
        );
        ctx.constrain_equal(&value, &acc);
        let mut assigned_values = vec![];
        assigned_values.push(ctx.get(row_offset));
        for i in 0..15 {
            assigned_values.push(ctx.get(row_offset + 1 + 3 * i as isize));
        }
        AESState::<F>::new(ctx, gate, assigned_values)
    }

    pub fn add_round_key(
        &mut self, 
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        sbox_gate: &impl SBOXInstructions<F>,
        key: &[Byte<F>]
    ) {
        for i in 0..4 {
            for j in 0..4 {
                self.s[i][j] = Byte::<F>::xor_assign(ctx, gate, sbox_gate, self.s[i][j], key[4 * i + j]);
            }
        }
    }

    pub fn sub_bytes(
        &mut self, 
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        sbox_gate: &impl SBOXInstructions<F>,
        sbox: &Vec<u8>
    ) {
        for i in 0..4 {
            for j in 0..4 {
                self.s[i][j] = self.s[i][j].apply_sbox(ctx, gate, sbox_gate, sbox);
            }
        }
    }

    pub fn shift_rows(
        &mut self
    ) {
        (self.s[0][1], self.s[1][1], self.s[2][1], self.s[3][1]) = (self.s[1][1], self.s[2][1], self.s[3][1], self.s[0][1]);
        (self.s[0][2], self.s[1][2], self.s[2][2], self.s[3][2]) = (self.s[2][2], self.s[3][2], self.s[0][2], self.s[1][2]);
        (self.s[0][3], self.s[1][3], self.s[2][3], self.s[3][3]) = (self.s[3][3], self.s[0][3], self.s[1][3], self.s[2][3]);
    }

    pub fn mix_single_column(
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        sbox_gate: &impl SBOXInstructions<F>,
        vec: &mut Vec<Byte<F>>
    ) { 
        let xor01 = Byte::<F>::xor_assign(ctx, gate, sbox_gate, vec[0], vec[1]);
        let xor23 = Byte::<F>::xor_assign(ctx, gate, sbox_gate, vec[2], vec[3]);
        let xor_total = Byte::<F>::xor_assign(ctx, gate, sbox_gate, xor01, xor23);
        let prev_0 = vec[0].clone();
        for i in 0..4 {
            let sel = if i == 3 {
                prev_0
            }
            else {
                vec[i + 1]
            };
            let v = Byte::<F>::xor_assign(ctx, gate, sbox_gate, vec[i], sel);
            let xtime_v = v.xtime(ctx, gate, sbox_gate);
            let final_xor = Byte::<F>::xor_assign(ctx, gate, sbox_gate, xor_total, xtime_v);
            vec[i] = Byte::<F>::xor_assign(ctx, gate, sbox_gate, vec[i], final_xor);
        }
    }

    pub fn mix_columns(
        &mut self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
        sbox_gate: &impl SBOXInstructions<F>,
    ) {
        for i in 0..4 {
            Self::mix_single_column(ctx, gate, sbox_gate, &mut self.s[i]);
        }
    }
}

pub struct AESChip<F: ScalarField, const KEY_LEN: usize> {
    key_bytes: Vec<Byte<F>>,
    sbox: Vec<u8>,
}

impl<F: ScalarField, const KEY_LEN: usize> AESChip<F, KEY_LEN> {
    pub fn new(ctx: &mut Context<F>, 
        sbox_gate: &impl SBOXInstructions<F>, 
        key_bytes: Vec<AssignedValue<F>>,
    ) -> Result<Self, Error> {
        let gate = sbox_gate.gate();
        assert!(KEY_LEN == 128 || KEY_LEN == 192 || KEY_LEN == 256);
        assert_eq!(key_bytes.len() * 64, KEY_LEN);

        let mut key_ret = vec![];
        for val in key_bytes.iter() {
            let limbs = decompose_fe_to_u64_limbs(val.value(), 8, 8).into_iter().map(|x| Witness(F::from(x)));
            let row_offset = ctx.advice.len() as isize;
            let acc = gate.inner_product(
                ctx,
                limbs,
                (0..8).map(|idx| Constant(gate.pow_of_two()[8 * idx]))
            );
            ctx.constrain_equal(val, &acc);
            let mut assigned_values = vec![];
            assigned_values.push(ctx.get(row_offset));
            for i in 0..7 {
                assigned_values.push(ctx.get(row_offset + 1 + 3 * i as isize));
            }
            for i in 0..8 {
                key_ret.push(Byte::<F>::new(ctx, gate, assigned_values[i]));
            }
        }
        
        let sbox : Vec<u8> = vec![
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

        let rcon: Vec<u8> = vec![
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
            0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
            0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
            0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
        ];

        let (r, n) = match KEY_LEN {
            128 => (11, 4),
            192 => (13, 6),
            256 => (15, 8),
            _ => panic!()
        };

        for i in n..(4*r) {
            if i % n == 0 {
                for j in 0..4 {
                    let byte1 = key_ret[(i - n) * 4 + j];
                    let byte2 = key_ret[(i - 1) * 4 + (j + 1) % 4];
                    let sbox_val_byte = byte2.apply_sbox(ctx, gate, sbox_gate, &sbox);
                    let mut result = Byte::<F>::xor_assign(ctx, gate, sbox_gate, byte1, sbox_val_byte);
                    if j == 0 {
                        result = Byte::<F>::xor_constant(ctx, gate, sbox_gate, result, rcon[i / n]);
                    }
                    key_ret.push(result);
                }
            }
            else if i % n == 4 && n > 6 {
                for j in 0..4 {
                    let byte1 = key_ret[(i - n) * 4 + j];
                    let byte2 = key_ret[(i - 1) * 4 + j];
                    let sbox_val_byte = byte2.apply_sbox(ctx, gate, sbox_gate, &sbox);
                    let result = Byte::<F>::xor_assign(ctx, gate, sbox_gate, byte1, sbox_val_byte);
                    key_ret.push(result);
                }
            }
            else {
                for j in 0..4 {
                    let byte1 = key_ret[(i - n) * 4 + j];
                    let byte2 = key_ret[(i - 1) * 4 + j];
                    let result = Byte::<F>::xor_assign(ctx, gate, sbox_gate, byte1, byte2);
                    key_ret.push(result);
                }
            }
        }

        if DEBUG {
            let mut key_byte_u8 = vec![];
            for key_byte in &key_ret {
                key_byte_u8.push(key_byte.value.value());
            }
            println!("{:?}", key_byte_u8);
        }

        Ok(AESChip { key_bytes: key_ret, sbox })
    }

    pub fn encrypt(
        &mut self,
        ctx: &mut Context<F>,
        sbox_gate: &impl SBOXInstructions<F>,
        plaintext: AssignedValue<F>
    ) -> AssignedValue<F> {
        let gate = sbox_gate.gate();
        let mut state = AESState::new_from_128(ctx, gate, plaintext);
        state.add_round_key(ctx, gate, sbox_gate, &self.key_bytes[0..16]);
        let rounds = match KEY_LEN {
            128 => 10,
            192 => 12,
            256 => 14,
            _ => panic!()
        };
        
        for i in 1..(rounds) {
            state.sub_bytes(ctx, gate, sbox_gate, &self.sbox); // 16 sbox
            state.shift_rows();
            state.mix_columns(ctx, gate, sbox_gate); // 64 xor 16 xtime
            state.add_round_key(ctx, gate, sbox_gate, &self.key_bytes[16*i..16+16*i]); // 16 xor
        }

        state.sub_bytes(ctx, gate, sbox_gate, &self.sbox);
        state.shift_rows();
        state.add_round_key(ctx, gate, sbox_gate, &self.key_bytes[16*rounds..]);

        // little-endian - should use inner_product but whatever
        let mut ret = ctx.load_zero();
        for i in 0..4 {
            for j in 0..4 {
                let byte_val = state.s[i][j].value;
                ret = gate.mul_add(ctx, byte_val, Constant(F::from(256).pow(&[(4 * i + j) as u64, 0, 0, 0])), ret);
            }
        }

        ret
    }
}