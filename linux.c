static bool aegis128_do_simd(void)
{
#ifdef CONFIG_CRYPTO_AEGIS128_SIMD
	if (static_branch_likely(&have_simd))
		return crypto_simd_usable();
#endif
	return false;
}

static void crypto_aegis128_update(struct aegis_state *state)
{
	union aegis_block tmp;
	unsigned int i;

	tmp = state->blocks[AEGIS128_STATE_BLOCKS - 1];
	for (i = AEGIS128_STATE_BLOCKS - 1; i > 0; i--)
		crypto_aegis_aesenc(&state->blocks[i], &state->blocks[i - 1],
				    &state->blocks[i]);
	crypto_aegis_aesenc(&state->blocks[0], &tmp, &state->blocks[0]);
}

static void crypto_aegis128_update_a(struct aegis_state *state,
				     const union aegis_block *msg,
				     bool do_simd)
{
	if (IS_ENABLED(CONFIG_CRYPTO_AEGIS128_SIMD) && do_simd) {
		crypto_aegis128_update_simd(state, msg);
		return;
	}

	crypto_aegis128_update(state);
	crypto_aegis_block_xor(&state->blocks[0], msg);
}

static void crypto_aegis128_update_u(struct aegis_state *state, const void *msg,
				     bool do_simd)
{
	if (IS_ENABLED(CONFIG_CRYPTO_AEGIS128_SIMD) && do_simd) {
		crypto_aegis128_update_simd(state, msg);
		return;
	}

	crypto_aegis128_update(state);
	crypto_xor(state->blocks[0].bytes, msg, AEGIS_BLOCK_SIZE);
}

static void crypto_aegis128_init(struct aegis_state *state,
				 const union aegis_block *key,
				 const u8 *iv)
{
	union aegis_block key_iv;
	unsigned int i;

	key_iv = *key;
	crypto_xor(key_iv.bytes, iv, AEGIS_BLOCK_SIZE);

	state->blocks[0] = key_iv;
	state->blocks[1] = crypto_aegis_const[1];
	state->blocks[2] = crypto_aegis_const[0];
	state->blocks[3] = *key;
	state->blocks[4] = *key;

	crypto_aegis_block_xor(&state->blocks[3], &crypto_aegis_const[0]);
	crypto_aegis_block_xor(&state->blocks[4], &crypto_aegis_const[1]);

	for (i = 0; i < 5; i++) {
		crypto_aegis128_update_a(state, key, false);
		crypto_aegis128_update_a(state, &key_iv, false);
	}
