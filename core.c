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
}

static void crypto_aegis128_ad(struct aegis_state *state,
			       const u8 *src, unsigned int size,
			       bool do_simd)
{
	if (AEGIS_ALIGNED(src)) {
		const union aegis_block *src_blk =
				(const union aegis_block *)src;

		while (size >= AEGIS_BLOCK_SIZE) {
			crypto_aegis128_update_a(state, src_blk, do_simd);

			size -= AEGIS_BLOCK_SIZE;
			src_blk++;
		}
	} else {
		while (size >= AEGIS_BLOCK_SIZE) {
			crypto_aegis128_update_u(state, src, do_simd);

			size -= AEGIS_BLOCK_SIZE;
			src += AEGIS_BLOCK_SIZE;
		}
	}
}

static void crypto_aegis128_wipe_chunk(struct aegis_state *state, u8 *dst,
				       const u8 *src, unsigned int size)
{
	memzero_explicit(dst, size);
}

static void crypto_aegis128_encrypt_chunk(struct aegis_state *state, u8 *dst,
					  const u8 *src, unsigned int size)
{
	union aegis_block tmp;

	if (AEGIS_ALIGNED(src) && AEGIS_ALIGNED(dst)) {
		while (size >= AEGIS_BLOCK_SIZE) {
			union aegis_block *dst_blk =
					(union aegis_block *)dst;
			const union aegis_block *src_blk =
					(const union aegis_block *)src;

			tmp = state->blocks[2];
			crypto_aegis_block_and(&tmp, &state->blocks[3]);
			crypto_aegis_block_xor(&tmp, &state->blocks[4]);
			crypto_aegis_block_xor(&tmp, &state->blocks[1]);
			crypto_aegis_block_xor(&tmp, src_blk);

			crypto_aegis128_update_a(state, src_blk, false);

			*dst_blk = tmp;

			size -= AEGIS_BLOCK_SIZE;
			src += AEGIS_BLOCK_SIZE;
			dst += AEGIS_BLOCK_SIZE;
		}
	} else {
		while (size >= AEGIS_BLOCK_SIZE) {
