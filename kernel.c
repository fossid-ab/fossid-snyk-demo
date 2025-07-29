static int _aead_recvmsg(struct socket *sock, struct msghdr *msg,
			 size_t ignored, int flags)
{
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct sock *psk = ask->parent;
	struct alg_sock *pask = alg_sk(psk);
	struct af_alg_ctx *ctx = ask->private;
	struct crypto_aead *tfm = pask->private;
	unsigned int i, as = crypto_aead_authsize(tfm);
	struct af_alg_async_req *areq;
	struct af_alg_tsgl *tsgl, *tmp;
	struct scatterlist *rsgl_src, *tsgl_src = NULL;
	int err = 0;
	size_t used = 0;		/* [in]  TX bufs to be en/decrypted */
	size_t outlen = 0;		/* [out] RX bufs produced by kernel */
	size_t usedpages = 0;		/* [in]  RX bufs to be used from user */
	size_t processed = 0;		/* [in]  TX bufs to be consumed */

	if (!ctx->init || ctx->more) {
		err = af_alg_wait_for_data(sk, flags, 0);
		if (err)
			return err;
	}

	/*
	 * Data length provided by caller via sendmsg that has not yet been
	 * processed.
	 */
	used = ctx->used;

	/*
	 * Make sure sufficient data is present -- note, the same check is also
	 * present in sendmsg. The checks in sendmsg shall provide an
	 * information to the data sender that something is wrong, but they are
	 * irrelevant to maintain the kernel integrity.  We need this check
	 * here too in case user space decides to not honor the error message
	 * in sendmsg and still call recvmsg. This check here protects the
	 * kernel integrity.
	 */
	if (!aead_sufficient_data(sk))
		return -EINVAL;

	/*
	 * Calculate the minimum output buffer size holding the result of the
	 * cipher operation. When encrypting data, the receiving buffer is
	 * larger by the tag length compared to the input buffer as the
	 * encryption operation generates the tag. For decryption, the input
	 * buffer provides the tag which is consumed resulting in only the
	 * plaintext without a buffer for the tag returned to the caller.
	 */
	if (ctx->enc)
		outlen = used + as;
	else
		outlen = used - as;

	/*
	 * The cipher operation input data is reduced by the associated data
	 * length as this data is processed separately later on.
	 */
	used -= ctx->aead_assoclen;

	/* Allocate cipher request for current operation. */
	areq = af_alg_alloc_areq(sk, sizeof(struct af_alg_async_req) +
				     crypto_aead_reqsize(tfm));
	if (IS_ERR(areq))
		return PTR_ERR(areq);

	/* convert iovecs of output buffers into RX SGL */
	err = af_alg_get_rsgl(sk, msg, flags, areq, outlen, &usedpages);
	if (err)
		goto free;

	/*
	 * Ensure output buffer is sufficiently large. If the caller provides
	 * less buffer space, only use the relative required input size. This
	 * allows AIO operation where the caller sent all data to be processed
	 * and the AIO operation performs the operation on the different chunks
	 * of the input data.
	 */
	if (usedpages < outlen) {
		size_t less = outlen - usedpages;

		if (used < less) {
			err = -EINVAL;
			goto free;
		}
		used -= less;
		outlen -= less;
	}

	processed = used + ctx->aead_assoclen;
	list_for_each_entry_safe(tsgl, tmp, &ctx->tsgl_list, list) {
		for (i = 0; i < tsgl->cur; i++) {
			struct scatterlist *process_sg = tsgl->sg + i;

			if (!(process_sg->length) || !sg_page(process_sg))
				continue;
			tsgl_src = process_sg;
			break;
		}
		if (tsgl_src)
			break;
	}
	if (processed && !tsgl_src) {
		err = -EFAULT;
		goto free;
	}

	/*
	 * Copy of AAD from source to destination
	 *
	 * The AAD is copied to the destination buffer without change. Even
	 * when user space uses an in-place cipher operation, the kernel
	 * will copy the data as it does not see whether such in-place operation
	 * is initiated.
	 *
	 * To ensure efficiency, the following implementation ensure that the
	 * ciphers are invoked to perform a crypto operation in-place. This
	 * is achieved by memory management specified as follows.
	 */

	/* Use the RX SGL as source (and destination) for crypto op. */
	rsgl_src = areq->first_rsgl.sgl.sgt.sgl;

	if (ctx->enc) {
		/*
		 * Encryption operation - The in-place cipher operation is
		 * achieved by the following operation:
		 *
		 * TX SGL: AAD || PT
		 *	    |	   |
		 *	    | copy |
		 *	    v	   v
		 * RX SGL: AAD || PT || Tag
		 */
		memcpy_sglist(areq->first_rsgl.sgl.sgt.sgl, tsgl_src,
			      processed);
		af_alg_pull_tsgl(sk, processed, NULL, 0);
	} else {
		/*
		 * Decryption operation - To achieve an in-place cipher
		 * operation, the following  SGL structure is used:
		 *
		 * TX SGL: AAD || CT || Tag
		 *	    |	   |	 ^
		 *	    | copy |	 | Create SGL link.
		 *	    v	   v	 |
		 * RX SGL: AAD || CT ----+
		 */

		/* Copy AAD || CT to RX SGL buffer for in-place operation. */
		memcpy_sglist(areq->first_rsgl.sgl.sgt.sgl, tsgl_src, outlen);

		/* Create TX SGL for tag and chain it to RX SGL. */
		areq->tsgl_entries = af_alg_count_tsgl(sk, processed,
						       processed - as);
		if (!areq->tsgl_entries)
			areq->tsgl_entries = 1;
		areq->tsgl = sock_kmalloc(sk, array_size(sizeof(*areq->tsgl),
							 areq->tsgl_entries),
					  GFP_KERNEL);
		if (!areq->tsgl) {
			err = -ENOMEM;
			goto free;
		}
		sg_init_table(areq->tsgl, areq->tsgl_entries);

		/* Release TX SGL, except for tag data and reassign tag data. */
		af_alg_pull_tsgl(sk, processed, areq->tsgl, processed - as);

		/* chain the areq TX SGL holding the tag with RX SGL */
		if (usedpages) {
			/* RX SGL present */
			struct af_alg_sgl *sgl_prev = &areq->last_rsgl->sgl;
			struct scatterlist *sg = sgl_prev->sgt.sgl;

			sg_unmark_end(sg + sgl_prev->sgt.nents - 1);
			sg_chain(sg, sgl_prev->sgt.nents + 1, areq->tsgl);
		} else
			/* no RX SGL present (e.g. authentication only) */
			rsgl_src = areq->tsgl;
	}

	/* Initialize the crypto operation */
	aead_request_set_crypt(&areq->cra_u.aead_req, rsgl_src,
			       areq->first_rsgl.sgl.sgt.sgl, used, ctx->iv);
	aead_request_set_ad(&areq->cra_u.aead_req, ctx->aead_assoclen);
	aead_request_set_tfm(&areq->cra_u.aead_req, tfm);

	if (msg->msg_iocb && !is_sync_kiocb(msg->msg_iocb)) {
		/* AIO operation */
		sock_hold(sk);
		areq->iocb = msg->msg_iocb;

		/* Remember output size that will be generated. */
		areq->outlen = outlen;

		aead_request_set_callback(&areq->cra_u.aead_req,
					  CRYPTO_TFM_REQ_MAY_SLEEP,
					  af_alg_async_cb, areq);
		err = ctx->enc ? crypto_aead_encrypt(&areq->cra_u.aead_req) :
				 crypto_aead_decrypt(&areq->cra_u.aead_req);

		/* AIO operation in progress */
		if (err == -EINPROGRESS)
			return -EIOCBQUEUED;

		sock_put(sk);
	} else {
		/* Synchronous operation */
		aead_request_set_callback(&areq->cra_u.aead_req,
					  CRYPTO_TFM_REQ_MAY_SLEEP |
					  CRYPTO_TFM_REQ_MAY_BACKLOG,
					  crypto_req_done, &ctx->wait);
		err = crypto_wait_req(ctx->enc ?
				crypto_aead_encrypt(&areq->cra_u.aead_req) :
				crypto_aead_decrypt(&areq->cra_u.aead_req),
				&ctx->wait);
	}
