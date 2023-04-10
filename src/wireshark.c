// SPDX-License-Identifier: GPL-2.0-or-later
// Copied from the Wireshark project with some modifications.

#include "wireshark.h"

gint ssl_decrypt_record(SslDecryptSession *ssl, SslDecoder *decoder, guint8 ct, guint16 record_version,
                        gboolean ignore_mac_failed, const guchar *in, guint16 inl, const guchar *cid, guint8 cidl,
                        StringInfo *comp_str, StringInfo *out_str, guint *outl) {
    guint   pad, worklen, uncomplen, maclen, mac_fraglen = 0;
    guint8 *mac = NULL, *mac_frag = NULL;

    ssl_debug_printf("ssl_decrypt_record ciphertext len %d\n", inl);
    ssl_print_data("Ciphertext",in, inl);

    if ((ssl->session.version == TLSV1DOT3_VERSION) != (decoder->cipher_suite->kex == KEX_TLS13)) {
        ssl_debug_printf("%s Invalid cipher suite for the protocol version!\n", G_STRFUNC);
        return -1;
    }

    /* ensure we have enough storage space for decrypted data */
    if (inl > out_str->data_len)
    {
        /*ssl_debug_printf("ssl_decrypt_record: allocating %d bytes for decrypt data (old len %d)\n",
                         inl + 32, out_str->data_len);
        ssl_data_realloc(out_str, inl + 32);*/
        abort();
    }

    /* AEAD ciphers (GenericAEADCipher in TLS 1.2; TLS 1.3) have no padding nor
     * a separate MAC, so use a different routine for simplicity. */
    if (decoder->cipher_suite->mode == MODE_GCM ||
        decoder->cipher_suite->mode == MODE_CCM ||
        decoder->cipher_suite->mode == MODE_CCM_8 ||
        decoder->cipher_suite->mode == MODE_POLY1305 ||
        ssl->session.version == TLSV1DOT3_VERSION) {

        if (!tls_decrypt_aead_record(ssl, decoder, ct, record_version, ignore_mac_failed, in, inl, cid, cidl, out_str, &worklen)) {
            /* decryption failed */
            return -1;
        }

        goto skip_mac;
    }

    /* RFC 6101/2246: SSLCipherText/TLSCipherText has two structures for types:
     * (notation: { unencrypted, [ encrypted ] })
     * GenericStreamCipher: { [content, mac] }
     * GenericBlockCipher: { IV (TLS 1.1+), [content, mac, padding, padding_len] }
     * RFC 5426 (TLS 1.2): TLSCipherText has additionally:
     * GenericAEADCipher: { nonce_explicit, [content] }
     * RFC 4347 (DTLS): based on TLS 1.1, only GenericBlockCipher is supported.
     * RFC 6347 (DTLS 1.2): based on TLS 1.2, includes GenericAEADCipher too.
     */

    maclen = ssl_cipher_suite_dig(decoder->cipher_suite)->len;

    /* (TLS 1.1 and later, DTLS) Extract explicit IV for GenericBlockCipher */
    if (decoder->cipher_suite->mode == MODE_CBC) {
        guint blocksize = 0;

        switch (ssl->session.version) {
            case TLSV1DOT1_VERSION:
            case TLSV1DOT2_VERSION:
            case DTLSV1DOT0_VERSION:
            case DTLSV1DOT2_VERSION:
            case DTLSV1DOT0_OPENSSL_VERSION:
                blocksize = ssl_get_cipher_blocksize(decoder->cipher_suite);
                if (inl < blocksize) {
                    ssl_debug_printf("ssl_decrypt_record failed: input %d has no space for IV %d\n",
                                     inl, blocksize);
                    return -1;
                }
                pad = gcry_cipher_setiv(decoder->evp, in, blocksize);
                if (pad != 0) {
                    ssl_debug_printf("ssl_decrypt_record failed: failed to set IV: %s %s\n",
                                     gcry_strsource (pad), gcry_strerror (pad));
                }

                inl -= blocksize;
                in += blocksize;
                break;
        }

        /* Encrypt-then-MAC for (D)TLS (RFC 7366) */
        if (ssl->state & SSL_ENCRYPT_THEN_MAC) {
            /*
             * MAC is calculated over (IV + ) ENCRYPTED contents:
             *
             *      MAC(MAC_write_key, ... +
             *          IV +       // for TLS 1.1 or greater
             *          TLSCiphertext.enc_content);
             */
            if (inl < maclen) {
                ssl_debug_printf("%s failed: input %d has no space for MAC %d\n",
                                 G_STRFUNC, inl, maclen);
                return -1;
            }
            inl -= maclen;
            mac = (guint8 *)in + inl;
            mac_frag = (guint8 *)in - blocksize;
            mac_fraglen = blocksize + inl;
        }
    }

    /* First decrypt*/
    if ((pad = ssl_cipher_decrypt(&decoder->evp, out_str->data, out_str->data_len, in, inl)) != 0) {
        ssl_debug_printf("ssl_decrypt_record failed: ssl_cipher_decrypt: %s %s\n", gcry_strsource (pad),
                         gcry_strerror (pad));
        return -1;
    }

    ssl_print_data("Plaintext", out_str->data, inl);
    worklen=inl;


    /* strip padding for GenericBlockCipher */
    if (decoder->cipher_suite->mode == MODE_CBC) {
        if (inl < 1) { /* Should this check happen earlier? */
            ssl_debug_printf("ssl_decrypt_record failed: input length %d too small\n", inl);
            return -1;
        }
        pad=out_str->data[inl-1];
        if (worklen <= pad) {
            ssl_debug_printf("ssl_decrypt_record failed: padding %d too large for work %d\n",
                             pad, worklen);
            return -1;
        }
        worklen-=(pad+1);
        ssl_debug_printf("ssl_decrypt_record found padding %d final len %d\n",
                         pad, worklen);
    }

    /* MAC for GenericStreamCipher and GenericBlockCipher.
     * (normal case without Encrypt-then-MAC (RFC 7366) extension. */
    if (!mac) {
        /*
         * MAC is calculated over the DECRYPTED contents:
         *
         *      MAC(MAC_write_key, ... + TLSCompressed.fragment);
         */
        if (worklen < maclen) {
            ssl_debug_printf("%s wrong record len/padding outlen %d\n work %d\n", G_STRFUNC, *outl, worklen);
            return -1;
        }
        worklen -= maclen;
        mac = out_str->data + worklen;
        mac_frag = out_str->data;
        mac_fraglen = worklen;
    }

    /* If NULL encryption active and no keys are available, do not bother
     * checking the MAC. We do not have keys for that. */
    if (decoder->cipher_suite->mode == MODE_STREAM &&
        decoder->cipher_suite->enc == ENC_NULL &&
        !(ssl->state & SSL_MASTER_SECRET)) {
        ssl_debug_printf("MAC check skipped due to missing keys\n");
        goto skip_mac;
    }

    /* Now check the MAC */
    ssl_debug_printf("checking mac (len %d, version %X, ct %d seq %" G_GUINT64_FORMAT ")\n",
            worklen, ssl->session.version, ct, decoder->seq);
    if(ssl->session.version==SSLV3_VERSION){
        if(ssl3_check_mac(decoder,ct,mac_frag,mac_fraglen,mac) < 0) {
            if(ignore_mac_failed) {
                ssl_debug_printf("ssl_decrypt_record: mac failed, but ignored for troubleshooting ;-)\n");
            }
            else{
                ssl_debug_printf("ssl_decrypt_record: mac failed\n");
                return -1;
            }
        }
        else{
            ssl_debug_printf("ssl_decrypt_record: mac ok\n");
        }
    }
    else if(ssl->session.version==TLSV1_VERSION || ssl->session.version==TLSV1DOT1_VERSION || ssl->session.version==TLSV1DOT2_VERSION || ssl->session.version==GMTLSV1_VERSION){
        if(tls_check_mac(decoder,ct,ssl->session.version,mac_frag,mac_fraglen,mac)< 0) {
            if(ignore_mac_failed) {
                ssl_debug_printf("ssl_decrypt_record: mac failed, but ignored for troubleshooting ;-)\n");
            }
            else{
                ssl_debug_printf("ssl_decrypt_record: mac failed\n");
                return -1;
            }
        }
        else{
            ssl_debug_printf("ssl_decrypt_record: mac ok\n");
        }
    }
    else if(ssl->session.version==DTLSV1DOT0_VERSION ||
            ssl->session.version==DTLSV1DOT2_VERSION ||
            ssl->session.version==DTLSV1DOT0_OPENSSL_VERSION){
        /* Try rfc-compliant mac first, and if failed, try old openssl's non-rfc-compliant mac */
        if(dtls_check_mac(decoder,ct,ssl->session.version,mac_frag,mac_fraglen,mac)>= 0) {
            ssl_debug_printf("ssl_decrypt_record: mac ok\n");
        }
        else if(tls_check_mac(decoder,ct,TLSV1_VERSION,mac_frag,mac_fraglen,mac)>= 0) {
            ssl_debug_printf("ssl_decrypt_record: dtls rfc-compliant mac failed, but old openssl's non-rfc-compliant mac ok\n");
        }
        else if(ignore_mac_failed) {
            ssl_debug_printf("ssl_decrypt_record: mac failed, but ignored for troubleshooting ;-)\n");
        }
        else{
            ssl_debug_printf("ssl_decrypt_record: mac failed\n");
            return -1;
        }
    }
    skip_mac:

    *outl = worklen;

    if (decoder->compression > 0) {
        ssl_debug_printf("ssl_decrypt_record: compression method %d\n", decoder->compression);
        ssl_data_copy(comp_str, out_str);
        ssl_print_data("Plaintext compressed", comp_str->data, worklen);
        if (!decoder->decomp) {
            ssl_debug_printf("decrypt_ssl3_record: no decoder available\n");
            return -1;
        }
        if (ssl_decompress_record(decoder->decomp, comp_str->data, worklen, out_str, &uncomplen) < 0) return -1;
        ssl_print_data("Plaintext uncompressed", out_str->data, uncomplen);
        *outl = uncomplen;
    }

    return 0;
}

int ssl_decompress_record(SslDecompress *decomp, const guchar *in, guint inl, StringInfo *out_str, guint *outl) {
    ssl_debug_printf("ssl_decompress_record: unsupported compression method %d\n", decomp->compression);
    return -1;
}

gboolean tls_decrypt_aead_record(SslDecryptSession *ssl, SslDecoder *decoder, guint8 ct, guint16 record_version,
                                 gboolean ignore_mac_failed, const guchar *in, guint16 inl, const guchar *cid,
                                 guint8 cidl, StringInfo *out_str, guint *outl) {
    /* RFC 5246 (TLS 1.2) 6.2.3.3 defines the TLSCipherText.fragment as:
     * GenericAEADCipher: { nonce_explicit, [content] }
     * In TLS 1.3 this explicit nonce is gone.
     * With AES GCM/CCM, "[content]" is actually the concatenation of the
     * ciphertext and authentication tag.
     */
    const guint16   version = ssl->session.version;
    const gboolean  is_v12 = version == TLSV1DOT2_VERSION || version == DTLSV1DOT2_VERSION;
    gcry_error_t    err;
    const guchar   *explicit_nonce = NULL, *ciphertext;
    guint           ciphertext_len, auth_tag_len;
    guchar          nonce[12];
    const ssl_cipher_mode_t cipher_mode = decoder->cipher_suite->mode;
#ifdef HAVE_LIBGCRYPT_AEAD
    const gboolean  is_cid = ct == SSL_ID_TLS12_CID && version == DTLSV1DOT2_VERSION;
    const guint8    draft_version = ssl->session.tls13_draft_version;
    const guchar   *auth_tag_wire;
    guchar          auth_tag_calc[16];
#else
    guchar          nonce_with_counter[16] = { 0 };
#endif

    switch (cipher_mode) {
        case MODE_GCM:
        case MODE_CCM:
        case MODE_POLY1305:
            auth_tag_len = 16;
            break;
        case MODE_CCM_8:
            auth_tag_len = 8;
            break;
        default:
            ssl_debug_printf("%s unsupported cipher!\n", G_STRFUNC);
            return FALSE;
    }

    /* Parse input into explicit nonce (TLS 1.2 only), ciphertext and tag. */
    if (is_v12 && cipher_mode != MODE_POLY1305) {
        if (inl < EXPLICIT_NONCE_LEN + auth_tag_len) {
            ssl_debug_printf("%s input %d is too small for explicit nonce %d and auth tag %d\n",
                             G_STRFUNC, inl, EXPLICIT_NONCE_LEN, auth_tag_len);
            return FALSE;
        }
        explicit_nonce = in;
        ciphertext = explicit_nonce + EXPLICIT_NONCE_LEN;
        ciphertext_len = inl - EXPLICIT_NONCE_LEN - auth_tag_len;
    } else if (version == TLSV1DOT3_VERSION || cipher_mode == MODE_POLY1305) {
        if (inl < auth_tag_len) {
            ssl_debug_printf("%s input %d has no space for auth tag %d\n", G_STRFUNC, inl, auth_tag_len);
            return FALSE;
        }
        ciphertext = in;
        ciphertext_len = inl - auth_tag_len;
    } else {
        ssl_debug_printf("%s Unexpected TLS version %#x\n", G_STRFUNC, version);
        return FALSE;
    }
#ifdef HAVE_LIBGCRYPT_AEAD
    auth_tag_wire = ciphertext + ciphertext_len;
#endif

    /*
     * Nonce construction is version-specific. Note that AEAD_CHACHA20_POLY1305
     * (RFC 7905) uses a nonce construction similar to TLS 1.3.
     */
    if (is_v12 && cipher_mode != MODE_POLY1305) {
        DISSECTOR_ASSERT(decoder->write_iv.data_len == IMPLICIT_NONCE_LEN);
        /* Implicit (4) and explicit (8) part of nonce. */
        memcpy(nonce, decoder->write_iv.data, IMPLICIT_NONCE_LEN);
        memcpy(nonce + IMPLICIT_NONCE_LEN, explicit_nonce, EXPLICIT_NONCE_LEN);

#ifndef HAVE_LIBGCRYPT_AEAD
        if (cipher_mode == MODE_GCM) {
            /* NIST SP 800-38D, sect. 7.2 says that the 32-bit counter part starts
             * at 1, and gets incremented before passing to the block cipher. */
            memcpy(nonce_with_counter, nonce, IMPLICIT_NONCE_LEN + EXPLICIT_NONCE_LEN);
            nonce_with_counter[IMPLICIT_NONCE_LEN + EXPLICIT_NONCE_LEN + 3] = 2;
        } else if (cipher_mode == MODE_CCM || cipher_mode == MODE_CCM_8) {
            /* The nonce for CCM and GCM are the same, but the nonce is used as input
             * in the CCM algorithm described in RFC 3610. The nonce generated here is
             * the one from RFC 3610 sect 2.3. Encryption. */
            /* Flags: (L-1) ; L = 16 - 1 - nonceSize */
            nonce_with_counter[0] = 3 - 1;
            memcpy(nonce_with_counter + 1, nonce, IMPLICIT_NONCE_LEN + EXPLICIT_NONCE_LEN);
            /* struct { opaque salt[4]; opaque nonce_explicit[8] } CCMNonce (RFC 6655) */
            nonce_with_counter[IMPLICIT_NONCE_LEN + EXPLICIT_NONCE_LEN + 3] = 1;
        } else {
            assert(false);
            //ws_assert_not_reached();
        }
#endif
    } else if (version == TLSV1DOT3_VERSION || cipher_mode == MODE_POLY1305) {
        /*
         * Technically the nonce length must be at least 8 bytes, but for
         * AES-GCM, AES-CCM and Poly1305-ChaCha20 the nonce length is exact 12.
         */
        const guint nonce_len = 12;
        if(decoder->write_iv.data_len != nonce_len) {
            printf("IVDLEN: %d\n", decoder->write_iv.data_len);
        }
        DISSECTOR_ASSERT(decoder->write_iv.data_len == nonce_len);
        memcpy(nonce, decoder->write_iv.data, decoder->write_iv.data_len);
        /* Sequence number is left-padded with zeroes and XORed with write_iv */
        phton64(nonce + nonce_len - 8, pntoh64(nonce + nonce_len - 8) ^ decoder->seq);
        ssl_debug_printf("%s seq %" G_GUINT64_FORMAT "\n", G_STRFUNC, decoder->seq);
    }

    /* Set nonce and additional authentication data */
#ifdef HAVE_LIBGCRYPT_AEAD
    gcry_cipher_reset(decoder->evp);
    ssl_print_data("nonce", nonce, 12);
    err = gcry_cipher_setiv(decoder->evp, nonce, 12);
    if (err) {
        ssl_debug_printf("%s failed to set nonce: %s\n", G_STRFUNC, gcry_strerror(err));
        return FALSE;
    }

    if (decoder->cipher_suite->mode == MODE_CCM || decoder->cipher_suite->mode == MODE_CCM_8) {
        /* size of plaintext, additional authenticated data and auth tag. */
        guint64 lengths[3] = { ciphertext_len, is_v12 ? 13 : 0, auth_tag_len };
        if (is_cid) {
            lengths[1] = 13 + 1 + cidl; /* cid length (1 byte) + cid (cidl bytes)*/
        }
        gcry_cipher_ctl(decoder->evp, GCRYCTL_SET_CCM_LENGTHS, lengths, sizeof(lengths));
    }

    /* (D)TLS 1.2 needs specific AAD, TLS 1.3 (before -25) uses empty AAD. */
    if (is_cid) { /* if connection ID */
        guchar aad[14+DTLS_MAX_CID_LENGTH];
        guint aad_len = 14 + cidl;
        phton64(aad, decoder->seq);         /* record sequence number */
        phton16(aad, decoder->epoch);       /* DTLS 1.2 includes epoch. */
        aad[8] = ct;                        /* TLSCompressed.type */
        phton16(aad + 9, record_version);   /* TLSCompressed.version */
        memcpy(aad + 11, cid, cidl);        /* cid */
        aad[11 + cidl] = cidl;              /* cid_length */
        phton16(aad + 12 + cidl, ciphertext_len);  /* TLSCompressed.length */
        ssl_print_data("AAD", aad, aad_len);
        err = gcry_cipher_authenticate(decoder->evp, aad, aad_len);
        if (err) {
            ssl_debug_printf("%s failed to set AAD: %s\n", G_STRFUNC, gcry_strerror(err));
            return FALSE;
        }
    } else if (is_v12) {
        guchar aad[13];
        phton64(aad, decoder->seq);         /* record sequence number */
        if (version == DTLSV1DOT2_VERSION) {
            phton16(aad, decoder->epoch);   /* DTLS 1.2 includes epoch. */
        }
        aad[8] = ct;                        /* TLSCompressed.type */
        phton16(aad + 9, record_version);   /* TLSCompressed.version */
        phton16(aad + 11, ciphertext_len);  /* TLSCompressed.length */
        ssl_print_data("AAD", aad, sizeof(aad));
        err = gcry_cipher_authenticate(decoder->evp, aad, sizeof(aad));
        if (err) {
            ssl_debug_printf("%s failed to set AAD: %s\n", G_STRFUNC, gcry_strerror(err));
            return FALSE;
        }
    } else if (draft_version >= 25 || draft_version == 0) {
        guchar aad[5];
        aad[0] = ct;                        /* TLSCiphertext.opaque_type (23) */
        phton16(aad + 1, record_version);   /* TLSCiphertext.legacy_record_version (0x0303) */
        phton16(aad + 3, inl);              /* TLSCiphertext.length */
        ssl_print_data("AAD", aad, sizeof(aad));
        err = gcry_cipher_authenticate(decoder->evp, aad, sizeof(aad));
        if (err) {
            ssl_debug_printf("%s failed to set AAD: %s\n", G_STRFUNC, gcry_strerror(err));
            return FALSE;
        }
    }
#else
    err = gcry_cipher_setctr(decoder->evp, nonce_with_counter, 16);
    if (err) {
        ssl_debug_printf("%s failed: failed to set CTR: %s\n", G_STRFUNC, gcry_strerror(err));
        return FALSE;
    }
#endif

    /* Decrypt now that nonce and AAD are set. */
    err = gcry_cipher_decrypt(decoder->evp, out_str->data, out_str->data_len, ciphertext, ciphertext_len);
    if (err) {
        ssl_debug_printf("%s decrypt failed: %s\n", G_STRFUNC, gcry_strerror(err));
        return FALSE;
    }

    /* Check authentication tag for authenticity (replaces MAC) */
#ifdef HAVE_LIBGCRYPT_AEAD
    err = gcry_cipher_gettag(decoder->evp, auth_tag_calc, auth_tag_len);
    if (err == 0 && !memcmp(auth_tag_calc, auth_tag_wire, auth_tag_len)) {
        ssl_print_data("auth_tag(OK)", auth_tag_calc, auth_tag_len);
    } else {
        if (err) {
            ssl_debug_printf("%s cannot obtain tag: %s\n", G_STRFUNC, gcry_strerror(err));
        } else {
            ssl_debug_printf("%s auth tag mismatch\n", G_STRFUNC);
            ssl_print_data("auth_tag(expect)", auth_tag_calc, auth_tag_len);
            ssl_print_data("auth_tag(actual)", auth_tag_wire, auth_tag_len);
        }
        if (ignore_mac_failed) {
            ssl_debug_printf("%s: auth check failed, but ignored for troubleshooting ;-)\n", G_STRFUNC);
        } else {
            return FALSE;
        }
    }
#else
    ssl_debug_printf("Libgcrypt is older than 1.6, unable to verify auth tag!\n");
#endif

    /*
     * Increment the (implicit) sequence number for TLS 1.2/1.3. This is done
     * after successful authentication to ensure that early data is skipped when
     * CLIENT_EARLY_TRAFFIC_SECRET keys are unavailable.
     */
    if (version == TLSV1DOT2_VERSION || version == TLSV1DOT3_VERSION) {
        decoder->seq++;
    }

    ssl_print_data("Plaintext", out_str->data, ciphertext_len);
    *outl = ciphertext_len;
    return TRUE;
}

gint dtls_check_mac(SslDecoder *decoder, gint ct, int ver, guint8 *data, guint32 datalen, guint8 *mac) {
    SSL_HMAC hm;
    gint     md;
    guint32  len;
    guint8   buf[DIGEST_MAX_SIZE];
    gint16   temp;

    md=ssl_get_digest_by_name(ssl_cipher_suite_dig(decoder->cipher_suite)->name);
    ssl_debug_printf("dtls_check_mac mac type:%s md %d\n",
                     ssl_cipher_suite_dig(decoder->cipher_suite)->name, md);

    if (ssl_hmac_init(&hm,md) != 0)
        return -1;
    if (ssl_hmac_setkey(&hm,decoder->mac_key.data,decoder->mac_key.data_len) != 0)
        return -1;

    ssl_debug_printf("dtls_check_mac seq: %" G_GUINT64_FORMAT " epoch: %d\n",decoder->seq,decoder->epoch);
    /* hash sequence number */
    phton64(buf, decoder->seq);
    buf[0]=decoder->epoch>>8;
    buf[1]=(guint8)decoder->epoch;

    ssl_hmac_update(&hm,buf,8);

    /* hash content type */
    buf[0]=ct;
    ssl_hmac_update(&hm,buf,1);

    /* hash version,data length and data */
    temp = g_htons(ver);
    memcpy(buf, &temp, 2);
    ssl_hmac_update(&hm,buf,2);

    temp = g_htons(datalen);
    memcpy(buf, &temp, 2);
    ssl_hmac_update(&hm,buf,2);
    ssl_hmac_update(&hm,data,datalen);
    /* get digest and digest len */
    len = sizeof(buf);
    ssl_hmac_final(&hm,buf,&len);
    ssl_hmac_cleanup(&hm);
    ssl_print_data("Mac", buf, len);
    if(memcmp(mac,buf,len))
        return -1;

    return(0);
}

void ssl_debug_printf(const gchar *fmt, ...) {
    va_list ap;

    if (!ssl_debug_file)
        return;

    va_start(ap, fmt);
    vfprintf(ssl_debug_file, fmt, ap);
    va_end(ap);
}

void ssl_print_data(const gchar *name, const guchar *data, size_t len) {
    size_t i, j, k;
    if (!ssl_debug_file)
        return;
    fprintf(ssl_debug_file,"%s[%d]:\n",name, (int) len);
    for (i=0; i<len; i+=16) {
        fprintf(ssl_debug_file,"| ");
        for (j=i, k=0; k<16 && j<len; ++j, ++k)
            fprintf(ssl_debug_file,"%.2x ",data[j]);
        for (; k<16; ++k)
            fprintf(ssl_debug_file,"   ");
        fputc('|', ssl_debug_file);
        for (j=i, k=0; k<16 && j<len; ++j, ++k) {
            guchar c = data[j];
            if (!g_ascii_isprint(c) || (c=='\t')) c = '.';
            fputc(c, ssl_debug_file);
        }
        for (; k<16; ++k)
            fputc(' ', ssl_debug_file);
        fprintf(ssl_debug_file,"|\n");
    }
}

void ssl_print_string(const gchar *name, const StringInfo *data) {
    ssl_print_data(name, data->data, data->data_len);
}

gint ssl_data_alloc(StringInfo *str, size_t len) {
    str->data = (guchar *)g_malloc(len);
    /* the allocator can return a null pointer for a size equal to 0,
     * and that must be allowed */
    if (len > 0 && !str->data)
        return -1;
    str->data_len = (guint) len;
    return 0;
}

void ssl_data_set(StringInfo *str, const guchar *data, guint len) {
            DISSECTOR_ASSERT(data);
    memcpy(str->data, data, len);
    str->data_len = len;
}

gint ssl_data_realloc(StringInfo *str, guint len) {
    str->data = (guchar *)g_realloc(str->data, len);
    if (!str->data)
        return -1;
    str->data_len = len;
    return 0;
}

gint ssl_data_copy(StringInfo *dst, StringInfo *src) {
    if (dst->data_len < src->data_len) {
        if (ssl_data_realloc(dst, src->data_len))
            return -1;
    }
    memcpy(dst->data, src->data, src->data_len);
    dst->data_len = src->data_len;
    return 0;
}

gint ssl_hmac_init(gcry_md_hd_t *md, gint algo) {
    gcry_error_t  err;
    const char   *err_str, *err_src;

    err = gcry_md_open(md,algo, GCRY_MD_FLAG_HMAC);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        ssl_debug_printf("ssl_hmac_init(): gcry_md_open failed %s/%s", err_str, err_src);
        return -1;
    }
    return 0;
}

gint ssl_hmac_setkey(gcry_md_hd_t *md, const void *key, gint len) {
    gcry_error_t  err;
    const char   *err_str, *err_src;

    err = gcry_md_setkey (*(md), key, len);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        ssl_debug_printf("ssl_hmac_setkey(): gcry_md_setkey failed %s/%s", err_str, err_src);
        return -1;
    }
    return 0;
}

gint ssl_hmac_reset(gcry_md_hd_t *md) {
    gcry_md_reset(*md);
    return 0;
}

const SslCipherSuite *ssl_find_cipher(int num) {
    const SslCipherSuite *c;
    for(c=cipher_suites;c->number!=-1;c++){
        if(c->number==num){
            return c;
        }
    }

    return NULL;
}

guint ssl_get_cipher_blocksize(const SslCipherSuite *cipher_suite) {
    gint cipher_algo;
    if (cipher_suite->mode != MODE_CBC) return 0;
    cipher_algo = ssl_get_cipher_by_name(ciphers[cipher_suite->enc - ENC_START]);
    return (guint)gcry_cipher_get_algo_blklen(cipher_algo);
}

int ssl_get_cipher_algo(const SslCipherSuite *cipher_suite) {
    return gcry_cipher_map_name(ciphers[cipher_suite->enc - ENC_START]);
}

guint ssl_get_cipher_export_keymat_size(int cipher_suite_num) {
    switch (cipher_suite_num) {
        /* See RFC 6101 (SSL 3.0), Table 2, column Key Material. */
        case 0x0003:    /* TLS_RSA_EXPORT_WITH_RC4_40_MD5 */
        case 0x0006:    /* TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 */
        case 0x0008:    /* TLS_RSA_EXPORT_WITH_DES40_CBC_SHA */
        case 0x000B:    /* TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA */
        case 0x000E:    /* TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA */
        case 0x0011:    /* TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA */
        case 0x0014:    /* TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA */
        case 0x0017:    /* TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 */
        case 0x0019:    /* TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA */
            return 5;

            /* not defined in below draft, but "implemented by several vendors",
             * https://www.ietf.org/mail-archive/web/tls/current/msg00036.html */
        case 0x0060:    /* TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 */
        case 0x0061:    /* TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 */
            return 7;

            /* Note: the draft states that DES_CBC needs 8 bytes, but Wireshark always
             * used 7. Until a pcap proves 8, let's use the old value. Link:
             * https://tools.ietf.org/html/draft-ietf-tls-56-bit-ciphersuites-01 */
        case 0x0062:    /* TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA */
        case 0x0063:    /* TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA */
        case 0x0064:    /* TLS_RSA_EXPORT1024_WITH_RC4_56_SHA */
        case 0x0065:    /* TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA */
            return 7;

        default:
            return 0;
    }
}

void tls_hash(StringInfo *secret, StringInfo *seed, gint md, StringInfo *out, guint out_len) {
    /* RFC 2246 5. HMAC and the pseudorandom function
     * '+' denotes concatenation.
     * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
     *                        HMAC_hash(secret, A(2) + seed) + ...
     * A(0) = seed
     * A(i) = HMAC_hash(secret, A(i - 1))
     */
    guint8   *ptr;
    guint     left, tocpy;
    guint8   *A;
    guint8    _A[DIGEST_MAX_SIZE], tmp[DIGEST_MAX_SIZE];
    guint     A_l, tmp_l;
    SSL_HMAC  hm;

    ptr  = out->data;
    left = out_len;

    ssl_print_string("tls_hash: hash secret", secret);
    ssl_print_string("tls_hash: hash seed", seed);
    /* A(0) = seed */
    A = seed->data;
    A_l = seed->data_len;

    ssl_hmac_init(&hm, md);
    while (left) {
        /* A(i) = HMAC_hash(secret, A(i-1)) */
        ssl_hmac_setkey(&hm, secret->data, secret->data_len);
        ssl_hmac_update(&hm, A, A_l);
        A_l = sizeof(_A); /* upper bound len for hash output */
        ssl_hmac_final(&hm, _A, &A_l);
        A = _A;

        /* HMAC_hash(secret, A(i) + seed) */
        ssl_hmac_reset(&hm);
        ssl_hmac_setkey(&hm, secret->data, secret->data_len);
        ssl_hmac_update(&hm, A, A_l);
        ssl_hmac_update(&hm, seed->data, seed->data_len);
        tmp_l = sizeof(tmp); /* upper bound len for hash output */
        ssl_hmac_final(&hm, tmp, &tmp_l);
        ssl_hmac_reset(&hm);

        /* ssl_hmac_final puts the actual digest output size in tmp_l */
        tocpy = MIN(left, tmp_l);
        memcpy(ptr, tmp, tocpy);
        ptr += tocpy;
        left -= tocpy;
    }
    ssl_hmac_cleanup(&hm);
    out->data_len = out_len;

    ssl_print_string("hash out", out);
}

gint tls_handshake_hash(SslDecryptSession *ssl, StringInfo *out) {
    SSL_MD5_CTX  md5;
    SSL_SHA_CTX  sha;

    if (ssl_data_alloc(out, 36) < 0)
        return -1;

    ssl_md5_init(&md5);
    ssl_md5_update(&md5,ssl->handshake_data.data,ssl->handshake_data.data_len);
    ssl_md5_final(out->data,&md5);
    ssl_md5_cleanup(&md5);

    ssl_sha_init(&sha);
    ssl_sha_update(&sha,ssl->handshake_data.data,ssl->handshake_data.data_len);
    ssl_sha_final(out->data+16,&sha);
    ssl_sha_cleanup(&sha);
    return 0;
}

gint tls12_handshake_hash(SslDecryptSession *ssl, gint md, StringInfo *out) {
    SSL_MD  mc;
    guint8 tmp[48];
    guint  len;

    ssl_md_init(&mc, md);
    ssl_md_update(&mc,ssl->handshake_data.data,ssl->handshake_data.data_len);
    ssl_md_final(&mc, tmp, &len);
    ssl_md_cleanup(&mc);

    if (ssl_data_alloc(out, len) < 0)
        return -1;
    memcpy(out->data, tmp, len);
    return 0;
}

gboolean
tls_prf(StringInfo *secret, const gchar *usage, StringInfo *rnd1, StringInfo *rnd2, StringInfo *out, guint out_len) {
    StringInfo  seed, sha_out, md5_out;
    guint8     *ptr;
    StringInfo  s1, s2;
    guint       i,s_l;
    size_t      usage_len, rnd2_len;
    gboolean    success = FALSE;
    usage_len = strlen(usage);
    rnd2_len = rnd2 ? rnd2->data_len : 0;

    /* initalize buffer for sha, md5 random seed*/
    if (ssl_data_alloc(&sha_out, MAX(out_len, 20)) < 0) {
        ssl_debug_printf("tls_prf: can't allocate sha out\n");
        return FALSE;
    }
    if (ssl_data_alloc(&md5_out, MAX(out_len, 16)) < 0) {
        ssl_debug_printf("tls_prf: can't allocate md5 out\n");
        goto free_sha;
    }
    if (ssl_data_alloc(&seed, usage_len+rnd1->data_len+rnd2_len) < 0) {
        ssl_debug_printf("tls_prf: can't allocate rnd %d\n",
                         (int) (usage_len+rnd1->data_len+rnd2_len));
        goto free_md5;
    }

    ptr=seed.data;
    memcpy(ptr,usage,usage_len);
    ptr+=usage_len;
    memcpy(ptr,rnd1->data,rnd1->data_len);
    if (rnd2_len > 0) {
        ptr+=rnd1->data_len;
        memcpy(ptr,rnd2->data,rnd2->data_len);
        /*ptr+=rnd2->data_len;*/
    }

    /* initalize buffer for client/server seeds*/
    s_l=secret->data_len/2 + secret->data_len%2;
    if (ssl_data_alloc(&s1, s_l) < 0) {
        ssl_debug_printf("tls_prf: can't allocate secret %d\n", s_l);
        goto free_seed;
    }
    if (ssl_data_alloc(&s2, s_l) < 0) {
        ssl_debug_printf("tls_prf: can't allocate secret(2) %d\n", s_l);
        goto free_s1;
    }

    memcpy(s1.data,secret->data,s_l);
    memcpy(s2.data,secret->data + (secret->data_len - s_l),s_l);

    ssl_debug_printf("tls_prf: tls_hash(md5 secret_len %d seed_len %d )\n", s1.data_len, seed.data_len);
    tls_hash(&s1, &seed, ssl_get_digest_by_name("MD5"), &md5_out, out_len);
    ssl_debug_printf("tls_prf: tls_hash(sha)\n");
    tls_hash(&s2, &seed, ssl_get_digest_by_name("SHA1"), &sha_out, out_len);

    for (i = 0; i < out_len; i++)
        out->data[i] = md5_out.data[i] ^ sha_out.data[i];
    /* success, now store the new meaningful data length */
    out->data_len = out_len;
    success = TRUE;

    ssl_print_string("PRF out",out);
    g_free(s2.data);
    free_s1:
    g_free(s1.data);
    free_seed:
    g_free(seed.data);
    free_md5:
    g_free(md5_out.data);
    free_sha:
    g_free(sha_out.data);
    return success;
}

gboolean tls12_prf(gint md, StringInfo *secret, const gchar *usage, StringInfo *rnd1, StringInfo *rnd2, StringInfo *out,
                   guint out_len) {
    StringInfo label_seed;
    size_t     usage_len, rnd2_len;
    rnd2_len = rnd2 ? rnd2->data_len : 0;

    usage_len = strlen(usage);
    if (ssl_data_alloc(&label_seed, usage_len+rnd1->data_len+rnd2_len) < 0) {
        ssl_debug_printf("tls12_prf: can't allocate label_seed\n");
        return FALSE;
    }
    memcpy(label_seed.data, usage, usage_len);
    memcpy(label_seed.data+usage_len, rnd1->data, rnd1->data_len);
    if (rnd2_len > 0)
        memcpy(label_seed.data+usage_len+rnd1->data_len, rnd2->data, rnd2->data_len);

    ssl_debug_printf("tls12_prf: tls_hash(hash_alg %s secret_len %d seed_len %d )\n", gcry_md_algo_name(md), secret->data_len, label_seed.data_len);
    tls_hash(secret, &label_seed, md, out, out_len);
    g_free(label_seed.data);
    ssl_print_string("PRF out", out);
    return TRUE;
}

void ssl3_generate_export_iv(StringInfo *r1, StringInfo *r2, StringInfo *out, guint out_len) {
    SSL_MD5_CTX md5;
    guint8      tmp[16];

    ssl_md5_init(&md5);
    ssl_md5_update(&md5,r1->data,r1->data_len);
    ssl_md5_update(&md5,r2->data,r2->data_len);
    ssl_md5_final(tmp,&md5);
    ssl_md5_cleanup(&md5);

            DISSECTOR_ASSERT(out_len <= sizeof(tmp));
    ssl_data_set(out, tmp, out_len);
    ssl_print_string("export iv", out);
}

gboolean
ssl3_prf(StringInfo *secret, const gchar *usage, StringInfo *rnd1, StringInfo *rnd2, StringInfo *out, guint out_len) {
    SSL_MD5_CTX  md5;
    SSL_SHA_CTX  sha;
    guint        off;
    gint         i = 0,j;
    guint8       buf[20];

    ssl_sha_init(&sha);
    ssl_md5_init(&md5);
    for (off = 0; off < out_len; off += 16) {
        guchar outbuf[16];
        i++;

        ssl_debug_printf("ssl3_prf: sha1_hash(%d)\n",i);
        /* A, BB, CCC,  ... */
        for(j=0;j<i;j++){
            buf[j]=64+i;
        }

        ssl_sha_update(&sha,buf,i);
        ssl_sha_update(&sha,secret->data,secret->data_len);

        if(!strcmp(usage,"client write key") || !strcmp(usage,"server write key")){
            if (rnd2)
                ssl_sha_update(&sha,rnd2->data,rnd2->data_len);
            ssl_sha_update(&sha,rnd1->data,rnd1->data_len);
        }
        else{
            ssl_sha_update(&sha,rnd1->data,rnd1->data_len);
            if (rnd2)
                ssl_sha_update(&sha,rnd2->data,rnd2->data_len);
        }

        ssl_sha_final(buf,&sha);
        ssl_sha_reset(&sha);

        ssl_debug_printf("ssl3_prf: md5_hash(%d) datalen %d\n",i,
                         secret->data_len);
        ssl_md5_update(&md5,secret->data,secret->data_len);
        ssl_md5_update(&md5,buf,20);
        ssl_md5_final(outbuf,&md5);
        ssl_md5_reset(&md5);

        memcpy(out->data + off, outbuf, MIN(out_len - off, 16));
    }
    ssl_sha_cleanup(&sha);
    ssl_md5_cleanup(&md5);
    out->data_len = out_len;

    return TRUE;
}

gboolean
prf(SslDecryptSession *ssl, StringInfo *secret, const gchar *usage, StringInfo *rnd1, StringInfo *rnd2, StringInfo *out,
    guint out_len) {
    switch (ssl->session.version) {
        case SSLV3_VERSION:
            return ssl3_prf(secret, usage, rnd1, rnd2, out, out_len);

        case TLSV1_VERSION:
        case TLSV1DOT1_VERSION:
        case DTLSV1DOT0_VERSION:
        case DTLSV1DOT0_OPENSSL_VERSION:
        case GMTLSV1_VERSION:
            return tls_prf(secret, usage, rnd1, rnd2, out, out_len);

        default: /* TLSv1.2 */
            switch (ssl->cipher_suite->dig) {
                case DIG_SHA384:
                    return tls12_prf(GCRY_MD_SHA384, secret, usage, rnd1, rnd2,
                                     out, out_len);
                default:
                    return tls12_prf(GCRY_MD_SHA256, secret, usage, rnd1, rnd2,
                                     out, out_len);
            }
    }
}

int
ssl_init_decoder(SslDecoder *dec, const SslCipherSuite *cipher_suite, gint cipher_algo, gint compression, guint8 *mk,
                 guint8 *sk, guint8 *iv, guint iv_length) {
    ssl_cipher_mode_t mode = cipher_suite->mode;

    //dec = wmem_new0(wmem_file_scope(), SslDecoder);
    /* init mac buffer: mac storage is embedded into decoder struct to save a
     memory allocation and waste samo more memory*/
    dec->cipher_suite=cipher_suite;
    dec->compression = compression;
    if ((mode == MODE_STREAM && mk != NULL) || mode == MODE_CBC) {
        // AEAD ciphers use no MAC key, but stream and block ciphers do. Note
        // the special case for NULL ciphers, even if there is insufficieny
        // keying material (including MAC key), we will can still create
        // decoders since "decryption" is easy for such ciphers.
        dec->mac_key.data = dec->_mac_key_or_write_iv;
        ssl_data_set(&dec->mac_key, mk, ssl_cipher_suite_dig(cipher_suite)->len);
    } else if (mode == MODE_GCM || mode == MODE_CCM || mode == MODE_CCM_8 || mode == MODE_POLY1305) {
        // Input for the nonce, to be used with AEAD ciphers.
                DISSECTOR_ASSERT(iv_length <= sizeof(dec->_mac_key_or_write_iv));
        dec->write_iv.data = dec->_mac_key_or_write_iv;
        ssl_data_set(&dec->write_iv, iv, iv_length);
    }
    dec->seq = 0;
    // TODO: dec->decomp = ssl_create_decompressor(compression);

    // TODO: wmem_register_callback(wmem_file_scope(), ssl_decoder_destroy_cb, dec);

    if (ssl_cipher_init(&dec->evp,cipher_algo,sk,iv,cipher_suite->mode) < 0) {
        ssl_debug_printf("%s: can't create cipher id:%d mode:%d\n", G_STRFUNC,
                         cipher_algo, cipher_suite->mode);
        return -1;
    }

    ssl_debug_printf("decoder initialized (digest len %d)\n", ssl_cipher_suite_dig(cipher_suite)->len);
    return 0;
}

int ssl_generate_keyring_material(SslDecryptSession *ssl_session) {
    StringInfo  key_block = { NULL, 0 };
    guint8      _iv_c[MAX_BLOCK_SIZE],_iv_s[MAX_BLOCK_SIZE];
    guint8      _key_c[MAX_KEY_SIZE],_key_s[MAX_KEY_SIZE];
    gint        needed;
    gint        cipher_algo = -1;   /* special value (-1) for NULL encryption */
    guint       encr_key_len, write_iv_len = 0;
    gboolean    is_export_cipher;
    guint8     *ptr, *c_iv = NULL, *s_iv = NULL;
    guint8     *c_wk = NULL, *s_wk = NULL, *c_mk = NULL, *s_mk = NULL;
    const SslCipherSuite *cipher_suite = ssl_session->cipher_suite;

    /* TLS 1.3 is handled directly in tls13_change_key. */
    if (ssl_session->session.version == TLSV1DOT3_VERSION) {
        ssl_debug_printf("%s: detected TLS 1.3. Should not have been called!\n", G_STRFUNC);
        return -1;
    }

    /* check for enough info to proced */
    guint need_all = SSL_CIPHER|SSL_CLIENT_RANDOM|SSL_SERVER_RANDOM|SSL_VERSION;
    guint need_any = SSL_MASTER_SECRET | SSL_PRE_MASTER_SECRET;
    if (((ssl_session->state & need_all) != need_all) || ((ssl_session->state & need_any) == 0)) {
        ssl_debug_printf("ssl_generate_keyring_material not enough data to generate key "
                         "(0x%02X required 0x%02X or 0x%02X)\n", ssl_session->state,
                         need_all|SSL_MASTER_SECRET, need_all|SSL_PRE_MASTER_SECRET);
        /* Special case: for NULL encryption, allow dissection of data even if
         * the Client Hello is missing (MAC keys are now skipped though). */
        need_all = SSL_CIPHER|SSL_VERSION;
        if ((ssl_session->state & need_all) == need_all &&
            cipher_suite->enc == ENC_NULL) {
            ssl_debug_printf("%s NULL cipher found, will create a decoder but "
                             "skip MAC validation as keys are missing.\n", G_STRFUNC);
            goto create_decoders;
        }

        return -1;
    }

    /* if master key is not available, generate is from the pre-master secret */
    if (!(ssl_session->state & SSL_MASTER_SECRET)) {
        if ((ssl_session->state & SSL_EXTENDED_MASTER_SECRET_MASK) == SSL_EXTENDED_MASTER_SECRET_MASK) {
            StringInfo handshake_hashed_data;
            gint ret;

            handshake_hashed_data.data = NULL;
            handshake_hashed_data.data_len = 0;

            ssl_debug_printf("%s:PRF(pre_master_secret_extended)\n", G_STRFUNC);
            ssl_print_string("pre master secret",&ssl_session->pre_master_secret);
                    DISSECTOR_ASSERT(ssl_session->handshake_data.data_len > 0);

            switch(ssl_session->session.version) {
                case TLSV1_VERSION:
                case TLSV1DOT1_VERSION:
                case DTLSV1DOT0_VERSION:
                case DTLSV1DOT0_OPENSSL_VERSION:
                case GMTLSV1_VERSION:
                    ret = tls_handshake_hash(ssl_session, &handshake_hashed_data);
                    break;
                default:
                    switch (cipher_suite->dig) {
                        case DIG_SHA384:
                            ret = tls12_handshake_hash(ssl_session, GCRY_MD_SHA384, &handshake_hashed_data);
                            break;
                        default:
                            ret = tls12_handshake_hash(ssl_session, GCRY_MD_SHA256, &handshake_hashed_data);
                            break;
                    }
                    break;
            }
            if (ret) {
                ssl_debug_printf("%s can't generate handshake hash\n", G_STRFUNC);
                return -1;
            }

            // wmem_free(wmem_file_scope(), ssl_session->handshake_data.data);
            free(ssl_session->handshake_data.data);
            ssl_session->handshake_data.data = NULL;
            ssl_session->handshake_data.data_len = 0;

            if (!prf(ssl_session, &ssl_session->pre_master_secret, "extended master secret",
                     &handshake_hashed_data,
                     NULL, &ssl_session->master_secret,
                     SSL_MASTER_SECRET_LENGTH)) {
                ssl_debug_printf("%s can't generate master_secret\n", G_STRFUNC);
                g_free(handshake_hashed_data.data);
                return -1;
            }
            g_free(handshake_hashed_data.data);
        } else {
            ssl_debug_printf("%s:PRF(pre_master_secret)\n", G_STRFUNC);
            ssl_print_string("pre master secret",&ssl_session->pre_master_secret);
            ssl_print_string("client random",&ssl_session->client_random);
            ssl_print_string("server random",&ssl_session->server_random);
            if (!prf(ssl_session, &ssl_session->pre_master_secret, "master secret",
                     &ssl_session->client_random,
                     &ssl_session->server_random, &ssl_session->master_secret,
                     SSL_MASTER_SECRET_LENGTH)) {
                ssl_debug_printf("%s can't generate master_secret\n", G_STRFUNC);
                return -1;
            }
        }
        ssl_print_string("master secret",&ssl_session->master_secret);

        /* the pre-master secret has been 'consumend' so we must clear it now */
        ssl_session->state &= ~SSL_PRE_MASTER_SECRET;
        ssl_session->state |= SSL_MASTER_SECRET;
    }

    /* Find the Libgcrypt cipher algorithm for the given SSL cipher suite ID */
    if (cipher_suite->enc != ENC_NULL) {
        const char *cipher_name = ciphers[cipher_suite->enc-ENC_START];
        ssl_debug_printf("%s CIPHER: %s\n", G_STRFUNC, cipher_name);
        cipher_algo = ssl_get_cipher_by_name(cipher_name);
        if (cipher_algo == 0) {
            ssl_debug_printf("%s can't find cipher %s\n", G_STRFUNC, cipher_name);
            return -1;
        }
    }

    /* Export ciphers consume less material from the key block. */
    encr_key_len = ssl_get_cipher_export_keymat_size(cipher_suite->number);
    is_export_cipher = encr_key_len > 0;
    if (!is_export_cipher && cipher_suite->enc != ENC_NULL) {
        encr_key_len = (guint)gcry_cipher_get_algo_keylen(cipher_algo);
    }

    if (cipher_suite->mode == MODE_CBC) {
        write_iv_len = (guint)gcry_cipher_get_algo_blklen(cipher_algo);
    } else if (cipher_suite->mode == MODE_GCM || cipher_suite->mode == MODE_CCM || cipher_suite->mode == MODE_CCM_8) {
        /* account for a four-byte salt for client and server side (from
         * client_write_IV and server_write_IV), see GCMNonce (RFC 5288) */
        write_iv_len = 4;
    } else if (cipher_suite->mode == MODE_POLY1305) {
        /* RFC 7905: SecurityParameters.fixed_iv_length is twelve bytes */
        write_iv_len = 12;
    }

    /* Compute the key block. First figure out how much data we need */
    needed = ssl_cipher_suite_dig(cipher_suite)->len*2;     /* MAC key  */
    needed += 2 * encr_key_len;                             /* encryption key */
    needed += 2 * write_iv_len;                             /* write IV */

    key_block.data = (guchar *)g_malloc(needed);
    ssl_debug_printf("%s sess key generation\n", G_STRFUNC);
    if (!prf(ssl_session, &ssl_session->master_secret, "key expansion",
             &ssl_session->server_random,&ssl_session->client_random,
             &key_block, needed)) {
        ssl_debug_printf("%s can't generate key_block\n", G_STRFUNC);
        goto fail;
    }
    ssl_print_string("key expansion", &key_block);

    ptr=key_block.data;
    /* client/server write MAC key (for non-AEAD ciphers) */
    if (cipher_suite->mode == MODE_STREAM || cipher_suite->mode == MODE_CBC) {
        c_mk=ptr; ptr+=ssl_cipher_suite_dig(cipher_suite)->len;
        s_mk=ptr; ptr+=ssl_cipher_suite_dig(cipher_suite)->len;
    }
    /* client/server write encryption key */
    c_wk=ptr; ptr += encr_key_len;
    s_wk=ptr; ptr += encr_key_len;
    /* client/server write IV (used as IV (for CBC) or salt (for AEAD)) */
    if (write_iv_len > 0) {
        c_iv=ptr; ptr += write_iv_len;
        s_iv=ptr; /* ptr += write_iv_len; */
    }

    /* export ciphers work with a smaller key length */
    if (is_export_cipher) {
        if (cipher_suite->mode == MODE_CBC) {

            /* We only have room for MAX_BLOCK_SIZE bytes IVs, but that's
             all we should need. This is a sanity check */
            if (write_iv_len > MAX_BLOCK_SIZE) {
                ssl_debug_printf("%s cipher suite block must be at most %d nut is %d\n",
                                 G_STRFUNC, MAX_BLOCK_SIZE, write_iv_len);
                goto fail;
            }

            if(ssl_session->session.version==SSLV3_VERSION){
                /* The length of these fields are ignored by this caller */
                StringInfo iv_c, iv_s;
                iv_c.data = _iv_c;
                iv_s.data = _iv_s;

                ssl_debug_printf("%s ssl3_generate_export_iv\n", G_STRFUNC);
                ssl3_generate_export_iv(&ssl_session->client_random,
                                        &ssl_session->server_random, &iv_c, write_iv_len);
                ssl_debug_printf("%s ssl3_generate_export_iv(2)\n", G_STRFUNC);
                ssl3_generate_export_iv(&ssl_session->server_random,
                                        &ssl_session->client_random, &iv_s, write_iv_len);
            }
            else{
                guint8 _iv_block[MAX_BLOCK_SIZE * 2];
                StringInfo iv_block;
                StringInfo key_null;
                guint8 _key_null;

                key_null.data = &_key_null;
                key_null.data_len = 0;

                iv_block.data = _iv_block;

                ssl_debug_printf("%s prf(iv_block)\n", G_STRFUNC);
                if (!prf(ssl_session, &key_null, "IV block",
                         &ssl_session->client_random,
                         &ssl_session->server_random, &iv_block,
                         write_iv_len * 2)) {
                    ssl_debug_printf("%s can't generate tls31 iv block\n", G_STRFUNC);
                    goto fail;
                }

                memcpy(_iv_c, iv_block.data, write_iv_len);
                memcpy(_iv_s, iv_block.data + write_iv_len, write_iv_len);
            }

            c_iv=_iv_c;
            s_iv=_iv_s;
        }

        if (ssl_session->session.version==SSLV3_VERSION){

            SSL_MD5_CTX md5;
            ssl_debug_printf("%s MD5(client_random)\n", G_STRFUNC);

            ssl_md5_init(&md5);
            ssl_md5_update(&md5,c_wk,encr_key_len);
            ssl_md5_update(&md5,ssl_session->client_random.data,
                           ssl_session->client_random.data_len);
            ssl_md5_update(&md5,ssl_session->server_random.data,
                           ssl_session->server_random.data_len);
            ssl_md5_final(_key_c,&md5);
            ssl_md5_cleanup(&md5);
            c_wk=_key_c;

            ssl_md5_init(&md5);
            ssl_debug_printf("%s MD5(server_random)\n", G_STRFUNC);
            ssl_md5_update(&md5,s_wk,encr_key_len);
            ssl_md5_update(&md5,ssl_session->server_random.data,
                           ssl_session->server_random.data_len);
            ssl_md5_update(&md5,ssl_session->client_random.data,
                           ssl_session->client_random.data_len);
            ssl_md5_final(_key_s,&md5);
            ssl_md5_cleanup(&md5);
            s_wk=_key_s;
        }
        else{
            StringInfo key_c, key_s, k;
            key_c.data = _key_c;
            key_s.data = _key_s;

            k.data = c_wk;
            k.data_len = encr_key_len;
            ssl_debug_printf("%s PRF(key_c)\n", G_STRFUNC);
            if (!prf(ssl_session, &k, "client write key",
                     &ssl_session->client_random,
                     &ssl_session->server_random, &key_c, sizeof(_key_c))) {
                ssl_debug_printf("%s can't generate tll31 server key \n", G_STRFUNC);
                goto fail;
            }
            c_wk=_key_c;

            k.data = s_wk;
            k.data_len = encr_key_len;
            ssl_debug_printf("%s PRF(key_s)\n", G_STRFUNC);
            if (!prf(ssl_session, &k, "server write key",
                     &ssl_session->client_random,
                     &ssl_session->server_random, &key_s, sizeof(_key_s))) {
                ssl_debug_printf("%s can't generate tll31 client key \n", G_STRFUNC);
                goto fail;
            }
            s_wk=_key_s;
        }
    }

    /* show key material info */
    if (c_mk != NULL) {
        ssl_print_data("Client MAC key",c_mk,ssl_cipher_suite_dig(cipher_suite)->len);
        ssl_print_data("Server MAC key",s_mk,ssl_cipher_suite_dig(cipher_suite)->len);
    }
    ssl_print_data("Client Write key", c_wk, encr_key_len);
    ssl_print_data("Server Write key", s_wk, encr_key_len);
    /* used as IV for CBC mode and the AEAD implicit nonce (salt) */
    if (write_iv_len > 0) {
        ssl_print_data("Client Write IV", c_iv, write_iv_len);
        ssl_print_data("Server Write IV", s_iv, write_iv_len);
    }

    create_decoders:
    /* create both client and server ciphers*/
    ssl_debug_printf("%s ssl_create_decoder(client)\n", G_STRFUNC);
    if (ssl_init_decoder(&ssl_session->client_new, cipher_suite, cipher_algo, ssl_session->session.compression, c_mk, c_wk, c_iv, write_iv_len) < 0) {
        ssl_debug_printf("%s can't init client decoder\n", G_STRFUNC);
        goto fail;
    }
    ssl_debug_printf("%s ssl_create_decoder(server)\n", G_STRFUNC);
    if (ssl_init_decoder(&ssl_session->server_new, cipher_suite, cipher_algo, ssl_session->session.compression, s_mk, s_wk, s_iv, write_iv_len) < 0) {
        ssl_debug_printf("%s can't init client decoder\n", G_STRFUNC);
        goto fail;
    }

    /* Continue the SSL stream after renegotiation with new keys. */
    // TODO: ssl_session->client_new->flow = ssl_session->client ? ssl_session->client->flow : ssl_create_flow();
    // TODO: ssl_session->server_new->flow = ssl_session->server ? ssl_session->server->flow : ssl_create_flow();

    ssl_debug_printf("%s: client seq %" G_GUINT64_FORMAT ", server seq %" G_GUINT64_FORMAT "\n",
                     G_STRFUNC, ssl_session->client_new.seq, ssl_session->server_new.seq);
    g_free(key_block.data);
    ssl_session->state |= SSL_HAVE_SESSION_KEY;
    return 0;

    fail:
    g_free(key_block.data);
    return -1;
}

gint tls_check_mac(SslDecoder *decoder, gint ct, gint ver, guint8 *data, guint32 datalen, guint8 *mac) {
    SSL_HMAC hm;
    gint     md;
    guint32  len;
    guint8   buf[DIGEST_MAX_SIZE];
    gint16   temp;

    md=ssl_get_digest_by_name(ssl_cipher_suite_dig(decoder->cipher_suite)->name);
    ssl_debug_printf("tls_check_mac mac type:%s md %d\n",
                     ssl_cipher_suite_dig(decoder->cipher_suite)->name, md);

    if (ssl_hmac_init(&hm,md) != 0)
        return -1;
    if (ssl_hmac_setkey(&hm,decoder->mac_key.data,decoder->mac_key.data_len) != 0)
        return -1;

    /* hash sequence number */
    phton64(buf, decoder->seq);

    decoder->seq++;

    ssl_hmac_update(&hm,buf,8);

    /* hash content type */
    buf[0]=ct;
    ssl_hmac_update(&hm,buf,1);

    /* hash version,data length and data*/
    /* *((gint16*)buf) = g_htons(ver); */
    temp = g_htons(ver);
    memcpy(buf, &temp, 2);
    ssl_hmac_update(&hm,buf,2);

    /* *((gint16*)buf) = g_htons(datalen); */
    temp = g_htons(datalen);
    memcpy(buf, &temp, 2);
    ssl_hmac_update(&hm,buf,2);
    ssl_hmac_update(&hm,data,datalen);

    /* get digest and digest len*/
    len = sizeof(buf);
    ssl_hmac_final(&hm,buf,&len);
    ssl_hmac_cleanup(&hm);
    ssl_print_data("Mac", buf, len);
    if(memcmp(mac,buf,len))
        return -1;

    return 0;
}

int ssl3_check_mac(SslDecoder *decoder, int ct, guint8 *data, guint32 datalen, guint8 *mac) {
    SSL_MD  mc;
    gint    md;
    guint32 len;
    guint8  buf[64],dgst[20];
    gint    pad_ct;
    gint16  temp;

    pad_ct=(decoder->cipher_suite->dig==DIG_SHA)?40:48;

    /* get cipher used for digest comptuation */
    md=ssl_get_digest_by_name(ssl_cipher_suite_dig(decoder->cipher_suite)->name);
    if (ssl_md_init(&mc,md) !=0)
        return -1;

    /* do hash computation on data && padding */
    ssl_md_update(&mc,decoder->mac_key.data,decoder->mac_key.data_len);

    /* hash padding*/
    memset(buf,0x36,pad_ct);
    ssl_md_update(&mc,buf,pad_ct);

    /* hash sequence number */
    phton64(buf, decoder->seq);
    decoder->seq++;
    ssl_md_update(&mc,buf,8);

    /* hash content type */
    buf[0]=ct;
    ssl_md_update(&mc,buf,1);

    /* hash data length in network byte order and data*/
    /* *((gint16* )buf) = g_htons(datalen); */
    temp = g_htons(datalen);
    memcpy(buf, &temp, 2);
    ssl_md_update(&mc,buf,2);
    ssl_md_update(&mc,data,datalen);

    /* get partial digest */
    ssl_md_final(&mc,dgst,&len);
    ssl_md_reset(&mc);

    /* hash mac key */
    ssl_md_update(&mc,decoder->mac_key.data,decoder->mac_key.data_len);

    /* hash padding and partial digest*/
    memset(buf,0x5c,pad_ct);
    ssl_md_update(&mc,buf,pad_ct);
    ssl_md_update(&mc,dgst,len);

    ssl_md_final(&mc,dgst,&len);
    ssl_md_cleanup(&mc);

    if(memcmp(mac,dgst,len))
        return -1;

    return(0);
}

void ssl_hmac_update(gcry_md_hd_t *md, const void *data, gint len) {
    gcry_md_write(*(md), data, len);
}

void ssl_hmac_final(gcry_md_hd_t *md, guchar *data, guint *datalen) {
    gint  algo;
    guint len;

    algo = gcry_md_get_algo (*(md));
    len  = gcry_md_get_algo_dlen(algo);
            DISSECTOR_ASSERT(len <= *datalen);
    memcpy(data, gcry_md_read(*(md), algo), len);
    *datalen = len;
}

void ssl_hmac_cleanup(gcry_md_hd_t *md) {
    gcry_md_close(*(md));
}

gint ssl_md_init(gcry_md_hd_t *md, gint algo) {
    gcry_error_t  err;
    const char   *err_str, *err_src;
    err = gcry_md_open(md,algo, 0);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        ssl_debug_printf("ssl_md_init(): gcry_md_open failed %s/%s", err_str, err_src);
        return -1;
    }
    return 0;
}

void ssl_md_update(gcry_md_hd_t *md, guchar *data, gint len) {
    gcry_md_write(*(md), data, len);
}

void ssl_md_final(gcry_md_hd_t *md, guchar *data, guint *datalen) {
    gint algo;
    gint len;
    algo = gcry_md_get_algo (*(md));
    len = gcry_md_get_algo_dlen (algo);
    memcpy(data, gcry_md_read(*(md),  algo), len);
    *datalen = len;
}

void ssl_md_cleanup(gcry_md_hd_t *md) {
    gcry_md_close(*(md));
}

void ssl_md_reset(gcry_md_hd_t *md) {
    gcry_md_reset(*md);
}

void ssl_sha_init(gcry_md_hd_t *md) {
    gcry_md_open(md,GCRY_MD_SHA1, 0);
}

void ssl_sha_update(gcry_md_hd_t *md, guchar *data, gint len) {
    gcry_md_write(*(md), data, len);
}

void ssl_sha_final(guchar *buf, gcry_md_hd_t *md) {
    memcpy(buf, gcry_md_read(*(md),  GCRY_MD_SHA1),
           gcry_md_get_algo_dlen(GCRY_MD_SHA1));
}

void ssl_sha_reset(gcry_md_hd_t *md) {
    gcry_md_reset(*md);
}

void ssl_sha_cleanup(gcry_md_hd_t *md) {
    gcry_md_close(*(md));
}

gint ssl_md5_init(gcry_md_hd_t *md) {
    return gcry_md_open(md,GCRY_MD_MD5, 0);
}

void ssl_md5_update(gcry_md_hd_t *md, guchar *data, gint len) {
    gcry_md_write(*(md), data, len);
}

void ssl_md5_final(guchar *buf, gcry_md_hd_t *md) {
    memcpy(buf, gcry_md_read(*(md),  GCRY_MD_MD5),
           gcry_md_get_algo_dlen(GCRY_MD_MD5));
}

void ssl_md5_reset(gcry_md_hd_t *md) {
    gcry_md_reset(*md);
}

void ssl_md5_cleanup(gcry_md_hd_t *md) {
    gcry_md_close(*(md));
}

gint ssl_cipher_setiv(gcry_cipher_hd_t *cipher, guchar *iv, gint iv_len) {
    gint ret;
#if 0
    guchar *ivp;
    gint i;
    gcry_cipher_hd_t c;
    c=(gcry_cipher_hd_t)*cipher;
#endif
    ssl_debug_printf("--------------------------------------------------------------------");
#if 0
    for(ivp=c->iv,i=0; i < iv_len; i++ )
        {
        ssl_debug_printf("%d ",ivp[i]);
        i++;
        }
#endif
    ssl_debug_printf("--------------------------------------------------------------------");
    ret = gcry_cipher_setiv(*(cipher), iv, iv_len);
#if 0
    for(ivp=c->iv,i=0; i < iv_len; i++ )
        {
        ssl_debug_printf("%d ",ivp[i]);
        i++;
        }
#endif
    ssl_debug_printf("--------------------------------------------------------------------");
    return ret;
}

gint ssl_cipher_init(gcry_cipher_hd_t *cipher, gint algo, guchar *sk, guchar *iv, gint mode) {
    gint gcry_modes[] = {
            GCRY_CIPHER_MODE_STREAM,
            GCRY_CIPHER_MODE_CBC,
#ifdef HAVE_LIBGCRYPT_AEAD
            GCRY_CIPHER_MODE_GCM,
            GCRY_CIPHER_MODE_CCM,
            GCRY_CIPHER_MODE_CCM,
#else
            GCRY_CIPHER_MODE_CTR,
            GCRY_CIPHER_MODE_CTR,
            GCRY_CIPHER_MODE_CTR,
#endif
#ifdef HAVE_LIBGCRYPT_CHACHA20_POLY1305
            GCRY_CIPHER_MODE_POLY1305,
#else
            -1,                         /* AEAD_CHACHA20_POLY1305 is unsupported. */
#endif
    };
    gint err;
    if (algo == -1) {
        /* NULL mode */
        *(cipher) = (gcry_cipher_hd_t)-1;
        return 0;
    }
    err = gcry_cipher_open(cipher, algo, gcry_modes[mode], 0);
    if (err !=0)
        return  -1;
    err = gcry_cipher_setkey(*(cipher), sk, gcry_cipher_get_algo_keylen (algo));
    if (err != 0)
        return -1;
    /* AEAD cipher suites will set the nonce later. */
    if (mode == MODE_CBC) {
        err = gcry_cipher_setiv(*(cipher), iv, gcry_cipher_get_algo_blklen(algo));
        if (err != 0)
            return -1;
    }
    return 0;
}

gint ssl_cipher_decrypt(gcry_cipher_hd_t *cipher, guchar *out, gint outl, const guchar *in, gint inl) {
    if ((*cipher) == (gcry_cipher_hd_t)-1)
    {
        if (in && inl)
            memcpy(out, in, outl < inl ? outl : inl);
        return 0;
    }
    return gcry_cipher_decrypt ( *(cipher), out, outl, in, inl);
}

gint ssl_get_digest_by_name(const gchar *name) {
    return gcry_md_map_name(name);
}

gint ssl_get_cipher_by_name(const gchar *name) {
    return gcry_cipher_map_name(name);
}

void ssl_cipher_cleanup(gcry_cipher_hd_t *cipher) {
    if ((*cipher) != (gcry_cipher_hd_t)-1)
        gcry_cipher_close(*cipher);
    *cipher = NULL;
}
