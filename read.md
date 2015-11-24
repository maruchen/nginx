# ssl_st 结构体：
Ssl.h L996



入口1：
ngx_event_openssl.c
ngx_ssl_init(ngx_log_t *log)
    SSL_library_init






入口2：
ngx_event_openssl.c
ngx_ssl_handshake(ngx_connection_t *c)
    n = SSL_do_handshake(c->ssl->connection);  // Ssl_lib.c
        ssl->handshake_func(s) // ssl_connect 或 ssl_accept

### ssl_accept
ssl_accept in <t1_srvr.c>
SSL2,3
    ssl23_accept
TLS1.0
    ssl3_accept
TLS1.1
    ssl3_accept
TLS1.2
    ssl3_accept

#### ssl3_accept
ssl3_accept in <S3_srvr.c> 状态机

    ssl3_get_client_hello(SSL *s)

    ssl3_send_server_hello(SSL *s)
        组装ServerHello包，并调用ssl3_handshake_write()写数据

    SSL3_ST_SW_SESSION_TICKET_A
        ssl3_send_newsession_ticket()
        转到 SSL3_ST_SW_CHANGE_A

    SSL3_ST_SW_CHANGE_A
        s->method->ssl3_enc->setup_key_block(s)
        ssl3_send_change_cipher_spec()

    SSL3_ST_SW_FINISHED_A


ssl3_send_newsession_ticket

SSL3_ENC_METHOD TLSv1_2_enc_data = {
	.enc = tls1_enc,
	.mac = tls1_mac,
	.setup_key_block = tls1_setup_key_block,
	.generate_master_secret = tls1_generate_master_secret,
	.change_cipher_state = tls1_change_cipher_state,
	.final_finish_mac = tls1_final_finish_mac,
	.finish_mac_length = TLS1_FINISH_MAC_LENGTH,
	.cert_verify_mac = tls1_cert_verify_mac,
	.client_finished_label = TLS_MD_CLIENT_FINISH_CONST,
	.client_finished_label_len = TLS_MD_CLIENT_FINISH_CONST_SIZE,
	.server_finished_label = TLS_MD_SERVER_FINISH_CONST,
	.server_finished_label_len = TLS_MD_SERVER_FINISH_CONST_SIZE,
	.alert_value = tls1_alert_code,
	.export_keying_material = tls1_export_keying_material,
	.enc_flags = SSL_ENC_FLAG_EXPLICIT_IV|SSL_ENC_FLAG_SIGALGS|
	    SSL_ENC_FLAG_SHA256_PRF|SSL_ENC_FLAG_TLS1_2_CIPHERS,
};

const SSL_METHOD TLSv1_2_server_method_data = {
	.version = TLS1_2_VERSION,
	.ssl_new = tls1_new,
	.ssl_clear = tls1_clear,
	.ssl_free = tls1_free,
	.ssl_accept = ssl3_accept,
	.ssl_connect = ssl_undefined_function,
	.ssl_read = ssl3_read,
	.ssl_peek = ssl3_peek,
	.ssl_write = ssl3_write,
	.ssl_shutdown = ssl3_shutdown,
	.ssl_renegotiate = ssl3_renegotiate,
	.ssl_renegotiate_check = ssl3_renegotiate_check,
	.ssl_get_message = ssl3_get_message,
	.ssl_read_bytes = ssl3_read_bytes,
	.ssl_write_bytes = ssl3_write_bytes,
	.ssl_dispatch_alert = ssl3_dispatch_alert,
	.ssl_ctrl = ssl3_ctrl,
	.ssl_ctx_ctrl = ssl3_ctx_ctrl,
	.get_cipher_by_char = ssl3_get_cipher_by_char,
	.put_cipher_by_char = ssl3_put_cipher_by_char,
	.ssl_pending = ssl3_pending,
	.num_ciphers = ssl3_num_ciphers,
	.get_cipher = ssl3_get_cipher,
	.get_ssl_method = tls1_get_server_method,
	.get_timeout = tls1_default_timeout,
	.ssl3_enc = &TLSv1_2_enc_data,
	.ssl_version = ssl_undefined_void_function,
	.ssl_callback_ctrl = ssl3_callback_ctrl,
	.ssl_ctx_callback_ctrl = ssl3_ctx_callback_ctrl,
};



第一个RTT中，server发出Server Key Exchange。包含ECDH的参数：曲线、公钥（65字节）、签名（256字节）


