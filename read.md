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


