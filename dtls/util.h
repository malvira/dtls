/*
 * DTLS implementation for Contiki OS
 * Copyright (c) 2012, Vladislav Perelman <vladislav.perelman@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#ifndef __UTIL_H__
#define __UTIL_H__

#include <contiki.h>
int PRF(char* output, char* secret, int secret_length, char* label, char* seed,int seed_length, int size);
void create_hello_request(char* buffer, unsigned long long int seq_num, uint16_t epoch);
void create_first_server_hello(char* buffer,unsigned long long int seq_num, uint16_t epoch, uint16_t msn);
void create_next_server_hello(char* buffer, char* random, unsigned long long int seq_num, uint16_t epoch, uint16_t msn);
void create_helloverify_request(char* buffer, unsigned char* cookie, unsigned long long int seq_num, uint16_t epoch, uint16_t msn);
void create_first_client_hello(char* buffer, unsigned long long seq_num, uint16_t epoch, uint16_t msn);
void create_second_client_hello(char* buffer, char* random, char* cookie, uint8_t cookie_len, unsigned long long int seq_num, uint16_t epoch, uint16_t msn);
void create_client_key_exchange(char* buffer, char* psk_identity, uint16_t psk_identity_length, unsigned long long int seq_num, uint16_t epoch, uint16_t msn);
void create_change_cipher_spec(char* buffer, unsigned long long int seq_num, uint16_t epoch);
void create_finished(char* buffer, unsigned long long int seq_num, uint16_t epoch);
void create_application_data(char* buffer, uint16_t length, unsigned long long int seq_num, uint16_t epoch);
void create_alert(char* buffer, unsigned long long int seq_num, uint16_t epoch, uint8_t level, uint8_t type);

#endif
