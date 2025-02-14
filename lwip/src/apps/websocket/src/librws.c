/*
 *   Copyright (c) 2014 - 2019 Oleh Kulykov <info@resident.name>
 *
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *   THE SOFTWARE.
 */


#include "librws.h"

#ifdef CONFIG_SYSCALL
const unsigned long SWIHandler_entity_WEBSOCKET[] =
{
    (const unsigned long) rws_socket_create,
    (const unsigned long) rws_socket_set_url,
    (const unsigned long) rws_socket_set_scheme,
    (const unsigned long) rws_socket_get_scheme,
    (const unsigned long) rws_socket_set_host,
    (const unsigned long) rws_socket_get_host,
    (const unsigned long) rws_socket_set_port,
    (const unsigned long) rws_socket_get_port,
    (const unsigned long) rws_socket_set_path,
    (const unsigned long) rws_socket_get_path,
    (const unsigned long) rws_socket_set_server_cert,
    (const unsigned long) rws_socket_get_error,
    (const unsigned long) rws_socket_connect,
    (const unsigned long) rws_socket_disconnect_and_release,
    (const unsigned long) rws_socket_is_connected,
    (const unsigned long) rws_socket_send_text,
    (const unsigned long) rws_socket_set_user_object,
    (const unsigned long) rws_socket_get_user_object,
    (const unsigned long) rws_socket_set_on_connected,
    (const unsigned long) rws_socket_set_on_disconnected,
    (const unsigned long) rws_socket_set_on_received_text,
    (const unsigned long) rws_socket_set_on_received_bin,
    (const unsigned long) rws_socket_set_on_received_pong,
    (const unsigned long) rws_socket_send_bin_start,
    (const unsigned long) rws_socket_send_bin_continue,
    (const unsigned long) rws_socket_send_bin_finish,
    (const unsigned long) rws_error_get_code,
    (const unsigned long) rws_error_get_http_error,
    (const unsigned long) rws_error_get_description,
    (const unsigned long) rws_mutex_create_recursive,
    (const unsigned long) rws_mutex_lock,
    (const unsigned long) rws_mutex_unlock,
    (const unsigned long) rws_thread_create,
    (const unsigned long) rws_thread_sleep,
};

#endif
