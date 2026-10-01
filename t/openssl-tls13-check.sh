#!/bin/sh
set -eu

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/cl-tls-kit-openssl.XXXXXX")
server_pid=
cleanup() {
    if [ -n "${server_pid}" ]; then
        kill "${server_pid}" 2>/dev/null || true
        wait "${server_pid}" 2>/dev/null || true
    fi
    rm -rf "${tmpdir}"
}
trap cleanup EXIT INT TERM

cert="${tmpdir}/server.pem"
key="${tmpdir}/server.key"
port=$((20000 + ($$ % 20000)))

openssl req -x509 -newkey rsa:2048 -nodes \
    -subj /CN=localhost -keyout "${key}" -out "${cert}" -days 1 >/dev/null 2>&1

start_server() {
    suite=$1
    groups=$2
    "${OPENSSL:-openssl}" s_server -quiet -www -bind 127.0.0.1 -accept "${port}" \
        -tls1_3 -ciphersuites "${suite}" -groups "${groups}" \
        -cert "${cert}" -key "${key}" >"${tmpdir}/server.log" 2>&1 &
    server_pid=$!
    i=0
    while kill -0 "${server_pid}" 2>/dev/null; do
        i=$((i + 1))
        [ "${i}" -lt 50 ] || break
        sleep 0.1
    done
    kill -0 "${server_pid}" 2>/dev/null || {
        cat "${tmpdir}/server.log" >&2
        return 1
    }
}

stop_server() {
    kill "${server_pid}" 2>/dev/null || true
    wait "${server_pid}" 2>/dev/null || true
    server_pid=
}

run_client() {
    suite=$1
    groups=$2
    output=$("${OPENSSL:-openssl}" s_client -brief -connect "127.0.0.1:${port}" \
        -tls1_3 -ciphersuites "${suite}" -groups "${groups}" \
        -CAfile "${cert}" -verify_return_error </dev/null 2>&1) || {
        printf '%s\n' "${output}" >&2
        return 1
    }
    printf '%s\n' "${output}" | grep -Fq 'Protocol version: TLSv1.3'
    printf '%s\n' "${output}" | grep -Fq "Ciphersuite: ${suite}"
    case "${groups}" in
        X25519) printf '%s\n' "${output}" | grep -Eiq 'x25519' ;;
        P-256) printf '%s\n' "${output}" | grep -Eiq 'P-256|prime256v1' ;;
    esac
}

run_suite_group() {
    suite=$1
    group=$2
    printf 'condition suite=%s group=%s\n' "${suite}" "${group}"
    start_server "${suite}" "${group}"
    run_client "${suite}" "${group}"
    stop_server
}

for suite in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256; do
    run_suite_group "${suite}" X25519
    run_suite_group "${suite}" P-256
done

printf '%s\n' 'condition hello-retry-request'
start_server TLS_AES_128_GCM_SHA256 P-256
hrr_output=$("${OPENSSL:-openssl}" s_client -trace -brief -connect "127.0.0.1:${port}" \
    -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -groups X25519:P-256 \
    -CAfile "${cert}" -verify_return_error </dev/null 2>&1) || {
    printf '%s\n' "${hrr_output}" >&2
    exit 1
}
printf '%s\n' "${hrr_output}" | grep -Eiq 'HelloRetryRequest'
stop_server

printf '%s\n' 'condition invalid-certificate'
start_server TLS_AES_128_GCM_SHA256 X25519
if invalid_output=$("${OPENSSL:-openssl}" s_client -brief -connect "127.0.0.1:${port}" \
    -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -groups X25519 \
    -no-CAfile -no-CApath -verify_return_error </dev/null 2>&1); then
    printf '%s\n' "${invalid_output}" >&2
    exit 1
fi
printf '%s\n' "${invalid_output}" | grep -Eiq 'verify|certificate|issuer'
stop_server

printf '%s\n' 'OpenSSL TLS 1.3 conditions: PASS'
