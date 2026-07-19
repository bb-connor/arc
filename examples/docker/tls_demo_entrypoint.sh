#!/bin/sh
set -eu

mode="${CHIO_TLS_MODE:-serve}"
ca_dir=/var/lib/chio-tls-ca
server_dir=/var/lib/chio-tls-private
public_dir=/var/lib/chio-tls-public
ca_key="${ca_dir}/demo-ca-key.pem"
ca_cert="${public_dir}/demo-ca.pem"
server_key="${server_dir}/demo-server-key.pem"
server_cert="${server_dir}/demo-server.pem"

directory_is_empty() {
  first_entry="$(find "$1" -mindepth 1 -maxdepth 1 -print -quit)" || return 1
  [ -z "${first_entry}" ] || return 1
}

require_directory() {
  path=$1
  owner=$2
  mode_bits=$3
  [ -d "${path}" ] || return 1
  [ ! -L "${path}" ] || return 1
  [ "$(stat -c '%u:%g:%a' "${path}")" = "${owner}:${mode_bits}" ] || return 1
}

require_file() {
  path=$1
  owner=$2
  mode_bits=$3
  [ -f "${path}" ] || return 1
  [ ! -L "${path}" ] || return 1
  [ "$(stat -c '%u:%g:%a' "${path}")" = "${owner}:${mode_bits}" ] || return 1
}

verify_certificate_set() {
  key_owner=$1
  require_file "${ca_cert}" 0:0 444 || return 1
  require_file "${server_cert}" 0:0 444 || return 1
  require_file "${server_key}" "${key_owner}" 400 || return 1
  openssl verify -CAfile "${ca_cert}" "${server_cert}" >/dev/null 2>&1 || return 1
  openssl x509 -checkend 86400 -noout -in "${ca_cert}" >/dev/null 2>&1 || return 1
  openssl x509 -checkend 86400 -noout -in "${server_cert}" >/dev/null 2>&1 || return 1
  [ "$(openssl x509 -noout -modulus -in "${server_cert}" 2>/dev/null)" = \
    "$(openssl rsa -noout -modulus -in "${server_key}" 2>/dev/null)" ] || return 1
  san="$(openssl x509 -noout -ext subjectAltName -in "${server_cert}")" || return 1
  printf '%s\n' "${san}" | grep -F 'DNS:chio-trust-tls' >/dev/null || return 1
  printf '%s\n' "${san}" | grep -F 'DNS:localhost' >/dev/null || return 1
  printf '%s\n' "${san}" | grep -F 'IP Address:127.0.0.1' >/dev/null || return 1
  printf '%s\n' "${san}" | grep -F 'IP Address:0:0:0:0:0:0:0:1' >/dev/null || return 1
}

case "${mode}" in
  provision)
    for directory in "${ca_dir}" "${server_dir}" "${public_dir}"; do
      [ -d "${directory}" ] || exit 1
      [ ! -L "${directory}" ] || exit 1
    done
    chown 0:0 "${ca_dir}" "${server_dir}" "${public_dir}"
    chmod 0700 "${ca_dir}" "${server_dir}"
    chmod 0755 "${public_dir}"
    if [ -f "${server_key}" ] && [ ! -L "${server_key}" ]; then
      chown 0:0 "${server_key}"
    fi

    if require_file "${ca_key}" 0:0 400 \
      && verify_certificate_set 0:0 \
      && [ "$(openssl x509 -noout -modulus -in "${ca_cert}" 2>/dev/null)" = \
        "$(openssl rsa -noout -modulus -in "${ca_key}" 2>/dev/null)" ]; then
      chown 10001:10001 "${server_key}" "${server_dir}"
      exit 0
    fi
    if ! directory_is_empty "${ca_dir}" \
      || ! directory_is_empty "${server_dir}" \
      || ! directory_is_empty "${public_dir}"; then
      echo 'TLS state is incomplete or invalid; remove the demo volumes before reprovisioning' >&2
      exit 1
    fi

    work="$(mktemp -d /run/chio-tls-provision.XXXXXX)"
    trap 'rm -rf "${work}"' EXIT HUP INT TERM
    openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 30 \
      -subj '/CN=Chio Docker Demo CA' \
      -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
      -addext 'keyUsage=critical,keyCertSign,cRLSign' \
      -keyout "${work}/ca-key.pem" \
      -out "${work}/ca.pem"
    openssl req -newkey rsa:3072 -nodes -sha256 \
      -subj '/CN=chio-trust-tls' \
      -keyout "${work}/server-key.pem" \
      -out "${work}/server.csr"
    {
      echo 'subjectAltName=DNS:chio-trust-tls,DNS:localhost,IP:127.0.0.1,IP:::1'
      echo 'basicConstraints=critical,CA:FALSE'
      echo 'extendedKeyUsage=serverAuth'
      echo 'keyUsage=critical,digitalSignature,keyEncipherment'
    } > "${work}/extensions.cnf"
    openssl x509 -req \
      -in "${work}/server.csr" \
      -CA "${work}/ca.pem" \
      -CAkey "${work}/ca-key.pem" \
      -CAcreateserial \
      -days 30 \
      -sha256 \
      -extfile "${work}/extensions.cnf" \
      -out "${work}/server.pem"

    cp "${work}/ca-key.pem" "${ca_key}.new"
    cp "${work}/server-key.pem" "${server_key}.new"
    cp "${work}/server.pem" "${server_cert}.new"
    cp "${work}/ca.pem" "${ca_cert}.new"
    chown 0:0 "${ca_key}.new" "${server_key}.new" "${server_cert}.new" "${ca_cert}.new"
    chmod 0400 "${ca_key}.new" "${server_key}.new"
    chmod 0444 "${server_cert}.new" "${ca_cert}.new"
    mv "${ca_key}.new" "${ca_key}"
    mv "${server_key}.new" "${server_key}"
    mv "${server_cert}.new" "${server_cert}"
    mv "${ca_cert}.new" "${ca_cert}"
    require_directory "${ca_dir}" 0:0 700
    require_directory "${server_dir}" 0:0 700
    require_directory "${public_dir}" 0:0 755
    require_file "${ca_key}" 0:0 400
    verify_certificate_set 0:0
    [ "$(openssl x509 -noout -modulus -in "${ca_cert}" 2>/dev/null)" = \
      "$(openssl rsa -noout -modulus -in "${ca_key}" 2>/dev/null)" ]
    chown 10001:10001 "${server_key}" "${server_dir}"
    rm -rf "${work}"
    trap - EXIT HUP INT TERM
    ;;
  serve)
    require_directory "${server_dir}" 10001:10001 700
    require_directory "${public_dir}" 0:0 755
    verify_certificate_set 10001:10001
    if [ -e "${ca_key}" ] || [ -L "${ca_key}" ]; then
      echo 'TLS proxy must not receive the CA signing key' >&2
      exit 1
    fi
    exec python3 /opt/chio/tls_reverse_proxy.py
    ;;
  *)
    echo 'CHIO_TLS_MODE must be provision or serve' >&2
    exit 1
    ;;
esac
