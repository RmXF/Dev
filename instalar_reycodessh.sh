#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# -----------------------
# Instalador ReycodeSSH
# -----------------------
# Reemplazar PANEL_ZIP_URL por la URL directa del zip del panel (dl=1 o link directo)
PANEL_ZIP_URL="https://github.com/RmXF/Dev/blob/main/panel_web_basic.zip"

# Directorio de instalación
PANEL_DIR="/var/www/reycodessh"
APACHE_CONF="/etc/apache2/sites-available/reycodessh.conf"
APACHE_SSL_CONF="/etc/apache2/sites-available/reycodessh-ssl.conf"
SSL_DIR="/etc/ssl/reycodessh"

# Helpers
echog() { printf "\e[32m%s\e[0m\n" "$*"; }
echoe() { printf "\e[31m%s\e[0m\n" "$*"; }
echob() { printf "\e[33m%s\e[0m\n" "$*"; }

require_root(){
  if [ "$EUID" -ne 0 ]; then
    echoe "Este script debe ejecutarse como root. Usá sudo."
    exit 1
  fi
}

detect_os(){
  if [ -f /etc/debian_version ]; then
    OS="debian"
  else
    echoe "Sistema no reconocido (solo Debian/Ubuntu soportado)."
    exit 1
  fi
}

install_packages(){
  echog "Actualizando repositorios e instalando paquetes necesarios..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null
  apt-get install -y apache2 php php-sqlite3 unzip wget openssl >/dev/null
}

ask_credentials(){
  read -p "Usuario admin para el panel [admin]: " PANEL_USER
  PANEL_USER=${PANEL_USER:-admin}
  read -s -p "Contraseña admin [admin123]: " PANEL_PASS
  echo
  PANEL_PASS=${PANEL_PASS:-admin123}
  echog "Usuario: $PANEL_USER"
}

create_dirs(){
  echog "Creando directorios..."
  mkdir -p "$PANEL_DIR"
  mkdir -p "$SSL_DIR"
  chown -R www-data:www-data "$PANEL_DIR"
}

download_and_extract(){
  echog "Descargando panel desde: $PANEL_ZIP_URL"
  TMPZIP=$(mktemp --suffix=.zip)
  if ! wget -q -O "$TMPZIP" "$PANEL_ZIP_URL"; then
    echoe "Error: no se pudo descargar $PANEL_ZIP_URL"
    rm -f "$TMPZIP"
    exit 1
  fi
  echog "Extrayendo archivos..."
  unzip -o "$TMPZIP" -d "$PANEL_DIR" >/dev/null 2>&1 || true
  rm -f "$TMPZIP"
  # Ensure index exists (fallback)
  if [ ! -f "$PANEL_DIR/index.php" ]; then
    echob "No se encontró index.php dentro del ZIP. Se crea una página índice básica."
    cat > "$PANEL_DIR/index.php" <<'EOF'
<?php echo "<h1>ReycodeSSH instalado. Reemplaza los archivos del panel.</h1>"; ?>
EOF
  fi
  chown -R www-data:www-data "$PANEL_DIR"
}

write_config(){
  # If a config.php already exists, attempt to replace the default credentials.
  CFG="$PANEL_DIR/config.php"
  if [ -f "$CFG" ]; then
    echog "Actualizando credenciales en config.php..."
    # Attempt to replace admin_user and admin_pass patterns
    sed -i "s/'admin_user' *= *'[^']*'/'admin_user' => '${PANEL_USER}'/g" "$CFG" 2>/dev/null || true
    sed -i "s/'admin_pass' *= *'[^']*'/'admin_pass' => '${PANEL_PASS}'/g" "$CFG" 2>/dev/null || true
  else
    echog "Creando config.php básico..."
    cat > "$CFG" <<EOF
<?php
return [
  'admin_user' => '${PANEL_USER}',
  'admin_pass' => '${PANEL_PASS}',
  'theme'      => 'dark',
  'lang'       => 'es',
  'db_path'    => __DIR__ . '/data/tokens.db',
  'vps_db'     => __DIR__ . '/data/vps.db',
];
EOF
    chown www-data:www-data "$CFG"
    chmod 640 "$CFG"
  fi
}

generate_selfsigned_cert(){
  IPADDR=$(hostname -I | awk '{print $1}')
  if [ -z "$IPADDR" ]; then
    IPADDR="127.0.0.1"
  fi
  echog "Generando certificado SSL autofirmado para la IP: $IPADDR"
  # Create openssl config with SAN for IP
  OPENSSL_CFG=$(mktemp)
  cat > "$OPENSSL_CFG" <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
C = AR
ST = SomeState
L = SomeCity
O = ReycodeSSH
CN = $IPADDR

[v3_req]
subjectAltName = @alt_names

[alt_names]
IP.1 = $IPADDR
EOF

  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "$SSL_DIR/reycodessh.key" -out "$SSL_DIR/reycodessh.crt" \
    -config "$OPENSSL_CFG" >/dev/null 2>&1

  rm -f "$OPENSSL_CFG"
  chmod 600 "$SSL_DIR/reycodessh.key"
  chmod 644 "$SSL_DIR/reycodessh.crt"
  echog "Certificado creado en $SSL_DIR"
}

configure_apache(){
  local port_https=443
  echog "Configurando Apache (vhost HTTPS + redirección HTTP->HTTPS)..."

  # SSL VirtualHost
  cat > "$APACHE_SSL_CONF" <<EOF
<IfModule mod_ssl.c>
<VirtualHost *:${port_https}>
    ServerAdmin webmaster@localhost
    DocumentRoot ${PANEL_DIR}
    <Directory ${PANEL_DIR}>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    SSLEngine on
    SSLCertificateFile ${SSL_DIR}/reycodessh.crt
    SSLCertificateKeyFile ${SSL_DIR}/reycodessh.key

    ErrorLog \${APACHE_LOG_DIR}/reycodessh_ssl_error.log
    CustomLog \${APACHE_LOG_DIR}/reycodessh_ssl_access.log combined
</VirtualHost>
</IfModule>
EOF

  # HTTP vhost which redirects to https
  cat > "$APACHE_CONF" <<EOF
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot ${PANEL_DIR}
    <Directory ${PANEL_DIR}>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    # Redirect all HTTP traffic to HTTPS
    RewriteEngine On
    RewriteCond %{HTTPS} !=on
    RewriteRule ^/?(.*) https://%{SERVER_ADDR}/$1 [R=301,L]

    ErrorLog \${APACHE_LOG_DIR}/reycodessh_error.log
    CustomLog \${APACHE_LOG_DIR}/reycodessh_access.log combined
</VirtualHost>
EOF

  a2enmod ssl >/dev/null 2>&1 || true
  a2enmod rewrite >/dev/null 2>&1 || true
  a2ensite reycodessh-ssl.conf >/dev/null 2>&1 || true
  a2ensite reycodessh.conf >/dev/null 2>&1 || true
  a2dissite 000-default.conf >/dev/null 2>&1 || true

  systemctl reload apache2 || systemctl restart apache2
}

open_firewall(){
  # Optional: configure basic UFW (if exists)
  if command -v ufw >/dev/null 2>&1; then
    echog "Configurando UFW: permitiendo 22 (SSH), 80, 443"
    ufw allow 22/tcp >/dev/null 2>&1 || true
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
    # Enable if inactive
    if ufw status | grep -q inactive; then
      echob "Habilitando UFW"
      ufw --force enable >/dev/null 2>&1 || true
    fi
  fi
}

final_info(){
  IPADDR=$(hostname -I | awk '{print $1}')
  IPADDR=${IPADDR:-127.0.0.1}
  echog ""
  echog "==========================================="
  echog "  INSTALACIÓN COMPLETADA - ReycodeSSH"
  echog "==========================================="
  echog "  Acceso HTTPS: https://${IPADDR}/"
  echog "  Usuario: ${PANEL_USER}"
  echog "  Contraseña: ${PANEL_PASS}"
  echog ""
  echob "IMPORTANTE:"
  echob " - El certificado es autofirmado. Para evitar advertencias, usa un dominio y Let's Encrypt."
  echob " - Cambia la contraseña admin desde el panel después del primer acceso."
}

# ----------------------
# Main
# ----------------------
main(){
  require_root
  detect_os
  echob "REYCODESSH - INSTALADOR AUTOMÁTICO (HTTPS)"
  ask_credentials

  install_packages
  create_dirs
  download_and_extract
  write_config
  generate_selfsigned_cert
  configure_apache
  open_firewall
  final_info
}

main "$@"
