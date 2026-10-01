#!/usr/bin/env bash
# CEOSSH 2.0.3 — instalador completo para VPS Debian/Ubuntu.
# Panel: https://github.com/RmXF/Dev/blob/main/CEOSSH_2.0_completo.zip
# Incluye actualizador, diagnóstico y comando ceo, en este único archivo.
set -Eeuo pipefail
umask 077
export TZ="${TZ:-America/Argentina/Buenos_Aires}"
REPO_ZIP_URL='https://raw.githubusercontent.com/RmXF/Dev/main/CEOSSH_2.0_completo.zip'
EXPECTED_SHA256='cdf9e0079b00ae5744ba8a8b67b8623a34a0922dfc373f2bbc7d8b9168215e99'
MODE=--install
LOCAL_ZIP=''
while [[ $# -gt 0 ]];do
 case "$1" in
  --install|--update|--auto|--check) MODE=$1;shift ;;
  --zip) [[ $# -ge 2 ]] || { echo 'Falta la ruta después de --zip';exit 1; };LOCAL_ZIP=$2;shift 2 ;;
  --help)
   printf '%s\n' 'CEOSSH 2.0.3 — Instalación desde GitHub' \
    'sudo bash install_ceossh.sh --install       VPS limpia' \
    'sudo bash install_ceossh.sh --update        Respaldo y actualización' \
    'bash install_ceossh.sh --check              Descargar/verificar sin instalar' \
    'bash install_ceossh.sh --check --zip ARCHIVO.zip  Verificar copia local' \
    'Instalación: Debian/Ubuntu con systemd y PHP >=8.1 en sus repositorios.' \
    'Pedirá administrador, contraseña y puerto HTTP (8088 por defecto).'
   exit 0 ;;
  *) echo "Opción desconocida: $1; usá --help";exit 1 ;;
 esac
done
LOG_FILE=''
if [[ "$MODE" != --check ]];then
 [[ $(id -u) == 0 ]] || { echo 'Ejecutá con sudo bash install_ceossh.sh --install';exit 1; }
 [[ -f /etc/os-release ]] || { echo 'No se detectó el sistema operativo';exit 1; }
 . /etc/os-release
 [[ "$ID" == ubuntu || "$ID" == debian ]] || { echo 'El instalador automático requiere Debian/Ubuntu';exit 1; }
 [[ -d /run/systemd/system ]] || { echo 'Se necesita un VPS con systemd activo';exit 1; }
 [[ ! -L /opt/ceossh ]] || { echo '/opt/ceossh no debe ser un enlace simbólico';exit 1; }
 if [[ "$MODE" == --install && ( -e /opt/ceossh/config/config.php || -e /opt/ceossh/app ) ]];then
  echo 'Ya existe un panel; usá --update. No se reemplazó nada.';exit 1
 fi
 if [[ "$MODE" == --update && ! -f /opt/ceossh/config/config.php ]];then
  echo 'No hay configuración para actualizar; usá --install';exit 1
 fi
 LOG_FILE=/var/log/ceossh-install.log
 touch "$LOG_FILE";chmod 0600 "$LOG_FILE"
fi
log() {
 local level=$1;shift;local stamp color='' reset=''
 stamp=$(date +%H:%M:%S)
 if [[ -t 1 ]];then
  case "$level" in OK) color=$'\033[32m';;ERROR) color=$'\033[31m';;*) color=$'\033[36m';;esac
  reset=$'\033[0m'
 fi
 printf '%s[%s] [%s] %s%s\n' "$color" "$stamp" "$level" "$*" "$reset"
 if [[ -n "$LOG_FILE" ]];then printf '[%s] [%s] %s\n' "$stamp" "$level" "$*" >> "$LOG_FILE";fi
}
WORK=''
cleanup() {
 local result=$?
 trap - EXIT
 if [[ -n "$WORK" ]] && command -v python3 >/dev/null;then
  python3 - "$WORK" <<'PYCLEAN'
import shutil,sys
shutil.rmtree(sys.argv[1],ignore_errors=True)
PYCLEAN
 fi
 exit "$result"
}
trap cleanup EXIT
trap 'result=$?;log ERROR "Instalador detenido en línea $LINENO (código $result). Revisá el mensaje anterior y /var/log/ceossh-install.log.";exit "$result"' ERR
log INFO 'CEOSSH 2.0.3 — descarga verificada y despliegue completo'
if [[ "$MODE" != --check ]];then
 if ! command -v python3 >/dev/null || ! command -v curl >/dev/null || [[ ! -f /etc/ssl/certs/ca-certificates.crt ]];then
  log INFO 'Preparando herramientas de descarga'
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl python3
 fi
else
 command -v python3 >/dev/null || { log ERROR '--check necesita Python 3; no se instaló nada';exit 1; }
 if [[ -z "$LOCAL_ZIP" ]];then command -v curl >/dev/null || { log ERROR '--check necesita curl para descargar; podés usar --zip';exit 1; };fi
fi
WORK=$(mktemp -d -t ceossh-github.XXXXXXXX)
if [[ -n "$LOCAL_ZIP" ]];then
 [[ -f "$LOCAL_ZIP" ]] || { log ERROR 'No se encontró el ZIP local';exit 1; }
 cp -- "$LOCAL_ZIP" "$WORK/panel.zip"
else
 log INFO "Descargando $REPO_ZIP_URL"
 curl --fail --location --show-error --silent --proto '=https' --proto-redir '=https' \
  --retry 3 --connect-timeout 20 --max-time 180 --max-filesize 33554432 \
  --output "$WORK/panel.zip" "$REPO_ZIP_URL"
fi
python3 - "$WORK/panel.zip" "$WORK" "$EXPECTED_SHA256" <<'PYEXTRACT'
from pathlib import Path,PurePosixPath
import sys,hashlib,zipfile,stat
archive=Path(sys.argv[1]);destination=Path(sys.argv[2]);expected=sys.argv[3]
try:
    if archive.stat().st_size>32*1024*1024: raise ValueError('ZIP mayor al límite permitido')
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=expected:
        raise ValueError('SHA-256 no coincide con el panel revisado. No se instalará; revisá si cambió el ZIP del repositorio')
    with zipfile.ZipFile(archive) as z:
        if sum(i.file_size for i in z.infolist())>128*1024*1024: raise ValueError('Contenido descomprimido demasiado grande')
        seen=set()
        for item in z.infolist():
            path=PurePosixPath(item.filename);mode=item.external_attr>>16
            if path.is_absolute() or '..' in path.parts or '\\' in item.filename or not path.parts or path.parts[0]!='ceossh-completo' or stat.S_ISLNK(mode):
                raise ValueError('Ruta insegura dentro del ZIP')
            if item.filename in seen: raise ValueError('Archivo duplicado dentro del ZIP')
            seen.add(item.filename)
        required=['app/bootstrap.php','app/Core.php','app/Operations.php','app/SshManager.php','public/index.php','database/schema.sql','scripts/migrate.php','scripts/backup.php','config/config.example.php']
        if not all('ceossh-completo/'+r in seen for r in required): raise ValueError('El paquete está incompleto')
        if 'ceossh-completo/config/config.php' in seen or 'ceossh-completo/config/secret.key' in seen:
            raise ValueError('El paquete contiene configuración privada')
        z.extractall(destination)
except Exception as error:
    print('Validación falló: '+str(error),file=sys.stderr);sys.exit(1)
print('Integridad SHA-256, estructura y extracción del ZIP: OK')
PYEXTRACT
PACKAGE="$WORK/ceossh-completo"
# Complementos revisados: se aplican únicamente dentro del paquete temporal.
cat > "$PACKAGE/app/bootstrap.php" <<'CEOSSH_FILE_1_END'
<?php
declare(strict_types=1);
define('CEOSSH_ROOT', dirname(__DIR__));
if (PHP_SAPI !== 'cli' && is_file(CEOSSH_ROOT . '/storage/maintenance')) {
    http_response_code(503); header('Retry-After: 120'); exit('CEOSSH en mantenimiento. Intentá nuevamente en unos minutos.');
}
if (!is_file(CEOSSH_ROOT . '/config/config.php')) {
    http_response_code(503); exit('CEOSSH necesita configuración. Ejecutá install.sh o seguí docs/INSTALL.md.');
}
require_once CEOSSH_ROOT . '/config/config.php';
define('CEOSSH_PREVIOUS_TIMEZONE', date_default_timezone_get());
date_default_timezone_set(defined('APP_TIMEZONE') ? APP_TIMEZONE : 'America/Argentina/Buenos_Aires');
require_once __DIR__ . '/Core.php';
require_once __DIR__ . '/SshManager.php';
require_once __DIR__ . '/Operations.php';
if (PHP_SAPI !== 'cli') {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: same-origin');
    header('Cache-Control: no-store');
    session_name('ceossh_sess');
    session_set_cookie_params(['httponly'=>true,'secure'=>!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off','samesite'=>'Strict','path'=>'/']);
    ini_set('session.use_strict_mode', '1');
    session_start();
    if (!isset($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    if (!empty($_SESSION['admin']) && time() - (int)($_SESSION['seen'] ?? time()) > 1800) {
        session_unset(); $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    if (!empty($_SESSION['admin'])) $_SESSION['seen'] = time();
}
CEOSSH_FILE_1_END
cat > "$PACKAGE/install.sh" <<'CEOSSH_FILE_2_END'
#!/usr/bin/env bash
# CEOSSH 2.0.3 — instalador del paquete. No descarga ni genera clases antiguas.
set -Eeuo pipefail
umask 027
SOURCE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
TARGET=/opt/ceossh
[[ $# -le 1 ]] || { echo 'Usá --help para ver las opciones';exit 1; }
MODE=${1:---auto}
case "$MODE" in
 --auto) [[ -f "$TARGET/config/config.php" ]] && MODE=--update || MODE=--install ;;
 --install|--update|--check) ;;
 --help) printf '%s\n' 'Uso: sudo bash install.sh [--install | --update | --check]' 'Sin opción detecta una instalación existente. --check no instala nada.';exit 0 ;;
 *) echo 'Opción inválida. Usá --help';exit 1 ;;
esac
[[ -f "$SOURCE/app/Operations.php" && -f "$SOURCE/scripts/migrate.php" && -f "$SOURCE/scripts/ceo.php" ]] || { echo 'Paquete CEOSSH incompleto';exit 1; }
if [[ "$MODE" == --check ]];then
 bash -n "$SOURCE/install.sh"
 for file in "$SOURCE"/scripts/*.sh;do bash -n "$file";done
 if command -v php >/dev/null;then find "$SOURCE/app" "$SOURCE/scripts" "$SOURCE/public" -name '*.php' -print0 | while IFS= read -r -d '' file;do php -l "$file" >/dev/null;done;else echo 'PHP no disponible: su comprobación de sintaxis queda pendiente.';fi
 echo 'Paquete y sintaxis comprobados; no se modificó el servidor.';exit 0
fi
[[ $(id -u) == 0 ]] || { echo 'Ejecutá con sudo bash install.sh';exit 1; }
[[ ! -L "$TARGET" && ! -L "$TARGET/config" && ! -L "$TARGET/storage" ]] || { echo 'Ruta de instalación inesperada: hay enlaces simbólicos. Revisá antes de continuar.';exit 1; }
[[ "$SOURCE" != "$TARGET" && "$SOURCE" != "$TARGET/"* ]] || { echo 'Ejecutá desde /root, fuera de /opt/ceossh';exit 1; }
. /etc/os-release
[[ "$ID" == ubuntu || "$ID" == debian ]] || { echo 'Esta versión automática requiere Debian/Ubuntu con PHP >=8.1';exit 1; }
command -v systemctl >/dev/null && [[ -d /run/systemd/system ]] || { echo 'Se necesita un servidor con systemd activo';exit 1; }
exec 8>/run/ceossh-install.lock
flock -n 8 || { echo 'Ya hay otro instalador CEOSSH activo';exit 1; }
HAS_COLOR=0;[[ -t 1 ]] && HAS_COLOR=1
LOG=/var/log/ceossh-install.log
touch "$LOG";chmod 0600 "$LOG"
exec > >(tee -a "$LOG") 2>&1
log() { local level=$1;shift;local color='';if [[ "$HAS_COLOR" == 1 ]];then case "$level" in OK) color=$'\033[32m';;ERROR) color=$'\033[31m';;WARN) color=$'\033[33m';;*) color=$'\033[36m';;esac;fi;local reset='';[[ -n "$color" ]] && reset=$'\033[0m';printf '%s[%s] [%s] %s%s\n' "$color" "$(date +%H:%M:%S)" "$level" "$*" "$reset"; }
ask_admin() {
 # LC_ALL=C hace que la longitud en Bash coincida con strlen() de PHP (bytes).
 local LC_ALL=C confirmation password_bytes
 log INFO 'Usuario: 3–64 letras A–Z, números o guion bajo. Contraseña: 12–128 bytes.'
 while true;do
  if ! IFS= read -r -p 'Administrador [admin]: ' CEOSSH_ADMIN_NAME;then
   log ERROR 'Entrada interrumpida; no se creó el administrador';return 1
  fi
  CEOSSH_ADMIN_NAME=${CEOSSH_ADMIN_NAME:-admin}
  if [[ "$CEOSSH_ADMIN_NAME" =~ ^[a-zA-Z0-9_]{3,64}$ ]];then break;fi
  log WARN 'Usuario inválido: usá 3–64 letras, números o guion bajo, sin espacios ni acentos.'
 done
 while true;do
  if ! IFS= read -r -s -p 'Contraseña administrador (12–128 bytes): ' CEOSSH_ADMIN_PASSWORD;then
   printf '\n';unset CEOSSH_ADMIN_PASSWORD;log ERROR 'Entrada interrumpida';return 1
  fi
  printf '\n'
  password_bytes=${#CEOSSH_ADMIN_PASSWORD}
  if [[ "$password_bytes" -lt 12 || "$password_bytes" -gt 128 ]];then
   unset CEOSSH_ADMIN_PASSWORD
   log WARN 'La contraseña debe tener entre 12 y 128 bytes. Probá nuevamente.'
   continue
  fi
  if ! IFS= read -r -s -p 'Repetir contraseña: ' confirmation;then
   printf '\n';unset CEOSSH_ADMIN_PASSWORD confirmation;log ERROR 'Entrada interrumpida';return 1
  fi
  printf '\n'
  if [[ "$CEOSSH_ADMIN_PASSWORD" != "$confirmation" ]];then
   unset CEOSSH_ADMIN_PASSWORD confirmation
   log WARN 'Las contraseñas no coinciden. Ingresalas nuevamente.'
   continue
  fi
  unset confirmation
  log OK 'Usuario y contraseña validados'
  break
 done
}
BACKUP=''
trap 'code=$?;log ERROR "Proceso detenido en línea $LINENO (código $code). Respaldo: ${BACKUP:-todavía no creado}. Revisá $LOG. No se realizó una restauración automática.";exit "$code"' ERR
log INFO "CEOSSH 2.0.3: $MODE — $PRETTY_NAME"
if [[ "$MODE" == --update ]];then
 [[ -f "$TARGET/config/config.php" ]] || { log ERROR 'No existe configuración; usá --install';exit 1; }
else
 [[ ! -e "$TARGET/config/config.php" && ! -e "$TARGET/app" ]] || { log ERROR 'Instalación existente/incompleta: revisala y usá --update';exit 1; }
 ask_admin
 read -r -p 'Puerto HTTP dedicado [8088]: ' PANEL_PORT;PANEL_PORT=${PANEL_PORT:-8088}
 [[ "$PANEL_PORT" =~ ^[0-9]{1,5}$ ]] || { log ERROR 'Puerto inválido';exit 1; }
 PANEL_PORT=$((10#$PANEL_PORT))
 [[ "$PANEL_PORT" -ge 1024 && "$PANEL_PORT" -le 65535 ]] || { log ERROR 'Puerto fuera de 1024–65535';exit 1; }
fi
export DEBIAN_FRONTEND=noninteractive
log INFO 'Instalando dependencias; no se reemplaza la configuración global de puertos'
apt-get update
apt-get install -y apache2 libapache2-mod-php php-cli php-mysql php-curl mariadb-client openssh-client sshpass rsync unzip cron openssl util-linux iproute2 python3 curl logrotate
php -r 'if(PHP_VERSION_ID<80100||!extension_loaded("pdo_mysql")||!extension_loaded("openssl")){fwrite(STDERR,"Se requiere PHP >=8.1, PDO MySQL y OpenSSL\n");exit(1);}'
log INFO 'Comprobando la sintaxis PHP del paquete antes de crear o migrar la base'
while IFS= read -r -d '' file;do php -l "$file" >/dev/null;done < <(find "$SOURCE/app" "$SOURCE/scripts" "$SOURCE/public" -name '*.php' -print0)
apache2ctl configtest
BACKUP="/root/ceossh-backups/$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p "$BACKUP";chmod 0700 "$BACKUP"
cp -a /etc/apache2 "$BACKUP/apache2"
crontab -l > "$BACKUP/root.cron" 2>/dev/null || :
for file in /etc/cron.d/ceossh /etc/sudoers.d/ceossh /etc/logrotate.d/ceossh /usr/local/bin/ceo /root/.ceossh-credentials;do
 if [[ -e "$file" || -L "$file" ]];then cp -a --parents "$file" "$BACKUP/";fi
done
# Suspender únicamente tareas conocidas del instalador anterior; no filtrar todo "ceossh".
python3 - "$BACKUP/root.cron" "$BACKUP/root.cron.new" <<'PY'
import pathlib,sys
src=pathlib.Path(sys.argv[1]).read_text().splitlines(True)
known={'/opt/ceossh/scripts/expire_users.sh','/opt/ceossh/scripts/worker.php'}
lines=[]
for line in src:
    tokens=line.split()
    if not line.lstrip().startswith('#') and known.intersection(tokens): continue
    lines.append(line)
pathlib.Path(sys.argv[2]).write_text(''.join(lines))
PY
if ! cmp -s "$BACKUP/root.cron" "$BACKUP/root.cron.new";then crontab "$BACKUP/root.cron.new";log INFO 'Cron antiguo CEOSSH retirado; otros trabajos conservados';fi
if [[ -f /etc/cron.d/ceossh ]];then
 if grep -qE '/opt/ceossh/scripts/(expire_users.sh|worker.php)' /etc/cron.d/ceossh;then
  mv /etc/cron.d/ceossh "$BACKUP/cron-ceossh-retirado"
 else log ERROR 'Cron CEOSSH personalizado no reconocido; revisalo antes de actualizar';exit 1;fi
fi
if [[ "$MODE" == --update ]];then
 mkdir -p "$TARGET/storage"
 exec 9>"$TARGET/storage/worker.lock"
 flock -w 120 9 || { log ERROR 'Worker ocupado; reintentá luego';exit 1; }
 log INFO 'Respaldo obligatorio antes de copiar código o migrar datos'
 CEOSSH_BACKUP_CONFIG="$TARGET/config/config.php" php "$SOURCE/scripts/backup.php" "$BACKUP/database.sql"
 tar -czf "$BACKUP/panel.tar.gz" -C /opt ceossh
 python3 "$SOURCE/scripts/apache-migrate.py" > "$BACKUP/apache-migration.json"
 # Conservar también la copia antigua del frontend cuando se identifica con certeza.
 python3 - "$BACKUP" <<'PY'
import json,sys,pathlib,tarfile
backup=pathlib.Path(sys.argv[1]);roots={x['old_root'] for x in json.loads((backup/'apache-migration.json').read_text())}
for i,root in enumerate(sorted(roots)):
    with tarfile.open(backup/f'legacy-webroot-{i}.tar.gz','w:gz') as archive: archive.add(root,arcname='webroot')
PY
 log OK "Respaldo de archivos, SQL y configuración: $BACKUP"
else
 ss -H -lnt | awk '{print $4}' | grep -qE ":$PANEL_PORT$" && { log ERROR 'Puerto ocupado';exit 1; }
 [[ ! -e /etc/apache2/sites-available/ceossh.conf ]] || { log ERROR 'Ya existe ceossh.conf; revisá su configuración';exit 1; }
 apt-get install -y mariadb-server
 systemctl enable --now mariadb
 mkdir -p "$TARGET/config"
 CEOSSH_DB_PASS=$(openssl rand -hex 24);CEOSSH_DB_NAME="ceossh_$(openssl rand -hex 4)";CEOSSH_DB_USER="ceo_$(openssl rand -hex 4)"
 mysql <<SQL
CREATE DATABASE \`$CEOSSH_DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER '$CEOSSH_DB_USER'@'localhost' IDENTIFIED BY '$CEOSSH_DB_PASS';
GRANT ALL PRIVILEGES ON \`$CEOSSH_DB_NAME\`.* TO '$CEOSSH_DB_USER'@'localhost';
SQL
 CEOSSH_SERVER_IP=$(hostname -I | awk '{print $1}');CEOSSH_SERVER_IP=${CEOSSH_SERVER_IP:-127.0.0.1}
 export CEOSSH_DB_PASS CEOSSH_DB_NAME CEOSSH_DB_USER CEOSSH_SERVER_IP
 php -r '$c="<?php\n";foreach(["DB_HOST"=>"localhost","DB_NAME"=>getenv("CEOSSH_DB_NAME"),"DB_USER"=>getenv("CEOSSH_DB_USER"),"DB_PASS"=>getenv("CEOSSH_DB_PASS"),"APP_TIMEZONE"=>"America/Argentina/Buenos_Aires","LEGACY_DATA_TIMEZONE"=>"UTC","CEOSSH_VERSION"=>"2.0.3","SERVER_IP"=>getenv("CEOSSH_SERVER_IP")] as $k=>$v)$c.="define(".var_export($k,true).", ".var_export($v,true).");\n";file_put_contents("/opt/ceossh/config/config.php",$c);'
 unset CEOSSH_DB_PASS
fi
mkdir -p "$TARGET/storage/logs" "$TARGET/storage/tmp" "$TARGET/storage/cache" "$TARGET/config/ssh"
# Retirar privilegios amplios del archivo exacto creado por el instalador v1.8.
if [[ -f /etc/sudoers.d/ceossh ]];then
 if grep -qE 'www-data.*NOPASSWD:.*useradd' /etc/sudoers.d/ceossh;then
  mv /etc/sudoers.d/ceossh "$BACKUP/ceossh-sudoers-retirado"
  log INFO 'Permisos sudo heredados retirados y respaldados'
 else log INFO 'sudoers personalizado conservado; revisá sus permisos manualmente';fi
fi
touch "$TARGET/storage/maintenance"
rsync -a --exclude config --exclude storage --exclude tests --exclude .git "$SOURCE/" "$TARGET/"
# Retirar únicamente el enlace público a config.php generado por v1.8.
python3 - <<'PYPUBLIC'
from pathlib import Path
link=Path('/opt/ceossh/public/config.php')
if link.is_symlink() and link.resolve()==Path('/opt/ceossh/config/config.php'):
    link.unlink()
PYPUBLIC
cp "$SOURCE/config/config.example.php" "$TARGET/config/config.example.php"
log INFO 'Migrando esquema y cifrando credenciales; administradores existentes conservados'
php "$TARGET/scripts/migrate.php"
if [[ "$MODE" == --install ]];then export CEOSSH_ADMIN_NAME CEOSSH_ADMIN_PASSWORD;php "$TARGET/scripts/admin.php";unset CEOSSH_ADMIN_PASSWORD;fi
chown -R root:www-data "$TARGET"
find "$TARGET" -type d -exec chmod 0750 {} +
find "$TARGET" -type f -exec chmod 0640 {} +
chmod 0750 "$TARGET/install.sh" "$TARGET"/scripts/*.sh
chown -R www-data:www-data "$TARGET/storage"
if [[ ! -f "$TARGET/config/ssh/id_ed25519" ]];then ssh-keygen -q -t ed25519 -N '' -f "$TARGET/config/ssh/id_ed25519";fi
chown www-data:www-data "$TARGET/config/ssh/id_ed25519";chmod 0600 "$TARGET/config/ssh/id_ed25519"
touch "$TARGET/config/known_hosts";chown root:www-data "$TARGET/config/known_hosts";chmod 0640 "$TARGET/config/known_hosts"
cat > /etc/apache2/conf-available/ceossh-directory.conf <<'APACHE'
<Directory /opt/ceossh/public>
    Require all granted
    AllowOverride None
    Options -Indexes
    DirectoryIndex index.php
</Directory>
<Directory /opt/ceossh/config>
    Require all denied
</Directory>
APACHE
a2enconf ceossh-directory
if [[ "$MODE" == --install ]];then
 cat > /etc/apache2/sites-available/ceossh.conf <<APACHE
Listen $PANEL_PORT
<VirtualHost *:$PANEL_PORT>
    DocumentRoot /opt/ceossh/public
    ErrorLog \${APACHE_LOG_DIR}/ceossh-error.log
    CustomLog \${APACHE_LOG_DIR}/ceossh-access.log combined
</VirtualHost>
APACHE
 a2ensite ceossh
else
 log INFO 'Adaptando DocumentRoot de sitios CEOSSH reconocidos; se conservan TLS y otros sitios'
 python3 "$TARGET/scripts/apache-migrate.py" --apply
fi
if ! apache2ctl configtest;then
 log ERROR "Apache rechazó la configuración. Restaurando únicamente archivos Apache desde $BACKUP/apache2"
 python3 - "$BACKUP/apache2" <<'PYROLLBACK'
from pathlib import Path
import sys
backup=Path(sys.argv[1])
for name in ['sites-available/ceossh.conf','sites-enabled/ceossh.conf','conf-available/ceossh-directory.conf','conf-enabled/ceossh-directory.conf']:
    if not (backup/name).exists() and not (backup/name).is_symlink():
        (Path('/etc/apache2')/name).unlink(missing_ok=True)
PYROLLBACK
 cp -a "$BACKUP/apache2/." /etc/apache2/
 exit 1
fi
printf '* * * * * www-data /usr/bin/php /opt/ceossh/scripts/worker.php >> /opt/ceossh/storage/logs/worker.log 2>&1\n' > /etc/cron.d/ceossh
chmod 0644 /etc/cron.d/ceossh
cat > /etc/logrotate.d/ceossh <<'ROTATE'
/opt/ceossh/storage/logs/*.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    su www-data www-data
    copytruncate
}
ROTATE
cat > /usr/local/bin/ceo <<'CEO'
#!/usr/bin/env bash
exec bash /opt/ceossh/scripts/ceo-menu.sh "$@"
CEO
chown root:root /usr/local/bin/ceo;chmod 0755 /usr/local/bin/ceo
php "$TARGET/scripts/diagnose.php"
# Solo retirar el marcador cuando las verificaciones hayan pasado.
systemctl enable --now apache2 cron
systemctl reload apache2
python3 -c 'from pathlib import Path;Path("/opt/ceossh/storage/maintenance").unlink(missing_ok=True)'
if [[ "$MODE" == --install ]];then
 RESPONSE=$(mktemp)
 HTTP_CODE=$(curl --silent --show-error --max-time 20 --output "$RESPONSE" --write-out '%{http_code}' "http://127.0.0.1:$PANEL_PORT/index.php") || HTTP_CODE=000
 if [[ "$HTTP_CODE" != 200 ]] || ! grep -q 'CEOSSH' "$RESPONSE" || grep -q '<?php' "$RESPONSE";then
  touch "$TARGET/storage/maintenance"
  log ERROR "La comprobación HTTP del login falló (código $HTTP_CODE); el panel queda en mantenimiento"
  python3 - "$RESPONSE" <<'PYREMOVE'
import pathlib,sys
pathlib.Path(sys.argv[1]).unlink(missing_ok=True)
PYREMOVE
  exit 1
 fi
 python3 - "$RESPONSE" <<'PYREMOVE'
import pathlib,sys
pathlib.Path(sys.argv[1]).unlink(missing_ok=True)
PYREMOVE
 log OK 'Login servido por Apache y PHP: HTTP 200'
fi
if [[ "$MODE" == --update ]];then flock -u 9;fi
log OK 'Panel, migración, permisos, comando ceo y cron preparados'
log INFO "Respaldo: $BACKUP — Registro: $LOG"
if [[ "$MODE" == --install ]];then log INFO "Panel: http://IP_DEL_SERVIDOR:$PANEL_PORT/";else log INFO 'Accedé por tu URL existente y verificá el VirtualHost si no se detectó automáticamente';fi
log INFO 'Ejecutá sudo ceo. Registrá huellas con scripts/trust-vps.sh; para cuentas heredadas revisá scripts/adopt.php'
CEOSSH_FILE_2_END
cat > "$PACKAGE/scripts/admin.php" <<'CEOSSH_FILE_4_END'
<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'){http_response_code(404);exit;}
require dirname(__DIR__).'/app/bootstrap.php';
try {
    $name=getenv('CEOSSH_ADMIN_NAME')?:'';$password=getenv('CEOSSH_ADMIN_PASSWORD')?:'';
    if(!preg_match('/^[a-zA-Z0-9_]{3,64}$/D',$name)||strlen($password)<12||strlen($password)>128)
        throw new RuntimeException('Administrador inválido o contraseña fuera de 12–128 bytes');
    if(Core::query('SELECT id FROM panel_admins WHERE username=?',[$name])->fetchColumn())
        throw new RuntimeException('El administrador ya existe; su contraseña se conserva');
    Core::query('INSERT INTO panel_admins(username,password) VALUES(?,?)',[$name,password_hash($password,PASSWORD_DEFAULT)]);
    echo "Administrador creado\n";
} catch(Throwable $e){fwrite(STDERR,'No se pudo crear el administrador: '.$e->getMessage()."\n");exit(1);}
CEOSSH_FILE_4_END
cat > "$PACKAGE/scripts/apache-migrate.py" <<'CEOSSH_FILE_5_END'
#!/usr/bin/env python3
"""Modifica solamente DocumentRoot de sitios que sirven un frontend CEOSSH identificado."""
import re, pathlib, sys, json
base=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else '/etc/apache2/sites-available')
roots=[]
for conf in sorted(base.glob('*.conf')):
    content=conf.read_text()
    def migrate(match):
        root=pathlib.Path(match.group(2).strip('"'))
        if str(root)=='/opt/ceossh/public': return match.group(0)
        if not root.is_dir(): return match.group(0)
        files=[root/'index.php',root/'dashboard.php',root/'api'/'users_list.php']
        if not all(f.is_file() for f in files): return match.group(0)
        login=files[0].read_text(errors='replace')
        if 'ceossh_sess' not in login or '/opt/ceossh/config/config.php' not in login: return match.group(0)
        roots.append({'config':str(conf),'old_root':str(root)})
        return match.group(1)+'/opt/ceossh/public'+match.group(3)
    changed=re.sub(r'(?m)^(\s*DocumentRoot\s+)("[^"\n]+"|[^\s#]+)([^\n]*)$',migrate,content)
    if changed!=content:
        if '--apply' in sys.argv: conf.write_text(changed)
print(json.dumps(roots,ensure_ascii=False,indent=2))
CEOSSH_FILE_5_END
cat > "$PACKAGE/scripts/ceo-menu.sh" <<'CEOSSH_FILE_6_END'
#!/usr/bin/env bash
set -uo pipefail
umask 077
[[ $(id -u) == 0 ]] || { echo 'Ejecutá sudo ceo'; exit 1; }
TARGET=/opt/ceossh
cli() { php "$TARGET/scripts/ceo.php" "$@"; }
pause() { read -r -p 'Enter para continuar… ' _ || true; }
secret() {
 read -r -p 'Usuario administrador: ' CEOSSH_ADMIN_NAME || return 1
 read -r -s -p 'Contraseña (12–128 caracteres): ' CEOSSH_ADMIN_PASSWORD || return 1; printf '\n'
 local confirmation
 read -r -s -p 'Repetir contraseña: ' confirmation || return 1; printf '\n'
 if [[ "$confirmation" != "$CEOSSH_ADMIN_PASSWORD" ]]; then unset CEOSSH_ADMIN_PASSWORD;echo 'No coinciden';return 1;fi
 export CEOSSH_ADMIN_NAME CEOSSH_ADMIN_PASSWORD
}
if [[ ${1:-} == --status ]]; then cli status;exit $?;fi
while true;do
 printf '\nCEOSSH 2.0 — Administración del servidor\n'
 printf '%s\n' '1) Estado y estadísticas' '2) Administradores' '3) Usuarios SSH locales' '4) Servicios y puertos' '5) Registros y alertas' '6) Crear respaldo completo' '7) Diagnóstico' '0) Salir'
 read -r -p 'Opción: ' option || exit 0
 case "$option" in
 1) cli status ;;
 2)
  cli admins
  printf '%s\n' '1) Crear' '2) Cambiar contraseña' '3) Eliminar' '0) Volver'
  read -r -p 'Opción: ' action || exit 0
  case "$action" in
   1|2) if secret;then [[ "$action" == 1 ]] && cmd=add || cmd=password;cli "$cmd";fi;unset CEOSSH_ADMIN_PASSWORD CEOSSH_ADMIN_NAME ;;
   3) read -r -p 'Usuario a eliminar: ' name;read -r -p "Escribí ELIMINAR $name: " confirm
      [[ "$confirm" == "ELIMINAR $name" ]] && cli delete "$name" ;;
  esac ;;
 3) awk -F: '$3>=1000 && $3<65534 {printf "%s\tUID=%s\t%s\n",$1,$3,$7}' /etc/passwd ;;
 4) for svc in apache2 mariadb mysql cron;do printf '%s: ' "$svc";systemctl is-active "$svc" || true;done;ss -lnt
    read -r -p 'Recargar Apache (s/n): ' choice
    if [[ "$choice" == s ]];then apache2ctl configtest && systemctl reload apache2;fi ;;
 5) printf '%s\n' '1) Instalador' '2) Worker' '3) Errores Apache' '4) Alertas recientes'
    read -r -p 'Registro: ' kind
    case "$kind" in
     1) tail -n 100 /var/log/ceossh-install.log ;;
     2) tail -n 100 "$TARGET/storage/logs/worker.log" ;;
     3) tail -n 100 /var/log/apache2/ceossh-error.log ;;
     4) php "$TARGET/scripts/diagnose.php" --alerts ;;
    esac ;;
 6) bash "$TARGET/scripts/backup.sh" ;;
 7) php "$TARGET/scripts/diagnose.php";apache2ctl configtest;systemctl is-active cron || true ;;
 0) exit 0 ;;
 *) echo 'Opción inválida' ;;
 esac
 pause
done
CEOSSH_FILE_6_END
cat > "$PACKAGE/scripts/ceo.php" <<'CEOSSH_FILE_7_END'
<?php
// Administración local: no endpoint HTTP y no contraseñas en argumentos.
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require dirname(__DIR__).'/app/bootstrap.php';
function fail(string $message): never { fwrite(STDERR, $message."\n"); exit(1); }
function clean(mixed $value): string { return preg_replace('/[\x00-\x1f\x7f\x1b]/', ' ', (string)$value); }
$action=$argv[1]??'status';
try {
    switch ($action) {
        case 'status':
            foreach (['Administradores'=>'panel_admins','Grupos'=>'vps_groups','VPS'=>'vps','Cuentas'=>'ssh_users'] as $label=>$table)
                echo $label.': '.Core::query("SELECT COUNT(*) FROM $table")->fetchColumn()."\n";
            echo 'Operaciones pendientes: '.Core::query("SELECT COUNT(*) FROM jobs WHERE status IN ('pending','running','failed')")->fetchColumn()."\n";
            echo 'Alertas abiertas: '.Core::query('SELECT COUNT(*) FROM events WHERE resolved_at IS NULL')->fetchColumn()."\n";
            break;
        case 'admins':
            foreach(Core::query('SELECT id,username,last_login FROM panel_admins ORDER BY id')->fetchAll() as $row)
                printf("%s\t%s\t%s\n",$row['id'],clean($row['username']),clean($row['last_login']??'Sin acceso registrado'));
            break;
        case 'add': case 'password':
            $name=getenv('CEOSSH_ADMIN_NAME')?:'';
            $password=getenv('CEOSSH_ADMIN_PASSWORD')?:'';
            if(!preg_match('/^[a-zA-Z0-9_]{3,64}$/D',$name)||strlen($password)<12||strlen($password)>128) fail('Usuario inválido o contraseña fuera de 12–128 caracteres.');
            $db=Core::db(); $db->beginTransaction();
            // Serializar la administración para proteger al último administrador.
            $rows=Core::query('SELECT id,username FROM panel_admins ORDER BY id FOR UPDATE')->fetchAll();
            $found=false; foreach($rows as $row)if($row['username']===$name)$found=true;
            if($action==='add'&&$found)fail('Ya existe; su contraseña se conserva.');
            if($action==='password'&&!$found)fail('Administrador inexistente.');
            $hash=password_hash($password,PASSWORD_DEFAULT);
            if($action==='add')Core::query('INSERT INTO panel_admins(username,password) VALUES(?,?)',[$name,$hash]);
            else Core::query('UPDATE panel_admins SET password=? WHERE username=?',[$hash,$name]);
            Core::event('admin','info',"Administración local: $action de $name"); $db->commit();
            echo "Administrador actualizado.\n"; break;
        case 'delete':
            $name=$argv[2]??'';
            $db=Core::db();$db->beginTransaction();
            $rows=Core::query('SELECT id,username FROM panel_admins ORDER BY id FOR UPDATE')->fetchAll();
            $found=false;foreach($rows as $row)if($row['username']===$name)$found=true;
            if(!$found)fail('Administrador inexistente.');
            if(count($rows)<=1)fail('No se puede eliminar el último administrador.');
            Core::query('DELETE FROM panel_admins WHERE username=?',[$name]);
            Core::event('admin','warning',"Administración local: baja de $name");$db->commit();
            echo "Administrador eliminado.\n";break;
        default: fail('Acción desconocida.');
    }
} catch(Throwable $e) { if(isset($db)&&$db->inTransaction())$db->rollBack(); fail('Error de administración: '.$e->getMessage()); }
CEOSSH_FILE_7_END
cat > "$PACKAGE/scripts/diagnose.php" <<'CEOSSH_FILE_8_END'
<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'){http_response_code(404);exit;}
require dirname(__DIR__).'/app/bootstrap.php';
try {
    Core::query('SELECT 1');echo "Base de datos: OK\n";
    if(($argv[1]??'')==='--alerts') {
        foreach(Core::query('SELECT severity,message,created_at FROM events WHERE resolved_at IS NULL ORDER BY id DESC LIMIT 25')->fetchAll() as $r)
            echo preg_replace('/[\x00-\x1f\x7f\x1b]/',' ',implode(' | ',$r))."\n";
        exit;
    }
    foreach(['config/secret.key','config/known_hosts','config/ssh/id_ed25519','scripts/worker.php'] as $path)
        echo $path.': '.(is_file(CEOSSH_ROOT.'/'.$path)?'presente':'FALTA')."\n";
    echo 'Operaciones: '.Core::query('SELECT COUNT(*) FROM jobs')->fetchColumn()."\n";
    echo 'PHP: '.PHP_VERSION."\n";
    echo 'Huella de VPS: verificá cada servidor con trust-vps.sh.\n';
} catch(Throwable $e){fwrite(STDERR,'Diagnóstico falló: '.$e->getMessage()."\n");exit(1);}
CEOSSH_FILE_8_END
cat > "$PACKAGE/scripts/worker.php" <<'CEOSSH_FILE_9_END'
<?php
require dirname(__DIR__).'/app/bootstrap.php';
if (PHP_SAPI!=='cli') exit;
if (is_file(CEOSSH_ROOT.'/storage/maintenance')) exit;
$lock=fopen(CEOSSH_ROOT.'/storage/worker.lock','c');
if (!$lock || !flock($lock,LOCK_EX|LOCK_NB)) exit;
try {
    Operations::expire();
    $count=Operations::runJobs(8);
    // Monitorear las 3 VPS menos recientes por ciclo para no bloquear toda la cola.
    foreach (Core::query("SELECT * FROM vps WHERE status='active' AND (last_checked IS NULL OR last_checked<DATE_SUB(UTC_TIMESTAMP(),INTERVAL 60 SECOND)) ORDER BY last_checked LIMIT 3")->fetchAll() as $vps) Operations::monitor($vps);
    Core::query("INSERT INTO app_meta(name,value) VALUES('worker_heartbeat',?) ON DUPLICATE KEY UPDATE value=VALUES(value)",[gmdate('Y-m-d H:i:s')]);
    Core::query('DELETE FROM login_attempts WHERE created_at<DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 DAY)');
    echo date('Y-m-d H:i:s')." OK: $count operaciones completadas\n";
} catch (Throwable $e) { fwrite(STDERR,date('Y-m-d H:i:s').' ERROR: '.$e->getMessage()."\n"); exit(1); }
CEOSSH_FILE_9_END
log OK 'Panel descargado y complementos del instalador preparados'
bash "$PACKAGE/install.sh" "$MODE"
if [[ "$MODE" != --check ]];then
 log OK 'Finalizado. Administrá el panel con sudo ceo'
 log INFO 'En instalación nueva, abrí http://IP_PUBLICA:PUERTO/ con el puerto que elegiste'
 log INFO 'Verificá las huellas SSH de tus VPS antes de crear cuentas; instrucciones en /opt/ceossh/docs/INSTALL.md'
fi
