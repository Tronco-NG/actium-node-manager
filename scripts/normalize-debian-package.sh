#!/usr/bin/env bash
set -Eeuo pipefail

package_path=${1:-}
if [[ -z "$package_path" || ! -f "$package_path" ]]; then
  echo "Uso: $0 <paquete.deb>" >&2
  exit 2
fi

work_dir=$(mktemp -d -t actium-node-manager-deb.XXXXXX)
trap 'rm -rf "$work_dir"' EXIT

package_root="$work_dir/package"
dpkg-deb --raw-extract "$package_path" "$package_root"
control_path="$package_root/DEBIAN/control"

if ! grep -Eq '^Depends: .*libgtk-3-0([[:space:]],|[[:space:]]*$)' "$control_path"; then
  echo 'El control DEB no contiene la dependencia GTK esperada para normalizar.' >&2
  exit 3
fi

awk '
  /^Depends: / {
    sub(/libgtk-3-0[[:space:]]*,/, "libgtk-3-0 | libgtk-3-0t64,")
    sub(/libgtk-3-0$/, "libgtk-3-0 | libgtk-3-0t64")
  }
  { print }
' "$control_path" > "$control_path.tmp"
mv "$control_path.tmp" "$control_path"

normalized_path="$work_dir/normalized.deb"
dpkg-deb --build "$package_root" "$normalized_path" >/dev/null

depends=$(dpkg-deb -f "$normalized_path" Depends)
case "$depends" in
  *'libgtk-3-0 | libgtk-3-0t64'*) ;;
  *)
    echo 'El control DEB normalizado no declara la alternativa GTK Debian 12/13.' >&2
    exit 4
    ;;
esac

for forbidden in docker-ce docker-compose-plugin docker-compose-v2; do
  case "$depends" in
    *"$forbidden"*)
      echo "El control DEB contiene una dependencia Docker no soportada: $forbidden" >&2
      exit 5
      ;;
  esac
done

mv "$normalized_path" "$package_path"
echo "Dependencias Debian normalizadas: $package_path"
