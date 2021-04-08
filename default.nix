{ pkgs, tzdata ? pkgs.tzdata, locale ? pkgs.locale, pacifier, nss-certs }:

pkgs.dockerTools.buildLayeredImage rec {
  name = "docker-registry.intr/net/pacifier";
  tag = "latest";
  contents = [ pacifier nss-certs ];
  config = {
    Entrypoint = [ "${pacifier}/bin/pacifier" ];
    Env = [
      "TZ=Europe/Moscow"
      "TZDIR=${tzdata}/share/zoneinfo"
      "LOCALE_ARCHIVE_2_27=${locale}/lib/locale/locale-archive"
      "LOCALE_ARCHIVE=${locale}/lib/locale/locale-archive"
      "LC_ALL=en_US.UTF-8"
      "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
    ];
  };
  extraCommands = ''
    set -x -e

    mkdir -p {etc,root,tmp}
    chmod 755 etc
    chmod 777 tmp

    cat > etc/passwd << 'EOF'
    root:!:0:0:System administrator:/root:/bin/sh
    EOF

    cat > etc/group << 'EOF'
    root:!:0:
    EOF
  '';
}
