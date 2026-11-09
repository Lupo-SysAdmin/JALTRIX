Name: snort-soc-desktop
Version: 1.0.0
Release: 1%{?dist}
Summary: JALTRIX bilingual desktop console for Snort 3
License: GPL-3.0-or-later
Packager: Jan Herrera <281252544+Lupo-SysAdmin@users.noreply.github.com>
URL: https://github.com/Lupo-SysAdmin
Source0: %{name}-%{version}.tar.gz
BuildArch: noarch
Requires: python3 >= 3.11
Requires: python3-gobject-base
Requires: python3-pyside6
Requires: qt6-qtdeclarative
Requires: qt6-qtsvg
Recommends: nftables
Recommends: polkit
Recommends: iproute

%description
Snort JSON investigation and offline replay console by Jan Herrera.
No engine or capture service is bundled. English and Latin American Spanish.

%prep
%setup -q

%build

%install
mkdir -p %{buildroot}%{_prefix}/lib/%{name} %{buildroot}%{_bindir}
cp -r src/snort_soc %{buildroot}%{_prefix}/lib/%{name}/
chmod -R go-w %{buildroot}%{_prefix}/lib/%{name}/
printf '%s\n' '#!/usr/bin/python3' 'import sys' 'sys.dont_write_bytecode = True' 'sys.path.insert(0, "/usr/lib/snort-soc-desktop")' 'from snort_soc.app import main' 'main()' > %{buildroot}%{_bindir}/snort-soc
chmod 755 %{buildroot}%{_bindir}/snort-soc
install -Dm644 packaging/desktop/io.github.LupoSysAdmin.SnortSOC.desktop %{buildroot}%{_datadir}/applications/io.github.LupoSysAdmin.SnortSOC.desktop
install -Dm644 src/snort_soc/ui/app-icon.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/io.github.LupoSysAdmin.SnortSOC.svg
install -Dm644 src/snort_soc/ui/app-icon.png %{buildroot}%{_datadir}/icons/hicolor/512x512/apps/io.github.LupoSysAdmin.SnortSOC.png

install -Dm644 packaging/metainfo/io.github.LupoSysAdmin.SnortSOC.metainfo.xml %{buildroot}%{_datadir}/metainfo/io.github.LupoSysAdmin.SnortSOC.metainfo.xml
install -Dm644 packaging/man/snort-soc.1 %{buildroot}%{_mandir}/man1/snort-soc.1

%files
%license LICENSE
%doc NOTICE AUTHORS
%{_prefix}/lib/%{name}/
%{_bindir}/snort-soc
%{_datadir}/applications/io.github.LupoSysAdmin.SnortSOC.desktop
%{_datadir}/icons/hicolor/512x512/apps/io.github.LupoSysAdmin.SnortSOC.png
%{_datadir}/icons/hicolor/scalable/apps/io.github.LupoSysAdmin.SnortSOC.svg

%{_datadir}/metainfo/io.github.LupoSysAdmin.SnortSOC.metainfo.xml
%{_mandir}/man1/snort-soc.1*
