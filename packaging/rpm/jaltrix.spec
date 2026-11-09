Name: jaltrix
Version: 1.1.0
Release: 1%{?dist}
Summary: JALTRIX bilingual desktop console for Snort 3
License: GPL-3.0-or-later
Packager: Jan Herrera <281252544+Lupo-SysAdmin@users.noreply.github.com>
URL: https://github.com/Lupo-SysAdmin
Source0: %{name}-%{version}.tar.gz
BuildArch: noarch
Obsoletes: snort-soc-desktop < 1.1.0
Conflicts: snort-soc-desktop
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
cp -r src/jaltrix %{buildroot}%{_prefix}/lib/%{name}/
chmod -R go-w %{buildroot}%{_prefix}/lib/%{name}/
printf '%s\n' '#!/usr/bin/python3' 'import sys' 'sys.dont_write_bytecode = True' 'sys.path.insert(0, "/usr/lib/jaltrix")' 'from jaltrix.app import main' 'main()' > %{buildroot}%{_bindir}/jaltrix
chmod 755 %{buildroot}%{_bindir}/jaltrix
install -Dm644 packaging/desktop/io.github.LupoSysAdmin.Jaltrix.desktop %{buildroot}%{_datadir}/applications/io.github.LupoSysAdmin.Jaltrix.desktop
install -Dm644 src/jaltrix/ui/app-icon.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/io.github.LupoSysAdmin.Jaltrix.svg
install -Dm644 src/jaltrix/ui/app-icon.png %{buildroot}%{_datadir}/icons/hicolor/512x512/apps/io.github.LupoSysAdmin.Jaltrix.png

install -Dm644 packaging/metainfo/io.github.LupoSysAdmin.Jaltrix.metainfo.xml %{buildroot}%{_datadir}/metainfo/io.github.LupoSysAdmin.Jaltrix.metainfo.xml
install -Dm644 packaging/man/jaltrix.1 %{buildroot}%{_mandir}/man1/jaltrix.1

%files
%license LICENSE
%doc NOTICE AUTHORS
%{_prefix}/lib/%{name}/
%{_bindir}/jaltrix
%{_datadir}/applications/io.github.LupoSysAdmin.Jaltrix.desktop
%{_datadir}/icons/hicolor/512x512/apps/io.github.LupoSysAdmin.Jaltrix.png
%{_datadir}/icons/hicolor/scalable/apps/io.github.LupoSysAdmin.Jaltrix.svg

%{_datadir}/metainfo/io.github.LupoSysAdmin.Jaltrix.metainfo.xml
%{_mandir}/man1/jaltrix.1*
