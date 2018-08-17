Name: qsslcaudit
Version: 0.1.0
Release: alt1
Summary: test SSL/TLS clients how secure they are
License: GPLv3
Group: Security/Networking
Url: https://github.com/gremwell/qsslcaudit

Packager: Pavel Nakonechnyi <pavel@gremwell.com>

Source: %name.tar

BuildPreReq: cmake rpm-macros-cmake
BuildRequires: qt5-base-devel, libgnutls-devel

BuildRequires: unsafelibssl-devel

%description
This tool can be used to determine if an application that uses TLS/SSL for its
data transfers does this in a secure way.

%prep
%setup -n %name

%build
%cmake_insource -DOPENSSL_ROOT_DIR="/opt/unsafeopenssl/usr" -DCMAKE_BUILD_TYPE=Release
%make_build VERBOSE=1

%install
%makeinstall_std

%files
%_bindir/*
%doc README.md

%changelog
* Thu Aug 17 2018 Pavel Nakonechnyi <pavel@altlinux.org> 0.1.0-alt1
- initial build from https://github.com/gremwell/qsslcaudit
