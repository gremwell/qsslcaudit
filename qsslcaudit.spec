Name: qsslcaudit
Version: 0.5.1
Release: alt1
Summary: test SSL/TLS clients how secure they are
License: GPLv3
Group: Security/Networking
Url: https://github.com/gremwell/qsslcaudit

Packager: Pavel Nakonechnyi <pavel@gremwell.com>

Source: %name.tar

BuildPreReq: cmake rpm-macros-cmake
BuildRequires: qt5-base-devel, libgnutls-devel

BuildRequires: libunsafessl-devel
#BuildRequires: libssl1.1

Patch: %name-%version-%release.patch

%description
This tool can be used to determine if an application that uses TLS/SSL for its
data transfers does this in a secure way.

%prep
%setup -n %name
%patch -p1

%build
%cmake_insource -DCMAKE_BUILD_TYPE=Release
%make_build VERBOSE=1

%install
%makeinstall_std

%files
%_bindir/*
%doc README.md

%changelog
* Wed Jun 26 2019 Pavel Nakonechnyi <pavel@altlinux.org> 0.5.1-alt1
- version 0.5.1

* Wed May 29 2019 Pavel Nakonechnyi <pavel@altlinux.org> 0.5.0-alt1
- version 0.5.0

* Fri Apr 26 2019 Pavel Nakonechnyi <pavel@altlinux.org> 0.4.0-alt1
- version 0.4.0

* Thu Jan 10 2019 Pavel Nakonechnyi <pavel@altlinux.org> 0.3.0-alt1
- version 0.3.0

* Thu Dec 27 2018 Pavel Nakonechnyi <pavel@altlinux.org> 0.2.1-alt1
- version 0.2.1

* Sat Dec 22 2018 Pavel Nakonechnyi <pavel@altlinux.org> 0.2.0-alt1
- version 0.2.0
- spec updated to follow another edition of unsafe OpenSSL library

* Thu Aug 17 2018 Pavel Nakonechnyi <pavel@altlinux.org> 0.1.0-alt1
- initial build from https://github.com/gremwell/qsslcaudit
