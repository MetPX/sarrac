#
# spec file for package sarrac
#
# Copyright (c) 2019 SUSE LINUX GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


Name:           sarrac
Version:        2.19.11b1
Release:        0
Summary:        C implementation of Sarracenia (partial)
License:        GPL-2.0
Source:         .
BuildRequires:  gcc make libopenssl-devel libjson-c-devel librabbitmq-devel
Requires:       libopenssl libjson-c librabbitmq4
BuildArch:      noarch
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description

%prep
%setup -q

%build
make %{?_smp_mflags}

%install
%make_install

%post
%postun

%files
%defattr(-,root,root)
%doc README.rst ./debian/changelog
%{_bindir}/*
%{_libdir}/*
%{_includedir}/*

%changelog

