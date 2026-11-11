# SPDX-License-Identifier: MIT
#
# Built by scripts/package.sh, which passes the version and puts the release binary, LICENSE and
# README.md in %{_sourcedir}:
#   rpmbuild --define "_topdir <dir>" --define "pkg_version <version>" -bb xe-bug-report.spec
%{!?pkg_version: %global pkg_version 0.0.0}

# The binary is built (and stripped) by cargo before rpmbuild runs.
%global debug_package %{nil}
%global __strip /bin/true

Name:           xe-bug-report
Version:        %{pkg_version}
Release:        1%{?dist}
Summary:        Standalone GPU diagnostic collector
License:        MIT
URL:            https://github.com/team-blue-savery42/xe-bug-report
Recommends:     pciutils
Suggests:       xpu-smi

%description
Writes one redacted zip bundle of kernel logs, sysfs and debugfs attributes, PCI state, package
lists and xpu-smi output, for bug reports. It does not link Level Zero or any GPU library, so it
still runs when the GPU runtime is missing or the driver is wedged, and it records why a source
could not be collected. Host and user names, serial numbers and addresses are replaced by default.

%prep

%build

%install
install -D -m 0755 %{_sourcedir}/xe-bug-report %{buildroot}%{_bindir}/xe-bug-report
install -D -m 0644 %{_sourcedir}/LICENSE %{buildroot}%{_licensedir}/%{name}/LICENSE
install -D -m 0644 %{_sourcedir}/README.md %{buildroot}%{_docdir}/%{name}/README.md

%files
%license %{_licensedir}/%{name}/LICENSE
%doc %{_docdir}/%{name}/README.md
%{_bindir}/xe-bug-report

%changelog
* Tue Nov 10 2026 xe-bug-report contributors <savery42@users.noreply.github.com> - %{pkg_version}-1
- Packaged by scripts/package.sh.
