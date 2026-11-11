# SPDX-License-Identifier: MIT
Name:           xe-bug-report
Version:        0.1.0
Release:        1%{?dist}
Summary:        Standalone GPU diagnostic collector
License:        MIT

%description
Writes a redacted zip bundle of kernel logs, sysfs, PCI state and xpu-smi output.

%install
install -D -m 0755 %{_sourcedir}/xe-bug-report %{buildroot}%{_bindir}/xe-bug-report

%files
%{_bindir}/xe-bug-report
