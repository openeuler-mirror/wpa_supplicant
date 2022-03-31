Name:          wpa_supplicant
Epoch:         1
Version:       2.10
Release:       1
Summary:       A WPA Supplicant with support for WPA and WPA2 (IEEE 802.11i / RSN)
License:       BSD or GPLv2
Url:           https://w1.fi/wpa_supplicant/
Source0:       http://w1.fi/releases/%{name}-%{version}.tar.gz
Source1:       build-config
Source2:       %{name}.conf
Source3:       %{name}.service
Source5:       %{name}.logrotate

Patch6000:     wpa_supplicant-gui-qt4.patch

BuildRequires: qt-devel >= 4.0 openssl-devel readline-devel dbus-devel libnl3-devel systemd-units docbook-utils
Requires(post): systemd-sysv
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
Obsoletes:     libeap < %{epoch}:%{version}-%{release} libeap-devel < %{epoch}:%{version}-%{release}

%description
wpa_supplicant is a WPA Supplicant for Linux, BSD, Mac OS X, and Windows with support for WPA and WPA2 (IEEE 802.11i / RSN).
It is suitable for both desktop/laptop computers and embedded systems. Supplicant is the IEEE 802.1X/WPA component that is
used in the client stations. It implements key negotiation with a WPA Authenticator and it controls the roaming
and IEEE 802.11 authentication/association of the wlan driver.

%package gui
Summary: Graphical User Interface for %{name}

%description gui
Graphical User Interface for wpa_supplicant written using QT

%package help
Summary: Help package for %{name}
Requires: %{name} = %{epoch}:%{version}-%{release}

%description help
This is the help package for %{name}, including some doc and man help files.

%prep
%autosetup -n %{name}-%{version} -p1

%build
%define _build_cmd__() %{make_build} %{?1:-C %1} %{?2}
%define _build_setups_qt__ QMAKE='%{qmake_qt4}' LRELEASE='%{_qt4_bindir}/lrelease' QTDIR=%{_libdir}/qt4

export CFLAGS="${CFLAGS:-%optflags} -fPIE -DPIE"\
  CXXFLAGS="${CXXFLAGS:-%optflags} -fPIE -DPIE"\
  LDFLAGS="${LDFLAGS:-%optflags} -pie -Wl,-z,now"\
  BINDIR="%{_sbindir}"\
  LIBDIR="%{_libdir}"

cp -f %{SOURCE1} %{name}/.config
%{_build_cmd__ %{name}}
%{_build_cmd__ %{name} wpa_gui-qt4} %{_build_setups_qt__}
%{_build_cmd__ %{name} eapol_test}
%{_build_cmd__ %{name}/doc/docbook man}

%install
install -Dm600 %{SOURCE2} %{buildroot}%{_sysconfdir}/%{name}/%{name}.conf
install -Dm644 %{SOURCE3} %{buildroot}%{_unitdir}/%{name}.service
install -Dm644 %{SOURCE5} %{buildroot}%{_sysconfdir}/logrotate.d/%{name}

install -d %{buildroot}/%{_sbindir}
install -m755 %{name}/{wpa_passphrase,wpa_cli,wpa_supplicant,eapol_test} %{buildroot}%{_sbindir}

install -Dm644 %{name}/dbus/dbus-wpa_supplicant.conf %{buildroot}%{_sysconfdir}/dbus-1/system.d/wpa_supplicant.conf
install -Dm644 %{name}/dbus/fi.w1.wpa_supplicant1.service %{buildroot}%{_datadir}/dbus-1/system-services/fi.w1.wpa_supplicant1.service

install -Dm755 %{name}/wpa_gui-qt4/wpa_gui %{buildroot}/%{_bindir}/wpa_gui

install -d %{buildroot}%{_mandir}/man{5,8}
install -m644 %{name}/doc/docbook/*.8 %{buildroot}%{_mandir}/man8
install -m644 %{name}/doc/docbook/*.5 %{buildroot}%{_mandir}/man5

%post
%systemd_post wpa_supplicant

%preun
%systemd_preun wpa_supplicant

%files
%license COPYING
%config(noreplace) %{_sysconfdir}/%{name}/%{name}.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/%{name}
%{_unitdir}/%{name}.service
%{_sysconfdir}/dbus-1/system.d/%{name}.conf
%{_datadir}/dbus-1/system-services/fi.w1.wpa_supplicant1.service
%{_sbindir}/wpa_passphrase
%{_sbindir}/wpa_supplicant
%{_sbindir}/wpa_cli
%{_sbindir}/eapol_test
%dir %{_sysconfdir}/%{name}

%files gui
%{_bindir}/wpa_gui

%files help
%doc %{name}/ChangeLog README %{name}/eap_testing.txt %{name}/todo.txt %{name}/wpa_supplicant.conf %{name}/examples
%{_mandir}/man8/*
%{_mandir}/man5/*

%changelog
* Thu Mar 31 2022 yuanxin <yuanxin24@h-partners.com> - 1:2.10-1
- update version to 2.10

* Wed Jan 26 2022 shixuantong <shixuantong@huawei.com> - 1:2.6-30
- Type:cves
- ID:CVE-2022-23303 CVE-2022-23304
- SUG:NA
- DESC:fix CVE-2022-23303 CVE-2022-23304

* Wed Sep 22 2021 gaoyusong <gaoyusong1@huawei.com> - 1:2.6-29
- Type:cves
- ID: CVE-2021-0326
- SUG:NA
- DESC: fix CVE-2021-0326

* Thu Mar 11 2021 openEuler Buildteam <buildteam@openeuler.org> - 1:2.6-28
- fix CVE-2021-27803

* Thu Dec 24 2020 wuchaochao <wuchaochao4@huawei.com> - 1:2.6-27
- Type:cves
- ID: CVE-2019-13377
- SUG:NA
- DESC: fix CVE-2019-13377

* Tue Feb 04 2020 zhouyihang <zhouyihang1@huawei.com> - 1:2.6-26
- Type:cves
- ID: CVE-2019-9495
- SUG:restart
- DESC: fix CVE-2019-9495

* Mon Feb 03 2020 zhouyihang <zhouyihang1@huawei.com> - 1:2.6-25
- Type:cves
- ID: CVE-2019-9499
- SUG:restart
- DESC: fix CVE-2019-9499

* Mon Feb 03 2020 lihao <lihao129@huawei.com> - 1:2.6-24
- Type:cves
- ID: CVE-2018-14526
- SUG:restart
- DESC: fix CVE-2018-14526

* Fri Jan 10 2020 openEuler Buildteam <buildteam@openeuler.org> - 1:2.6-23
- clean code

* Tue Dec 31 2019 openEuler Buildteam <buildteam@openeuler.org> - 1:2.6-22
- add options of wpa_supplicant.service

* Sat Dec 21 2019 openEuler Buildteam <buildteam@openeuler.org> - 1:2.6-21
- Modify requires

* Mon Dec 16 2019 openEuler Buildteam <buildteam@openeuler.org> - 1:2.6-20
- fix CVE-2019-16275, CVE-2019-9497, CVE-2019-9498, CVE-2019-9499, CVE-2019-11555

* Wed Sep 25 2019 huzhiyu <huzhiyu1@huawei.com> - 1:2.6-19
- change patch names legal

* Sat Sep 14 2019 huzhiyu <huzhiyu1@huawei.com> - 1:2.6-18
- Package init
