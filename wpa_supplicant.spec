Name:          wpa_supplicant
Epoch:         1
Version:       2.6
Release:       26
Summary:       A WPA Supplicant with support for WPA and WPA2 (IEEE 802.11i / RSN)
License:       BSD
Url:           https://w1.fi/wpa_supplicant/
Source0:       http://w1.fi/releases/%{name}-%{version}.tar.gz
Source1:       build-config
Source2:       %{name}.conf
Source3:       %{name}.service
Source5:       %{name}.logrotate

#patches number ranging between [0,6000) are from fedora/redhat upstream
#patches number ranging between [6000,9000) are backport from higher versions, including some CVE fixes
Patch6000:     macsec-0001-mka-Move-structs-transmit-receive-_-sa-sc-to-a-commo.patch
Patch6001:     macsec-0002-mka-Pass-full-structures-down-to-macsec-drivers-pack.patch
Patch6002:     macsec-0003-mka-Pass-full-structures-down-to-macsec-drivers-tran.patch
Patch6003:     macsec-0004-mka-Pass-full-structures-down-to-macsec-drivers-rece.patch
Patch6004:     macsec-0005-mka-Pass-full-structures-down-to-macsec-drivers-tran.patch
Patch6005:     macsec-0006-mka-Pass-full-structures-down-to-macsec-drivers-rece.patch
Patch6006:     macsec-0007-mka-Add-driver-op-to-get-macsec-capabilities.patch
Patch6007:     macsec-0008-mka-Remove-channel-hacks-from-the-stack-and-the-macs.patch
Patch6008:     macsec-0009-mka-Sync-structs-definitions-with-IEEE-Std-802.1X-20.patch
Patch6009:     macsec-0010-mka-Add-support-for-removing-SAs.patch
Patch6010:     macsec-0011-mka-Implement-reference-counting-on-data_key.patch
Patch6011:     macsec-0012-mka-Fix-getting-capabilities-from-the-driver.patch
Patch6012:     macsec-0013-wpa_supplicant-Allow-pre-shared-CAK-CKN-pair-for-MKA.patch
Patch6013:     macsec-0014-mka-Disable-peer-detection-timeout-for-PSK-mode.patch
Patch6014:     macsec-0015-wpa_supplicant-Add-macsec_integ_only-setting-for-MKA.patch
Patch6015:     macsec-0016-mka-Add-enable_encrypt-op-and-call-it-from-CP-state-.patch
Patch6016:     macsec-0017-wpa_supplicant-Allow-configuring-the-MACsec-port-for.patch
Patch6017:     macsec-0018-drivers-Move-common-definitions-for-wired-drivers-ou.patch
Patch6018:     macsec-0019-drivers-Move-wired_multicast_membership-to-a-common-.patch
Patch6019:     macsec-0020-drivers-Move-driver_wired_multi-to-a-common-file.patch
Patch6020:     macsec-0021-drivers-Move-driver_wired_get_ifflags-to-a-common-fi.patch
Patch6021:     macsec-0022-drivers-Move-driver_wired_set_ifflags-to-a-common-fi.patch
Patch6022:     macsec-0023-drivers-Move-driver_wired_get_ifstatus-to-a-common-f.patch
Patch6023:     macsec-0024-drivers-Move-driver_wired_init_common-to-a-common-fi.patch
Patch6024:     macsec-0025-drivers-Move-driver_wired_deinit_common-to-a-common-.patch
Patch6025:     macsec-0026-drivers-Move-driver_wired_get_capa-to-a-common-file.patch
Patch6026:     macsec-0027-drivers-Move-driver_wired_get_bssid-to-a-common-file.patch
Patch6027:     macsec-0028-drivers-Move-driver_wired_get_ssid-to-a-common-file.patch
Patch6028:     macsec-0029-macsec_linux-Add-a-driver-for-macsec-on-Linux-kernel.patch
Patch6029:     macsec-0030-mka-Remove-references-to-macsec_qca-from-wpa_supplic.patch
Patch6030:     macsec-0031-PAE-Make-KaY-specific-details-available-via-control-.patch
Patch6031:     macsec-0032-mka-Make-MKA-actor-priority-configurable.patch
Patch6032:     macsec-0033-mka-Fix-an-incorrect-update-of-participant-to_use_sa.patch
Patch6033:     macsec-0034-mka-Some-bug-fixes-for-MACsec-in-PSK-mode.patch
Patch6034:     macsec-0035-mka-Send-MKPDUs-forever-if-mode-is-PSK.patch
Patch6035:     macsec-0036-mka-Fix-the-order-of-operations-in-secure-channel-de.patch
Patch6036:     macsec-0037-mka-Fix-use-after-free-when-receive-secure-channels-.patch
Patch6037:     macsec-0038-mka-Fix-use-after-free-when-transmit-secure-channels.patch
Patch6038:     macsec-0039-macsec_linux-Fix-NULL-pointer-dereference-on-error-c.patch
Patch6039:     https://w1.fi/security/2017-1/rebased-v2.6-0001-hostapd-Avoid-key-reinstallation-in-FT-handshake.patch
Patch6040:     https://w1.fi/security/2017-1/rebased-v2.6-0002-Prevent-reinstallation-of-an-already-in-use-group-ke.patch
Patch6041:     https://w1.fi/security/2017-1/rebased-v2.6-0003-Extend-protection-of-GTK-IGTK-reinstallation-of-WNM-.patch
Patch6042:     https://w1.fi/security/2017-1/rebased-v2.6-0004-Prevent-installation-of-an-all-zero-TK.patch
Patch6043:     https://w1.fi/security/2017-1/rebased-v2.6-0005-Fix-PTK-rekeying-to-generate-a-new-ANonce.patch
Patch6044:     https://w1.fi/security/2017-1/rebased-v2.6-0006-TDLS-Reject-TPK-TK-reconfiguration.patch
Patch6045:     https://w1.fi/security/2017-1/rebased-v2.6-0007-WNM-Ignore-WNM-Sleep-Mode-Response-without-pending-r.patch
Patch6046:     https://w1.fi/security/2017-1/rebased-v2.6-0008-FT-Do-not-allow-multiple-Reassociation-Response-fram.patch
Patch6047:     rh1451834-nl80211-Fix-race-condition-in-detecting-MAC-change.patch
Patch6048:     rh1462262-use-system-openssl-ciphers.patch
Patch6049:     rh1465138-openssl-Fix-openssl-1-1-private-key-callback.patch
Patch6050:     rh1497640-mka-add-error-handling-for-secy_init_macsec.patch
Patch6051:     rh1497640-pae-validate-input-before-pointer.patch
Patch6052:     rh1567474-0002-D-Bus-Add-pmf-to-global-capabilities.patch
Patch6053:     rh1570903-nl80211-Fix-NL80211_ATTR_SMPS_MODE-encoding.patch
Patch6054:     CVE-2019-9496-SAE-Fix-confirm-message-validation-in-error-cases.patch
Patch6055:     CVE-2019-9494-1.patch
Patch6056:     CVE-2019-9494-2.patch
Patch6057:     CVE-2019-9494-3.patch
Patch6058:     CVE-2019-9494-4.patch
Patch6059:     CVE-2019-9494-5.patch
Patch6060:     CVE-2019-9494-6.patch
Patch6061:     CVE-2019-9494-7.patch
Patch6062:     CVE-2019-9494-8.patch
Patch6063:     CVE-2019-16275.patch
Patch6064:     CVE-2019-9497.patch
Patch6065:     CVE-2019-9498-and-CVE-2019-9499.patch
Patch6066:     CVE-2019-11555-1.patch
Patch6067:     CVE-2019-11555-2.patch
Patch6068:     https://w1.fi/security/2018-1/rebased-v2.6-0001-WPA-Ignore-unauthenticated-encrypted-EAPOL-Key-data.patch
Patch6069:     CVE-2019-9499.patch
Patch6070:     CVE-2019-9495-pre1.patch
Patch6071:     CVE-2019-9495-pre2.patch
Patch6072:     CVE-2019-9495-pre3.patch
Patch6073:     CVE-2019-9495.patch

Patch9000:     add-options-of-wpa_supplicant-service.patch
Patch9001:     allow-to-override-names-of-qt4-tools.patch

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
install -Dm644 %{name}/dbus/fi.epitest.hostap.WPASupplicant.service %{buildroot}%{_datadir}/dbus-1/system-services/fi.epitest.hostap.WPASupplicant.service

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
%{_datadir}/dbus-1/system-services/fi.epitest.hostap.WPASupplicant.service
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
