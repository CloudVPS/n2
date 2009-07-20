%define version 1.0.1

Name: n2
Summary: n2 packages
Group: Development
Version: %version
Source0: n2-%{version}.tar.gz
Source1: lua-5.1.4.tar.gz
BuildRequires: readline-devel,ncurses-devel
Release: 1
License: GPLv3
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-build
%description
n2 packages

%package n2txd
Summary: n2 transmit daemon
Group: Development
%description n2txd
This is the small agent component that you run on every host you
want to monitor.

%package n2rxd
Summary: n2 receive daemon
Group: Development
%description n2rxd
This package consists of the receiver daemon that stores reports from
nodes running n2rxd, plus tools to inspect those reports.

%prep
%setup -q -a 1

%build
BUILD_ROOT=$RPM_BUILD_ROOT
make -C lua-5.1.4 linux
LUALIBS='lua-5.1.4/src/liblua.a -lm -ldl' LUAINC='-Ilua-5.1.4/src' make

%install
BUILD_ROOT=$RPM_BUILD_ROOT
rm -rf ${BUILD_ROOT}
mkdir -p ${BUILD_ROOT}/etc/init.d
mkdir -p ${BUILD_ROOT}/etc/n2
mkdir -p ${BUILD_ROOT}/usr/bin
mkdir -p ${BUILD_ROOT}/usr/sbin

install -b -m 0755 rpm/n2txd.init ${BUILD_ROOT}/etc/init.d/n2txd
install -b -m 0644 n2txd.example.conf ${BUILD_ROOT}/etc/n2/
install -m 0755 n2txd ${BUILD_ROOT}/usr/sbin

sed s/n2txd/n2rxd/g < rpm/n2txd.init > rpm/n2rxd.init
install -b -m 0755 rpm/n2rxd.init ${BUILD_ROOT}/etc/init.d/n2rxd
rm rpm/n2rxd.init
install -b -m 0644 n2rxd.example.conf ${BUILD_ROOT}/etc/n2/
install -b -m 0644 analyze.lua ${BUILD_ROOT}/etc/n2/
install -b -m 0644 analyze-user.lua ${BUILD_ROOT}/etc/n2/analyze-user.lua.example
install -m 0755 n2rxd ${BUILD_ROOT}/usr/sbin/
install -m 0755 n2ping ${BUILD_ROOT}/usr/sbin/
install -m 0755 n2analyze ${BUILD_ROOT}/usr/bin/
install -m 0755 n2hstat ${BUILD_ROOT}/usr/bin/
install -m 0755 n2pgrep ${BUILD_ROOT}/usr/bin/
install -m 0755 n2history ${BUILD_ROOT}/usr/bin/
install -m 0755 n2contact ${BUILD_ROOT}/usr/bin/
install -m 0755 n2rawdat ${BUILD_ROOT}/usr/bin/
install -m 0755 n2groups ${BUILD_ROOT}/usr/bin/

%post n2txd
grep -qw ^n2 /etc/group || groupadd -f n2 > /dev/null
grep -qw ^n2 /etc/passwd || useradd n2 -r -g n2 > /dev/null
install -d -o root -g n2 -m 0750 /etc/n2
echo .. please create a config from the sample and start n2txd
chkconfig --level 2345 n2txd on

%post n2rxd
grep -qw ^n2 /etc/group || groupadd -f n2 > /dev/null
grep -qw ^n2 /etc/passwd || useradd n2 -r -g n2 > /dev/null
install -d -o root -g n2 -m 0750 /etc/n2
install -d -o n2 -g n2 -m 0750 /var/log/n2
install -d -m 0755 /var/state
install -d -m 0755 /var/state/n2
install -d -o n2 -g n2 -m 0750 /var/state/n2/current
install -d -o n2 -g n2 -m 0750 /var/state/n2/events
install -d -o n2 -g n2 -m 0750 /var/state/n2/log
install -d -o n2 -g n2 -m 0750 /var/state/n2/ping
install -d -o n2 -g n2 -m 0750 /var/state/n2/tmp
echo .. please create a config from the sample and start n2rxd
chkconfig --level 2345 n2rxd on

%preun n2txd
if [ "$1" = 0 ] ; then
	service n2txd stop > /dev/null 2>&1
	chkconfig --del n2txd
fi
exit 0

%postun n2txd
if [ "$1" -ge 1 ]; then
	service n2txd condrestart > /dev/null 2>&1
fi
exit 0 

%preun n2rxd
if [ "$1" = 0 ] ; then
	service n2rxd stop > /dev/null 2>&1
	chkconfig --del n2rxd
fi
exit 0

%postun n2rxd
if [ "$1" -ge 1 ]; then
	service n2rxd condrestart > /dev/null 2>&1
fi
exit 0 

%files n2txd
%defattr(-,root,root)
%dir /etc/n2
/etc/n2/n2txd.example.conf
/etc/init.d/n2txd
/usr/sbin/n2txd

%files n2rxd
%defattr(-,root,root)
%dir /etc/n2
/etc/n2/n2rxd.example.conf
/etc/n2/analyze.lua
/etc/n2/analyze-user.lua.example
/usr/bin/n2analyze
/usr/bin/n2history
/usr/bin/n2contact
/usr/bin/n2rawdat
/usr/bin/n2groups
/usr/bin/n2hstat
/usr/bin/n2pgrep
/usr/sbin/n2rxd
/usr/sbin/n2ping
/etc/init.d/n2rxd

%clean
rm -rf $RPM_BUILD_ROOT

