Name: omg-observer-fixture
Version: 1
Release: 1
Summary: Inert repository observer test fixture
License: MIT
BuildArch: noarch
%description
An inert package for offline repository observation tests.
%prep
%build
%install
mkdir -p %{buildroot}/usr/share/omg-observer-fixture
printf fixture > %{buildroot}/usr/share/omg-observer-fixture/value
%files
/usr/share/omg-observer-fixture/value
