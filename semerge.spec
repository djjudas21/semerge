Name:		semerge
Version:	0.0.1
Release:	1
Summary:	Merge SELinux policy files

Group:		Development/Tools
License:	Apache 2.0
URL:		https://github.com/djjudas21/semerge
Source0:	%{name}-%{version}.tar.gz
BuildArch:	noarch

Requires:	perl
Requires:	perl(Getopt::Long)

%description
semerge accepts SELinux rulesets via STDIN (e.g. the output of audit2allow) and by reading an existing policy file. It merges, deduplicates and sorts the two inputs to produce an output policy which contains the contents of both sources.

%prep
%setup -q


%install
rm -rf "$RPM_BUILD_ROOT"
mkdir -p $RPM_BUILD_ROOT/%{_bindir}
install -m 755 semerge.pl $RPM_BUILD_ROOT/%{_bindir}/semerge

%files
%{_bindir}/semerge
%doc

%clean
rm -rf $RPM_BUILD_ROOT


%changelog

