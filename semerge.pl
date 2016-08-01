#!/usr/bin/perl -w

# This script accepts SELinux rules via STDIN (e.g. the output of audit2allow)
# and also by referencing an existing policy file. It merges the two to produce
# an output file which contains the contents of both sources.

use Getopt::Long;

# Read in cmdline args
my $result = GetOptions (
	"i|input=s"	=> \$inputfile,
	"o|output=s"	=> \$outputfile,
	"v|version=s"	=> \$version,
	"n|name=s"	=> \$name,
	"h|help"        => \$help,
);

if ($help) {
	print << "LABEL";

	This script accepts SELinux rulesets via STDIN (e.g. the output of audit2allow) and by
	reading an existing policy file. It merges, deduplicates and sorts the two inputs to
	produce an output policy which contains the contents of both sources.

	ARGUMENTS
	=========

	-i|--input	Read an existing SELinux policy file.

	-o|--output	Write the resulting merged policy to a file. Defaults to STDOUT.

	-v|--version	Override the module number given to the resulting merged policy.
			Defaults to incrementing whatever version number is fed in from file,
			then stdin.

	-n|--name	Override the module name given to the resulting merged policy.
			Defaults to whatever name is fed in from file, then stdin.

	-h|--help	Print this message


	EXAMPLES
	========

	semerge -i existingpolicy.pp -o existingpolicy.pp

		Deduplicates and alphabetises existingpolicy.pp


	cat existingpolicy.pp | semerge > existingpolicy.pp

		Equivalent to the above


	cat /var/log/audit/audit.log | audit2allow | semerge -i existingpolicy.pp -o newpolicy.pp

		Create newpolicy.pp which merges new rules from audit2allow into existingpolicy.pp

LABEL
	exit;
}

# Validation of input files

# Set up some globals
my %output;
my @input_stdin;
my ($stdinname, $stdinver);
my @input_file;
my ($infilename, $infilever);

if (! -t STDIN ) {
	# Read in new SELinux rules from stdin
	while (<STDIN>) {
		chomp;
		push(@input_stdin, $_);
	}

	# Make sure STDIN is not blank
	if ($#input_stdin >= 1) {
		($stdinname, $stdinver) = get_header(@input_stdin);
	        # Filter the data into a nested hash for output
		&sort_output(@input_stdin);
	} else {
		print "no input from stdin\n";
		exit;
	}

	# Filter the data into a nested hash for output
	&sort_output(@input_stdin);
}

# Read in existing policy file from -i switch
if ($inputfile) {
	open(my $fh, "<", $inputfile) or die "Can't open $inputfile for reading: $!";
	chomp(my @input_file = <$fh>);
	close $fh;
	if ($#input_file >= 1) {
		($infilename, $infilever) = get_header(@input_file);
		# Filter the data into a nested hash for output
		&sort_output(@input_file);
	} else {
		print "empty file $inputfile\n";
		exit;
	}
}

# Figure out what module name and version to use
# Set by arg takes first precedence, then the infile, then stdin
# If we infer the version from file or stdin, we increment it
my ($modulename, $modulever);
if ($name) {
	$modulename = $name;
} elsif ($infilename) {
	$modulename = $infilename;
} elsif ($stdinname) {
	$modulename = $stdinname;
} else {
	print "Must set module name\n";
	exit;
}

if ($version) {
        $modulever = $version;
} elsif ($infilever) {
        $modulever = &incrementver($infilever);
} elsif ($stdinver) {
        $modulever = &incrementver($stdinver);
} else {
        print "Must set module version\n";
        exit;
}


# Collect final printable output into an array
my @finaloutput = &print_output;

# Finally output the data into file or stdout
if ($outputfile) {
	# Write to file
	open(my $fh, ">", $outputfile) or die "Can't open $outputfile for writing: $!";
	foreach (@finaloutput) {
		print $fh $_;
	}
} else {
	# Write to stdout
	foreach (@finaloutput) {
		print $_;
	}
}





sub print_output {
# Format the contents of the output hash into an array, ready for printing to file or stdout
	my @output;
	push (@output, "module $modulename $modulever;\n\n");
	push (@output, "require {\n");

	# Print types
	#       $TYPE
	# #type rpm_exec_t;
	foreach my $type (sort keys %{$output{'type'}}) {
		push (@output, "\ttype $type;\n");
	}

	push (@output, "\n");

	# Print classes
	#      $CLASS $OBJECT
	#class file { rename execute setattr read lock create ioctl execute_no_trans write getattr unlink open append };
	foreach my $class (sort keys %{$output{'class'}}) {
		push (@output, "\tclass $class { ");
		foreach my $object (sort keys %{$output{'class'}{$class}}) {
			push (@output, "$object ");
		}
		push (@output, "};\n");
	}

	push (@output, "}\n");

	# Print allows
	#        $ALLOW                   $OBJECT       $CLASS $PROPERTY
	# #allow nagios_services_plugin_t dhcpd_state_t:file { read getattr open ioctl };
	foreach my $allow (sort keys %{$output{'allow'}}) {
		push (@output, "\n#============= $allow ==============\n");
		foreach my $object (sort keys %{$output{'allow'}{$allow}}) {
			foreach my $class (sort keys %{$output{'allow'}{$allow}{$object}}) {
				push (@output, "allow $allow $object:$class { ");
				foreach my $property (sort keys %{$output{'allow'}{$allow}{$object}{$class}}) {
					push (@output, "$property ");
				}
				push (@output, "};\n");
			}
		}
	}
	return @output;
}

sub sort_output {
# Spin through an array of SELinux config and sort it into a hierarchical hash
	my @input = @_;
	foreach my $line (@input) {
		#type rpm_exec_t;
		if ($line =~ m/^\s*type (\w+)/) {
			$output{'type'}{$1} = $1;
		#class file rename;
		} elsif ($line =~ m/^\s*class (\w+) (\w+);$/) {
			$output{'class'}{$1}{$2} = $2;
		#class file { rename execute setattr read lock create ioctl execute_no_trans write getattr unlink open append };
		} elsif ($line =~ m/^\s*class (\w+) \{ ([\s\w]+) \};$/) {
			my @arrayofclasses = split(/ /, $2);
			foreach my $class (@arrayofclasses) {
				$output{'class'}{$1}{$class} = $class;
			}
		#allow nagios_services_plugin_t dhcpd_state_t:file read;
		} elsif ($line =~ m/^\s*allow (\w+) (\w+):(\w+) (\w+);$/) {
			$output{'allow'}{$1}{$2}{$3}{$4} = $4;
		#allow nagios_services_plugin_t dhcpd_state_t:file { read getattr open ioctl };
	        } elsif ($line =~ m/^\s*allow (\w+) (\w+):(\w+) \{ ([\s\w]+) \};$/) {
			my @arrayofallows = split(/ /, $4);
			foreach my $allow (@arrayofallows) {
				$output{'allow'}{$1}{$2}{$3}{$allow} = $allow;
			}
		}
	}
}

sub incrementver {
# Increment a decimal-separated version number
	my $ver = shift;
	my @verarray = split(/\./, $ver);
	$verarray[$#verarray]++;
	$ver = join('.', @verarray);
	return $ver;
}

sub get_header {
# Look at an array containing an SELinux policy and return
# the name and version of the policy, if it exists
	my @policy = @_;
	my $header = shift(@policy);
	chomp $header;

	# module resnet-nrpe 1.45;
	if ($header =~ m/^module ([a-z\-_]+) ([0-9\.]+);$/) {
		return ($1, $2);
	}
}
