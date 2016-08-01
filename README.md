# semerge
Merge SELinux policy files

This script accepts SELinux rulesets via STDIN (e.g. the output of `audit2allow`) and by reading an existing policy file. It merges, deduplicates and sorts the two inputs to produce an output policy which contains the contents of both sources.

## Usage

`-i|--input`	Read an existing SELinux policy file.

`-o|--output`	Write the resulting merged policy to a file. Defaults to STDOUT.

`-v|--version`	Override the module number given to the resulting merged policy. Defaults to incrementing whatever version number is fed in from file, then stdin.

`-n|--name`	Override the module name given to the resulting merged policy. Defaults to whatever name is fed in from file, then stdin.

`-h|--help`	Print this message


## Examples

```
semerge -i existingpolicy.pp -o existingpolicy.pp
# or 
cat existingpolicy.pp | semerge > existingpolicy.pp
```

Deduplicates and alphabetises `existingpolicy.pp`

```
cat /var/log/audit/audit.log | audit2allow | semerge -i existingpolicy.pp -o newpolicy.pp
```
Create `newpolicy.pp` which merges new rules from `audit2allow` into `existingpolicy.pp`

```
cat /var/log/audit/audit.log | audit2allow | semerge -i existingpolicy.pp -o existingpolicy.pp
```
Update `existingpolicy.pp` with new rules from `audit2allow`
