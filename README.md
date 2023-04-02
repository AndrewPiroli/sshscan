# Audit SSH algorithms in use

## Scan
Scan and generate report. Requires nmap installed and available in PATH.

```
Usage: sshscan scan [OPTIONS] <CIDR> [PORT] [AGGRESSIVE]

Arguments:
  <CIDR>        Range to scan in CIDR format X.X.X.X/X
  [PORT]        Port to scan (default: 22)
  [AGGRESSIVE]  Agressive mode (-T5) (default: true) [possible values: true, false]

Options:
  -o, --output <OUTPUT_FILE>  Output file to write
  -i, --include-down <INCLUDE_DOWN>  Include hosts that are down (default: false) [possible values: true, false]
  -h, --help                  Print help
```

## Generate

Generate a report based on existing scan data

```
Usage: sshscan generate [OPTIONS] <INPUT_FILE>

Arguments:
  <INPUT_FILE>  Input XML file to read from

Options:
  -o, --output <OUTPUT_FILE>  Output file to write
  -i, --include-down <INCLUDE_DOWN>  Include hosts that are down (default: false) [possible values: true, false]
  -h, --help                  Print help
```


## Examples

```shell
nmap -T5 -p22 --script ssh2-enum-algos 192.168.0.0/24 -oX output.xml
sshscan generate output.xml -o output.html
```

```shell
sshscan scan 192.168.0.0/24 -o output.html
```
