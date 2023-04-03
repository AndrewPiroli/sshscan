# Audit SSH algorithms in use

Generates an HTML report containing information of the SSH servers on your network.

Information includes:
 * Host/port of SSH servers
 * Key Exchange Algorithms
 * Host Key Algorithms
 * Encryption Algorithms
 * MAC Algorithms
 * Compression Algorithms

The data is organized in 2 ways:
 1) A hosts section, with a tabular view of algorithms per host
 2) A alogirthms section, with a list view of hosts per algorithm

Having these multiple views allows you to quickly locate the information you want.
Internal hyperlinks are used extensively to allow jumping between hosts and specific algorithms.


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
