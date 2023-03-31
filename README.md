# Audit SSH algorithms in use

## Generate

Generate a report based on existing scan data

```
Usage: sshscan-bin generate [OPTIONS] <INPUT_FILE>

Arguments:
  <INPUT_FILE>  Input XML file to read from

Options:
  -o, --output <OUTPUT_FILE>  Output file to write
  -h, --help                  Print help
```

## Scan
Scan and generate report

```
Usage: sshscan-bin scan [OPTIONS] <CIDR> [PORT] [AGGRESSIVE]

Arguments:
  <CIDR>        Range to scan in CIDR format X.X.X.X/X
  [PORT]        Port to scan (default: 22)
  [AGGRESSIVE]  Agressive mode (-T5) (default: true) [possible values: true, false]

Options:
  -o, --output <OUTPUT_FILE>  Output file to write
  -h, --help                  Print help
```


## Examples

```shell
nmap -T5 -p22 --script ssh2-enum-algos 192.168.0.0/24 -oX output.xml
sshscan-bin generate output.xml -o output.html
```

```shell
sshscan-bin scan 192.168.0.0/24 -o output.html
```
