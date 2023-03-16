# [WIP] Audit SSH algorithms in use

 1) Use nmap to generate an XML report. `nmap -T5 -p22 --script ssh2-enum-algos 192.168.0.0/24 -oX output.xml`
 2) Run sshscan `sshscan-bin output.xml -o report.html`
 3) Open the report in your browser.


