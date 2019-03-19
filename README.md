# IP_GeneralWhois
This tools aims to help my SOC Team to make Whois + GeoIP location on bulk IP.

## Installation
`pip -r requirements.txt`

## Run
`./IP_GeneralWhois -i ip.txt -o output.csv -g GeoLite2-City.mmdb`

## Output
The output is a csv file :
`ip,asn_description,country,latitude,longitude`
