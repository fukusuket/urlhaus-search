# URLhaus-Search
- Search IoC from [URLhaus API](https://urlhaus-api.abuse.ch/#taginfo) and output(json or csv).
- Search IoC from [Threatfox API](https://threatfox.abuse.ch/api/#taginfo) and output(json or csv).


## Usage

```
USAGE:
    urlhaus-search [OPTIONS]

OPTIONS:
    -a, --api <API>                    API Endpoint(urlhaus or threatfox) [default: urlhaus]
        --date-from <DATE_FROM>        Filter by date from(YYYYMMDD) [default: 20220213]
        --date-to <DATE_TO>            Filter by date to(YYYYMMDD) [default: 20220213]
        --exclude-ioc <EXCLUDE_IOC>    Exclude ioc type [default: hash]
        --exclude-offline              Exclude url_status offline
        --exclude-online               Exclude url_status online
    -f, --format <FORMAT>              Output format(json or csv)
    -h, --help                         Print help information
    -r, --reporter <REPORTER>          Filter by reporter(partial match) [default: ]
    -t, --tag <TAG>                    Filter by tag(partial match) [default: emotet]
```

## How to use([from release](https://github.com/fukusuket/urlhaus-search/releases))
1. Download zip [from release page](https://github.com/fukusuket/urlhaus-search/releases), and unzip.
2. >urlhause-search.exe ---date-from 20220201 --date-to 20220210 --tag emotet --api urlhaus --format csv

## How to use(from source)

1. git clone https://github.com/fukusuket/urlhaus-search.git
2. cd urlhaus-search
3. cargo run -- --date-from 20220201 --date-to 20220210 --tag emotet --api urlhaus --format csv

then output recent ioc from urlhaus api.

## Output
then output result.csv current directory as follows.
```
"url_id","url","url_status","dateadded","reporter","threat","tags"
"2107099","hxxp://example.com/4l9T5s7EcTyT/","online","2022-05-22 21:15:00 UTC","Bob","malware_download","emotet:epoch5:exe:Heodo"
"2106523","hxxp:///example.com/ae6oCWBnC/","online","2022-05-22 11:47:00 UTC","Alice","malware_download","emotet:epoch4:exe:Heodo"
...
```
