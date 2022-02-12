# urlhaus-search
Search IoC from [urlhaus-api](https://urlhaus-api.abuse.ch/#taginfo).

## Requirements

Rustc version 1.56.0 or greater.

## Usage

```
USAGE:
    urlhaus-search [OPTIONS]

OPTIONS:
        --date-from <DATE_FROM>    Filter by dateadded from(YYYYMMDD) [default: 20220212]
        --date-to <DATE_TO>        Filter by dateadded to(YYYYMMDD) [default: 20220212]
        --exclude-offline          Exclude url_status offline
        --exclude-online           Exclude url_status online
    -f, --format <FORMAT>          Output format(json or csv)
    -h, --help                     Print help information
    -r, --reporter <REPORTER>      Filter by reporter(partial match) [default: ]
    -t, --tag <TAG>                Filter by tag(partial match) [default: emotet]
```

## How to use

1. git clone https://github.com/fukusuket/urlhaus-search.git
2. cd urlhaus-search
3. cargo run -- --date-from 20220201 --date-to 20220210 --tag emotet

then output recent ioc from urlhaus api.

## Output

TODO

