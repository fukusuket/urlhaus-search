# URLhaus-Search
- Search IoC from [URLhaus API](https://urlhaus-api.abuse.ch/#taginfo).
- Search IoC from [Threatfox API](https://threatfox.abuse.ch/api/#taginfo).


## Requirements

Rustc version 1.56.0 or greater.

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

## How to use

1. git clone https://github.com/fukusuket/urlhaus-search.git
2. cd urlhaus-search
3. cargo run -- --date-from 20220201 --date-to 20220210 --tag emotet --api urlhaus

then output recent ioc from urlhaus api.

## Output

TODO

