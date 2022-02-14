use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use chrono::{DateTime, TimeZone, Utc};
use clap::Parser;
use csv::{QuoteStyle, WriterBuilder};
use serde::{Deserialize, Serialize};

mod my_date_format {
    use chrono::{DateTime, TimeZone, Utc};
    use serde::{self, Deserialize, Deserializer, Serializer};

    const FORMAT: &'static str = "%Y-%m-%d %H:%M:%S";

    pub fn serialize<S>(
        date: &DateTime<Utc>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
    {
        let s = format!("{}", date.format(FORMAT));
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<DateTime<Utc>, D::Error>
        where
            D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Utc.datetime_from_str(&s[0..18], FORMAT).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct UrlhausResponse {
    query_status: String,
    #[serde(with = "my_date_format")]
    firstseen: DateTime<Utc>,
    #[serde(with = "my_date_format")]
    lastseen: DateTime<Utc>,
    url_count: String,
    urls: Vec<UrlhausEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UrlhausEntry {
    url_id: String,
    url: String,
    url_status: String,
    #[serde(with = "my_date_format")]
    dateadded: DateTime<Utc>,
    reporter: String,
    threat: String,
    tags: Vec<String>,
    urlhaus_reference: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ThreatfoxResponse {
    query_status: String,
    data: Vec<ThreatFoxEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ThreatFoxEntry {
    id: String,
    ioc: String,
    threat_type: String,
    threat_type_desc: String,
    ioc_type: String,
    ioc_type_desc: String,
    malware: String,
    malware_printable: String,
    malware_alias: String,
    malware_malpedia: String,
    confidence_level: i32,
    #[serde(with = "my_date_format")]
    first_seen: DateTime<Utc>,
    reporter: String,
    tags: Vec<String>,
}


#[derive(Parser, Debug)]
#[clap(about, long_about = None)]
struct Args {
    /// API Endpoint(urlhaus or threatfox)
    #[clap(short, long, default_value_t = String::from("urlhaus"))]
    api : String,

    /// Exclude url_status online
    #[clap(long)]
    exclude_online: bool,

    /// Exclude url_status offline
    #[clap(long)]
    exclude_offline: bool,

    /// Exclude ioc type.
    #[clap(long, default_value_t = String::from("hash"))]
    exclude_ioc: String,

    /// Filter by reporter(partial match)
    #[clap(short, long, default_value_t = String::from(""))]
    reporter: String,

    /// Filter by tag(partial match)
    #[clap(short, long, default_value_t = String::from("emotet"))]
    tag: String,

    /// Filter by date from(YYYYMMDD)
    #[clap(long, default_value_t = Utc::today().format("%Y%m%d").to_string())]
    date_from: String,

    /// Filter by date to(YYYYMMDD)
    #[clap(long, default_value_t = Utc::today().format("%Y%m%d").to_string())]
    date_to: String,

    /// Output format(json or csv)
    #[clap(short, long)]
    format: Option<String>,
}

fn main() {
    let args: Args = Args::parse();
    let client = reqwest::blocking::Client::new();
    if args.api.contains("threatfox") {
        let param = HashMap::from([("query", "taginfo"), ("tag", args.tag.as_str()), ("limit", "1000")]);
        let res = client.post("https://threatfox-api.abuse.ch/api/v1/").json(&param).send();
        let res_data = match res {
            Ok(r) => r,
            Err(e) => panic!("failed to get abuse.ch api response. [{:?}]", e)
        };
        let res_json: ThreatfoxResponse = res_data.json().unwrap();
        let res_entries = res_json.data.iter().
            filter(|&e|
                e.reporter.contains(&args.reporter) &&
                    !e.ioc_type.contains(&args.exclude_ioc) &&
                    e.first_seen >= Utc.datetime_from_str(&format!("{}{}", &args.date_from, "000000"), "%Y%m%d%H%M%S").unwrap_or(Utc::now()) &&
                    e.first_seen <= Utc.datetime_from_str(&format!("{}{}", &args.date_to, "000000"), "%Y%m%d%H%M%S").unwrap_or(Utc::now()));
        match args.format {
            Some(x) if x.to_lowercase().eq("json") => {
                let content = serde_json::to_string_pretty(&res_json.data).unwrap();
                let f = File::create("result.json").expect("Unable to create file.");
                let mut f = BufWriter::new(f);
                f.write_all(content.as_bytes()).expect("Unable to write file.");
                println!("outputted. [{:?}].", f)
            },
            Some(x) if x.to_lowercase().eq("csv") => {
                let f = File::create("result.csv").expect("Unable to create file.");
                let mut wtr = WriterBuilder::new().quote_style(QuoteStyle::Always).from_writer(BufWriter::new(f));
                let _ = wtr.write_record(&["id", "ioc", "threat_type", "threat_type_desc", "ioc_type", "ioc_type_desc", "malware", "malware_printable", "malware_alias", "malware_malpedia", "confidence_level", "first_seen", "reporter", "tags"]);
                for e in res_entries {
                    let _ = wtr.write_record(&[&e.id, &e.ioc.replace("http", "hxxp"), &e.threat_type, &e.threat_type_desc, &e.ioc_type, &e.ioc_type_desc, &e.malware, &e.malware_printable, &e.malware_alias, &e.malware_malpedia, &e.confidence_level.to_string(), &e.first_seen.to_string(), &e.reporter, &e.tags.join(":")]);
                }
                println!("outputted. [{}].", "result.csv");
            },
            _ => {
                for entry in res_entries {
                    println!("{:?}", entry);
                }
            }
        }
    } else {
        let param = [("tag", args.tag.as_str())];
        let res = client.post("https://urlhaus-api.abuse.ch/v1/tag").form(&param).send();
        let res_data = match res {
            Ok(r) => r,
            Err(e) => panic!("failed to get abuse.ch api response. [{:?}]", e)
        };
        let res_json: UrlhausResponse = res_data.json().unwrap();
        let res_entries = res_json.urls.iter()
            .filter(|&e|
                ((e.url_status.eq("online") && !args.exclude_online) ||
                    (e.url_status.eq("offline") && !args.exclude_offline)) &&
                    e.reporter.contains(&args.reporter) &&
                    e.dateadded >= Utc.datetime_from_str(&format!("{}{}", &args.date_from, "000000"), "%Y%m%d%H%M%S").unwrap_or(Utc::now()) &&
                    e.dateadded <= Utc.datetime_from_str(&format!("{}{}", &args.date_to, "000000"), "%Y%m%d%H%M%S").unwrap_or(Utc::now()));

        match args.format {
            Some(x) if x.to_lowercase().eq("json") => {
                let content = serde_json::to_string_pretty(&res_json.urls).unwrap();
                let f = File::create("result.json").expect("Unable to create file.");
                let mut f = BufWriter::new(f);
                f.write_all(content.as_bytes()).expect("Unable to write file.");
                println!("outputted. [{:?}].", f)
            },
            Some(x) if x.to_lowercase().eq("csv") => {
                let f = File::create("result.csv").expect("Unable to create file.");
                let mut wtr = WriterBuilder::new().quote_style(QuoteStyle::Always).from_writer(BufWriter::new(f));
                let _ = wtr.write_record(&["url_id", "url", "url_status", "dateadded", "reporter", "threat", "tags"]);
                for e in res_entries {
                    let _ = wtr.write_record(&[&e.url_id, &e.url.replace("http", "hxxp"), &e.url_status, &e.dateadded.to_string(), &e.reporter, &e.threat, &e.tags.join(":")]);
                }
                println!("outputted. [{}].", "result.csv");
            },
            _ => {
                for entry in res_entries {
                    println!("{:?}", entry);
                }
            }
        };
    }
}

