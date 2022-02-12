use std::fs::File;
use std::io::{BufWriter, Write};
use chrono::{DateTime, TimeZone, Utc};
use clap::Parser;
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
        Utc.datetime_from_str(&s, FORMAT).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Response {
    query_status: String,
    #[serde(with = "my_date_format")]
    firstseen: DateTime<Utc>,
    #[serde(with = "my_date_format")]
    lastseen: DateTime<Utc>,
    url_count: String,
    urls: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Entry {
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


#[derive(Parser, Debug)]
#[clap(about, long_about = None)]
struct Args {
    /// Exclude url_status online
    #[clap(long)]
    exclude_online: bool,

    /// Exclude url_status offline
    #[clap(long)]
    exclude_offline: bool,

    /// Filter by reporter(partial match)
    #[clap(short, long, default_value_t = String::from(""))]
    reporter: String,

    /// Filter by tag(partial match)
    #[clap(short, long, default_value_t = String::from("emotet"))]
    tag: String,

    /// Filter by dateadded from(YYYYMMDD)
    #[clap(long, default_value_t = Utc::today().format("%Y%m%d").to_string())]
    date_from: String,

    /// Filter by dateadded to(YYYYMMDD)
    #[clap(long, default_value_t = Utc::today().format("%Y%m%d").to_string())]
    date_to: String,

    /// Output format(json or csv)
    #[clap(short, long)]
    format: Option<String>,
}

fn main() {
    let args: Args = Args::parse();
    let client = reqwest::blocking::Client::new();
    let res = client.post("https://urlhaus-api.abuse.ch/v1/tag").form(&[("tag", args.tag)]).send();
    let res_data = match res {
        Ok(r) => r,
        Err(e) => panic!("failed to get urlhaus api response. [{:?}]", e)
    };
    let res_json: Response = res_data.json().unwrap();
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
            todo!()
        },
        _ => {
            for entry in res_entries {
                println!("{:?}", entry);
            }
        }
    };
}

#[test]
fn compare_datetime() {
    let e = Entry {
        url_id: "".to_string(),
        url: "".to_string(),
        url_status: "".to_string(),
        dateadded: Utc::now(),
        reporter: "".to_string(),
        threat: "".to_string(),
        tags: vec![],
        urlhaus_reference: "".to_string(),
    };
    let d = Utc.datetime_from_str("20181207000000", "%Y%m%d%H%M%S").unwrap();
    assert!(e.dateadded > d)
}

