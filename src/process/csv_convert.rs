use csv::Reader;
use std::fs;

use crate::OutputFormat;

pub fn process_csv(input: &str, output: &str, format: OutputFormat) -> anyhow::Result<()> {
    let mut reader = Reader::from_path(input)?;

    let mut ret = Vec::with_capacity(128);
    let headers = reader.headers()?.clone();
    for result in reader.records() {
        let record = result?;
        // let iter = headers.iter().zip(record.iter());
        // let json_value:String = match format {
        //     OutputFormat::Json => {
        //         let v = iter.collect::<serde_json::Value>();
        //         serde_json::to_string_pretty(&v)?
        //     },
        //     OutputFormat::Yaml => {
        //         let v = iter.collect::<serde_yaml::value::Value>();
        //     },
        //     OutputFormat::Toml => {
        //         iter.collect::<toml::Value>();
        //         "".into()
        //     },
        // };

        let json_value = headers
            .iter()
            .zip(record.iter())
            .collect::<serde_json::Value>();
        ret.push(json_value);
    }

    let content = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&ret)?,
        OutputFormat::Yaml => serde_yaml::to_string(&ret)?,
        OutputFormat::Toml => toml::to_string(&ret)?,
    };

    // let json = serde_json::to_string_pretty(&ret)?;

    fs::write(output, content)?;

    Ok(())
}
