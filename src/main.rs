extern crate serde;

use evtx::EvtxParser;
use rusty_blue::detections::configs;
use rusty_blue::detections::detection;
use std::{fs, path::PathBuf, process};


fn main() {

    if let Some(filepath) = configs::singleton().args.value_of("filepath") {
        parse_file(&filepath.to_string());
    }

    if configs::singleton().args.is_present("credits") {
        print_credits();
    }
}

fn print_credits() {
    match fs::read_to_string("./credits.txt") {
        Ok(contents) => println!("{}", contents),
        Err(err) => println!("Error : credits.txt not found , {}", err),
    }
}

fn parse_file(filepath: &str) {
    let fp = PathBuf::from(filepath);
    let parser = match EvtxParser::from_path(fp) {
        Ok(pointer) => pointer,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };

    let mut detection = detection::Detection::new();
    &detection.start(parser);
}
