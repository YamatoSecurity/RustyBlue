extern crate regex;

use clap::{App, AppSettings, Arg, ArgMatches};
use std::fs::File;
use std::io::prelude::*;
use std::sync::Once;
use regex::Regex;
use std::collections::HashMap;

#[derive(Clone)]
pub struct SingletonReader {
    pub regex: Vec<Vec<String>>,
    pub whitelist: Vec<Vec<String>>,
    pub args: ArgMatches<'static>,
    pub cached_regex: HashMap<String,Regex>,
}

pub fn get_thread_num() -> i32 {
    let conf = singleton();
    let thread_number_str = conf.args.value_of("threadnumber").unwrap_or("1");
    return thread_number_str.parse().unwrap();
}
pub fn singleton() -> Box<SingletonReader> {
    static mut SINGLETON: Option<Box<SingletonReader>> = Option::None;
    static ONCE: Once = Once::new();

    unsafe {
        ONCE.call_once(|| {
            let singleton = SingletonReader {
                regex: read_csv("regexes.txt"),
                whitelist: read_csv("whitelist.txt"),
                args: build_app().get_matches(),
                cached_regex: get_regex(),
            };

            SINGLETON = Some(Box::new(singleton));
        });

        return SINGLETON.clone().unwrap();
    }
}

fn get_regex() -> HashMap<String,Regex> {
    let mut ret = HashMap::new();

    ret.insert(r"\-enc.*[A-Za-z0-9/+=]{100}".to_string(), Regex::new(r"\-enc.*[A-Za-z0-9/+=]{100}").unwrap());
    ret.insert(r"^.* \-Enc(odedCommand)? ".to_string(), Regex::new(r"^.* \-Enc(odedCommand)? ").unwrap());
    ret.insert(r":FromBase64String\(".to_string(), Regex::new(r":FromBase64String\(").unwrap());
    ret.insert(r"^.*:FromBase64String\('*".to_string(), Regex::new(r"^.*:FromBase64String\('*").unwrap());
    ret.insert(r"'.*$".to_string(), Regex::new(r"'.*$").unwrap());
    ret.insert(r"Compression.GzipStream.*Decompress".to_string(), Regex::new(r"Compression.GzipStream.*Decompress").unwrap());
    ret.insert(r"[a-z0-9/¥;:|.]".to_string(), Regex::new(r"[a-z0-9/¥;:|.]").unwrap());
    ret.insert(r"[01]".to_string(), Regex::new(r"[01]").unwrap());

    read_csv("whitelist.txt").iter().for_each(|e|{
        let def = "".to_string();
        let r_str = e.get(0).unwrap_or(&def);
        ret.insert(r_str.into(), Regex::new(r_str).unwrap());
    });
    
    read_csv("regexes.txt").iter().for_each(|e|{
        let def = "".to_string();
        let r_str = e.get(1).unwrap_or(&def);
        ret.insert(r_str.into(), Regex::new(r_str).unwrap());
    });

    return ret;
}

fn build_app() -> clap::App<'static, 'static> {
    let program = std::env::args()
        .nth(0)
        .and_then(|s| {
            std::path::PathBuf::from(s)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
        })
        .unwrap();

    App::new(program)
        .about("RustyBlue")
        .version("1.0.0")
        .author("YamatoSecurity <info@yamatosecurity.com>")
        .setting(AppSettings::VersionlessSubcommands)
        .arg(Arg::from_usage(
            "-f --filepath=[FILEPATH] 'analyze event file'",
        ))
        .arg(Arg::from_usage("-c --credits 'print credits information'"))
        .arg(Arg::from_usage("-t --threadnumber=[THREADNUMBER] 'thread count(default: 1)'"))
}

fn read_csv(filename: &str) -> Vec<Vec<String>> {
    let mut ret = vec![];
    let mut contents: String = String::new();
    match File::open(filename) {
        Ok(f) => {
            let mut f: File = f;
            if f.read_to_string(&mut contents).is_err() {
                return ret;
            }
        }
        Err(err) => {
            println!("Error : {} not found , {}", filename, err);
        }
    }

    let mut rdr = csv::Reader::from_reader(contents.as_bytes());
    rdr.records().for_each(|r| {
        if r.is_err() {
            return;
        }

        let line = r.unwrap();
        let mut v = vec![];
        line.iter().for_each(|s| v.push(s.to_string()));
        ret.push(v);
    });

    return ret;
}
