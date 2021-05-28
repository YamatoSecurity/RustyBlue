use crate::detections::print::MessageNotation;
use clap::ArgGroup;
use clap::{App, AppSettings, Arg, ArgMatches};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;

lazy_static! {
    pub static ref CONFIG: ConfigReader = ConfigReader::new();
}

#[derive(Clone)]
pub struct ConfigReader {
    pub regex: Vec<Vec<String>>,
    pub args: ArgMatches<'static>,
    pub application_regex: Regex,
    pub applocker_regex: Regex,
    pub powershell_hostapplication_regex: Regex,
    pub powershell_line_feed_regex: Regex,
    pub whitelist_regex: Vec<Regex>,
    pub encode_regex: Regex,
    pub encoded_command_regex: Regex,
    pub base64_regex: Regex,
    pub base64_with_before_after_regex: Regex,
    pub singlequote_regex: Regex,
    pub noalpha_regex: Regex,
    pub nobinary_regex: Regex,
    pub regexes: HashMap<String, Regex>,
    pub compress_regex: Regex,
}

impl ConfigReader {
    pub fn new() -> Self {
        ConfigReader {
            regex: read_csv("regexes.txt"),
            args: build_app(),
            application_regex: Regex::new(r"^Application: ").unwrap(),
            applocker_regex: Regex::new(r" was .*$").unwrap(),
            powershell_hostapplication_regex: Regex::new(
                "(?ms)^.*(ホスト アプリケーション|Host Application) = ",
            )
            .unwrap(),
            powershell_line_feed_regex: Regex::new("(?ms)\n.*$").unwrap(),
            whitelist_regex: get_whitelist_regex(read_csv("whitelist.txt")),
            encode_regex: Regex::new(r"\-enc.*[A-Za-z0-9/+=]{100}").unwrap(),
            encoded_command_regex: Regex::new(r"^.* \-Enc(odedCommand)? ").unwrap(),
            base64_regex: Regex::new(r":FromBase64String\(").unwrap(),
            base64_with_before_after_regex: Regex::new(r"^.*:FromBase64String\('*").unwrap(),
            singlequote_regex: Regex::new(r"'.*$").unwrap(),
            noalpha_regex: Regex::new(r"[a-z0-9/¥;:|.]").unwrap(),
            nobinary_regex: Regex::new(r"[01]").unwrap(),
            regexes: get_regexes(read_csv("regexes.txt")),
            compress_regex: Regex::new(r"Compression.GzipStream.*Decompress").unwrap(),
        }
    }
}

fn build_app<'a>() -> ArgMatches<'a> {
    let program = std::env::args()
        .nth(0)
        .and_then(|s| {
            std::path::PathBuf::from(s)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
        })
        .unwrap();

    if is_test_mode() {
        return ArgMatches::default();
    }

    App::new(program)
        .about("RustyBlue")
        .version("1.0.0")
        .author("YamatoSecurity <info@yamatosecurity.com>")
        .setting(AppSettings::VersionlessSubcommands)
        .args_from_usage(
            "-f --filepath=[FILEPATH] 'analyze event file'
            -d --dirpath=[DIRECTORYPATH] 'analyze event log files in directory'
            -c --credits 'print credits infomation'",
        )
        .group(
            ArgGroup::with_name("requireargs")
                .args(&["filepath", "dirpath", "credits"])
                .required(true),
        )
        .get_matches()
}

fn is_test_mode() -> bool {
    for i in std::env::args() {
        if i == "--test" {
            return true;
        }
    }

    return false;
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
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            MessageNotation::alert(
                &mut stdout,
                format!("Error : {} not found , {}", filename, err),
            )
            .ok();
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

    ret
}

fn get_whitelist_regex(whitelist: Vec<Vec<String>>) -> Vec<Regex> {
    let empty = "".to_string();
    let mut ret: Vec<Regex> = vec![];
    for line in whitelist {
        let r_str = line.get(0).unwrap_or(&empty);
        if r_str.is_empty() {
            continue;
        }

        ret.push(Regex::new(r_str).unwrap());
    }

    ret
}

pub fn get_regexes(regexes: Vec<Vec<String>>) -> HashMap<String, Regex> {
    let empty = "".to_string();
    let mut ret: HashMap<String, Regex> = HashMap::new();
    for line in regexes {
        let regex_str = line.get(1).unwrap_or(&empty);
        if regex_str.is_empty() {
            continue;
        }

        let re = Regex::new(regex_str);
        if re.is_ok() {
            ret.insert(regex_str.to_string(), re.unwrap());
        }
    }

    ret
}

#[cfg(test)]
mod tests {

    use crate::detections::configs;
    use regex::Regex;
    use std::collections::HashMap;

    // cargo test -- --test test_is_test_mode_true で実行
    #[test]
    #[ignore]
    fn test_is_test_mode_true() {
        assert_eq!(true, configs::is_test_mode());
        assert_ne!(false, configs::is_test_mode());
    }

    // cargo test -- test_is_test_mode_false で実行
    #[test]
    #[ignore]
    fn test_is_test_mode_false() {
        assert_eq!(false, configs::is_test_mode());
        assert_ne!(true, configs::is_test_mode());
    }

    #[test]
    fn test_get_regexes() {
        let mut regexes: Vec<Vec<String>> = Vec::new();
        let mut tmp = Vec::new();
        tmp.push("0".to_string());
        tmp.push("^cmd.exe /c echo [a-z]{6} > \\\\\\\\.\\\\pipe\\\\[a-z]{6}$".to_string());
        tmp.push(
            "Metasploit-style cmd with pipe (possible use of Meterpreter 'getsystem')".to_string(),
        );
        regexes.push(tmp);

        let ret: HashMap<String, Regex> = configs::get_regexes(regexes);

        assert_eq!(
            ret.contains_key("^cmd.exe /c echo [a-z]{6} > \\\\\\\\.\\\\pipe\\\\[a-z]{6}$"),
            true
        );
        assert_eq!(
            ret.contains_key("^cmd.exe /c echo [a-z]{6} > \\\\\\\\.\\\\pipe\\\\[a-z]{6}"),
            false
        );
    }

    #[test]
    fn test_get_whitelist_regex() {
        let mut regexes: Vec<Vec<String>> = Vec::new();
        let mut tmp = Vec::new();
        tmp.push(
            "^\"C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome\\.exe".to_string(),
        );
        regexes.push(tmp);

        let ret: Vec<Regex> = configs::get_whitelist_regex(regexes);
        assert_eq!(
            ret.get(0).unwrap().to_string(),
            "^\"C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome\\.exe"
        );
    }

    #[test]
    fn test_read_csv() {
        let csv = configs::read_csv("whitelist.txt");
        assert_eq!(
            csv.get(0).unwrap().get(0).unwrap(),
            "^\"C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome\\.exe\""
        );
    }

    #[test]
    fn test_failed_read_csv() {
        let csv = configs::read_csv("hogehoge.txt");
        assert_eq!(csv.len(), 0);
        assert_ne!(csv.len(), 1);
    }
}
