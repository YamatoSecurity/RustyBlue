extern crate csv;
extern crate quick_xml;
extern crate threadpool;

use crate::detections::application;
use crate::detections::applocker;
use crate::detections::common;
use crate::detections::powershell;
use crate::detections::security;
use crate::detections::sysmon;
use crate::detections::system;
use crate::detections::configs;
use crate::models::event;
use evtx::{EvtxParser, SerializedEvtxRecord};
use quick_xml::de::DeError;
use threadpool::ThreadPool;

use std::{collections::BTreeMap};
use std::sync::mpsc::channel;

#[derive(Debug)]
pub struct Detection {
    timeline_list: BTreeMap<String, String>,
}

const RECORD_LEN_PER_THREAD : i32 = 100;

impl Detection {
    pub fn new() -> Detection {
        Detection {
            timeline_list: BTreeMap::new(),
        }
    }

    pub fn start(&mut self, mut parser: EvtxParser<std::fs::File>) -> Result<(), DeError> {
        let xml_records = Detection::parse_xmlrecords(parser);

        let deserialized_records = Detection::deserialize_evtx_record(xml_records);

        // let start = Instant::now();
        self.detect(deserialized_records);
        // let end = start.elapsed();
        // println!("{}.{:03}秒経過しました。logic", end.as_secs(), end.subsec_nanos() / 1_000_000);

        return Ok(());
    }

    // .evtxファイルをxmlに変換する。
    fn parse_xmlrecords( mut parser: EvtxParser<std::fs::File> ) -> Vec<SerializedEvtxRecord<String>> {
        return parser.records().filter_map(|r| {
            if r.is_err() {
                eprintln!("{}", r.unwrap_err());
                return Option::None;
            } else {
                return Option::Some(r.unwrap());
            }
        }).collect();
    }

    // xmlファイルをevent::Evtxクラスのインスタンスに変換する。
    fn deserialize_evtx_record( xml_records: Vec<SerializedEvtxRecord<String>> ) -> Vec<event::Evtx> {
        // 高速化のため、マルチスレッド処理にする
        // tokioを使って書き直した方がいいかも
        // 非同期処理はここを見る 
        // https://tech-blog.optim.co.jp/entry/2019/11/08/163000#Rust-139-1
        // https://tech.uzabase.com/entry/2019/09/17/193206
        // https://blog.ymgyt.io/entry/mini_redis_tutorial_to_get_started_with_tokio#await%E3%81%AE%E3%83%A1%E3%83%B3%E3%82%BF%E3%83%AB%E3%83%A2%E3%83%87%E3%83%AB

        // スレッドプールを使って、並列処理実行
        let records_per_jobs:Vec<Vec<SerializedEvtxRecord<String>>> = Detection::chunks(xml_records,RECORD_LEN_PER_THREAD); // recordの配列を各スレッド毎に分割する
        let threadpool = ThreadPool::new(10);
        let job_num = records_per_jobs.len();
        let (tx, rx) = channel();
        for records_per_job in records_per_jobs {   // ここのfor文をforeach()で書くとなぜかエラーになる....よく分からない
            let tx = tx.clone();
            threadpool.execute( move|| {
                let serialized_records:Vec<event::Evtx> = records_per_job.iter().filter_map(|r|{
                    let serialized_result:Result<event::Evtx,DeError> = quick_xml::de::from_str(&r.data);
                    if serialized_result.is_err() {
                        return Option::None;
                    }else {
                        return Option::Some(serialized_result.unwrap());
                    }
                }).collect();
                tx.send(serialized_records).expect("");
            });            
        }

        // 全てのスレッドの処理が完了するまでブロックする。take()でブロックされている。
        let mut ret = vec![];
        rx.iter().take(job_num).for_each(|serialized_records|{
            serialized_records.into_iter().for_each(|serialized_record| ret.push(serialized_record));
        });

        return ret;
    }

    // ログを検知するロジックの部分
    fn detect( &mut self, records:Vec<event::Evtx> ) {
        let mut common: common::Common = common::Common::new();
        let mut security = security::Security::new();
        let mut system = system::System::new();
        let mut application = application::Application::new();
        let mut applocker = applocker::AppLocker::new();
        let mut sysmon = sysmon::Sysmon::new();
        let mut powershell = powershell::PowerShell::new();
        records.into_iter().for_each(|event|{
            let event_id = event.system.event_id.to_string();
            let channel = event.system.channel.to_string();
            let event_data = event.parse_event_data();

            &common.detection(&event.system, &event_data);
            if channel == "Security" {
                &security.detection(
                    event_id,
                    &event.system,
                    &event.user_data,
                    event_data,
                );
            } else if channel == "System" {
                &system.detection(event_id, &event.system, event_data);
            } else if channel == "Application" {
                &application.detection(event_id, &event.system, event_data);
            } else if channel == "Microsoft-Windows-PowerShell/Operational" {
                &powershell.detection(event_id, &event.system, event_data);
            } else if channel == "Microsoft-Windows-Sysmon/Operational" {
                &sysmon.detection(event_id, &event.system, event_data);
            } else if channel == "Microsoft-Windows-AppLocker/EXE and DLL" {
                &applocker.detection(event_id, &event.system, event_data);
            }
        });

        common.disp();
        security.disp();
    }

    // 配列を指定したサイズで分割する。Vector.chunksと同じ動作をするが、Vectorの関数だとinto的なことができないので自作
    fn chunks( ary:Vec<SerializedEvtxRecord<String>>, size: i32 ) -> Vec<Vec<SerializedEvtxRecord<String>>> {
        let arylen = ary.len();
        let mut ite = ary.into_iter();
    
        let mut ret = vec![];
        for i in 0..arylen as i32  {
            if i % size == 0 {
                ret.push(vec![]);
                ret.iter_mut().last().unwrap().push(ite.next().unwrap());
            } else{
                ret.iter_mut().last().unwrap().push(ite.next().unwrap());
            }
        }

        return ret;
    }
}
