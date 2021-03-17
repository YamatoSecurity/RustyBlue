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

use std::{collections::BTreeMap, convert::TryInto};
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

    // fn serialize_Evtx_record( mut parser: EvtxParser<std::fs::File> ) -> Vec<event::Evtx> {
    //     let records:Vec<SerializedEvtxRecord<String>> = parser.records().filter_map(|r| {
    //         if r.is_err() {
    //             eprintln!("{}", r.unwrap_err());
    //             return Option::None;
    //         } else {
    //             return Option::Some(r.unwrap());
    //         }
    //     }).collect();
        
    //     let threadpool = ThreadPool::new(configs::get_thread_num().try_into().unwrap());
    //     let job_num = records.len();
    //     let (tx, rx) = channel();

    //     let tx = tx.clone();

    //     // ここのfor文をforeach()で書くとなぜかエラーになる....よく分からない
    //     for records_per_job in records {
    //         let tx = tx.clone();
    //         threadpool.execute( move|| {
    //             let res = quick_xml::de::from_str(&records_per_job.data);
    //             tx.send(res.unwrap());
    //         });            
    //     }

    //     let mut ret = vec![];
    //     rx.iter().take(job_num).for_each(|serialized_records:event::Evtx|{
    //         ret.push(serialized_records);
    //     });
    //     return ret;
    // }

    fn chunks( &mut self, ary:Vec<SerializedEvtxRecord<String>>, size: i32 ) -> Vec<Vec<SerializedEvtxRecord<String>>> {
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
/* 
    fn serialize_Evtx_record(&mut self, mut parser: EvtxParser<std::fs::File> ) -> Vec<event::Evtx> {
        let records_per_jobs:Vec<Vec<SerializedEvtxRecord<String>>> = vec![];
        let records:Vec<SerializedEvtxRecord<String>> = parser.records().filter_map(|r| {
            if r.is_err() {
                eprintln!("{}", r.unwrap_err());
                return Option::None;
            } else {
                return Option::Some(r.unwrap());
            }
        }).collect();
        
        
        let records_per_jobs:Vec<Vec<SerializedEvtxRecord<String>>> = self.chunks(records,RECORD_LEN_PER_THREAD);

        // 非同期処理はここを見る 
        // https://tech-blog.optim.co.jp/entry/2019/11/08/163000#Rust-139-1
        // https://tech.uzabase.com/entry/2019/09/17/193206
        // https://blog.ymgyt.io/entry/mini_redis_tutorial_to_get_started_with_tokio#await%E3%81%AE%E3%83%A1%E3%83%B3%E3%82%BF%E3%83%AB%E3%83%A2%E3%83%87%E3%83%AB


        // let threadpool = ThreadPool::new(configs::get_thread_num().try_into().unwrap());
        // let job_num = records_per_jobs.len();
        // let (tx, rx) = channel();

        // let tx = tx.clone();

        // // ここのfor文をforeach()で書くとなぜかエラーになる....よく分からない
        // for records_per_job in records_per_jobs {
        //     let tx = tx.clone();
        //     threadpool.execute( move|| {
        //         let serialized_records:Vec<event::Evtx> = records_per_job.iter().filter_map(|r|{
        //             let serialized_result:Result<event::Evtx,DeError> = quick_xml::de::from_str(&r.data);
        //             if serialized_result.is_err() {
        //                 return Option::None;
        //             }else {
        //                 return Option::Some(serialized_result.unwrap());
        //             }
        //         }).collect();
        //         tx.send(serialized_records).expect("");
        //     });            
        // }

        // let mut ret = vec![];
        // rx.iter().take(job_num).for_each(|serialized_records|{
        //     serialized_records.into_iter().for_each(|serialized_record| ret.push(serialized_record));
        // });
        // return ret;
    } */

    pub fn start(&mut self, mut parser: EvtxParser<std::fs::File>) -> Result<(), DeError> {
        let mut common: common::Common = common::Common::new();
        let mut security = security::Security::new();
        let mut system = system::System::new();
        let mut application = application::Application::new();
        let mut applocker = applocker::AppLocker::new();
        let mut sysmon = sysmon::Sysmon::new();
        let mut powershell = powershell::PowerShell::new();

        for record in parser.records() {
            match record {
                Ok(r) => {
                    match quick_xml::de::from_str(&r.data) {
                        Ok(event) => {
                            let event: event::Evtx = event;

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
                            } else {
                                //&other.detection();
                            }
                        }
                        Err(err) => println!("{}", err),
                    }
                }
                Err(e) => eprintln!("{}", e),
            }
        }

        ////////////////////////////
        // 表示
        ////////////////////////////
        common.disp();
        security.disp();

        return Ok(());
    }
}
