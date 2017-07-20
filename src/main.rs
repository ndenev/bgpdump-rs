#[macro_use]
extern crate nom;
extern crate chrono;
extern crate memmap;

use memmap::{Mmap, Protection};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::io::{self, BufReader};
use std::io::prelude::*;
use std::fs::File;
use chrono::prelude::*;
use nom::{IResult, be_u8, be_u16, be_u32, Needed, FileProducer};

// const BUF_SIZE: usize = 1024;
// const BGP_DUMP: &'static str = "/Users/nikolay/Downloads/route-collector.summary.pch.net-mrt-bgp-updates-2015-10-07-23-51";
// const BGP_DUMP: &'static str = "/Users/nikolay/rib";
const BGP_DUMP: &'static str = "/Users/nikolay/Downloads/bview.20020722.2337";

fn main() {

    let mrt_dump_file = Mmap::open_path(BGP_DUMP, Protection::Read).expect("Unable to mmap file");
    println!("XXX: MMAP SIZE: {}", mrt_dump_file.len());
    let mrt_dump_bytes: &[u8] = unsafe { mrt_dump_file.as_slice() };
    let mrt_dump = MrtDump::new(mrt_dump_bytes);
    for record in mrt_dump.into_iter() {
        println!("{:?}", record);
    }
    println!("Done!");
}

struct MrtDump<'a> {
    buffer: &'a [u8],
}
impl<'a> MrtDump<'a> {
    fn new(byte_slice: &'a [u8]) -> MrtDump {
        MrtDump { buffer: byte_slice }
    }
}
impl<'a> IntoIterator for MrtDump<'a> {
    type Item = MrtRecord;
    type IntoIter = MrtDumpIterator<'a>;
    fn into_iter(self) -> Self::IntoIter {
        MrtDumpIterator {
            inner: self,
            index: 0,
        }
    }
}

struct MrtDumpIterator<'a> {
    inner: MrtDump<'a>,
    index: usize,
}
impl<'a> Iterator for MrtDumpIterator<'a> {
    type Item = MrtRecord;
    fn next(&mut self) -> Option<MrtRecord> {
        match parse_record(self.inner.buffer) {
            IResult::Done(i, r) => {
                self.inner.buffer = i;
                self.index += 1;
                Some(r)
            }
            IResult::Error(e) => {
                panic!("Error parsing: {:?}", e);
            }
            IResult::Incomplete(_) => None,
        }
    }
}

#[derive(Debug)]
pub enum TableDumpSubtype {
    AFI_IPv4,
    AFI_IPv6,
}

#[derive(Debug)]
pub enum TableDumpV2Subtype {
    PeerIndexTable,
    RibIpv4Unicast,
    RibIpv4Multicast,
    RibIpv6Unicast,
    RibIpv6Multicast,
    RibGeneric,
}

#[derive(Debug)]
pub enum Bgp4MpSubtype {
    StateChange,
    Message,
    MessageAs4,
    StateChangeAs4,
    MessageLocal,
    MessageAs4Local,
}


#[derive(Debug)]
pub enum MrtRecordType {
    // 11   OSPFv2
    Ospfv2,
    // 12   TABLE_DUMP
    TableDump(TableDumpSubtype),
    // 13   TABLE_DUMP_V2
    TableDumpV2(TableDumpV2Subtype),
    // 16   BGP4MP
    Bgp4Mp(Bgp4MpSubtype),
    // 17   BGP4MP_ET
    Bgp4Mp_ET(Bgp4MpSubtype),
    // 32   ISIS
    Isis,
    // 33   ISIS_ET
    Isis_ET,
    // 48   OSPFv3
    OspfV3,
    // 49   OSPFv3_ET
    OspfV3_ET,
    Unknown,
    Reserved,
}
impl MrtRecordType {
    fn is_et(&self) -> bool {
        match *self {
            MrtRecordType::Bgp4Mp_ET(_) => true,
            MrtRecordType::Isis_ET => true,
            MrtRecordType::OspfV3_ET => true,
            _ => false,
        }
    }
}

impl From<(u16, u16)> for MrtRecordType {
    fn from(t: (u16, u16)) -> MrtRecordType {
        match t.0 {
            11 => MrtRecordType::Ospfv2,
            12 => {
                match t.1 {
                    1 => MrtRecordType::TableDump(TableDumpSubtype::AFI_IPv4),
                    2 => MrtRecordType::TableDump(TableDumpSubtype::AFI_IPv6),
                    _ => MrtRecordType::Unknown,
                }
            }
            13 => {
                match t.1 {
                    1 => MrtRecordType::TableDumpV2(TableDumpV2Subtype::PeerIndexTable),
                    2 => MrtRecordType::TableDumpV2(TableDumpV2Subtype::RibIpv4Unicast),
                    3 => MrtRecordType::TableDumpV2(TableDumpV2Subtype::RibIpv4Multicast),
                    4 => MrtRecordType::TableDumpV2(TableDumpV2Subtype::RibIpv6Unicast),
                    5 => MrtRecordType::TableDumpV2(TableDumpV2Subtype::RibIpv6Multicast),
                    6 => MrtRecordType::TableDumpV2(TableDumpV2Subtype::RibGeneric),
                    _ => MrtRecordType::Unknown,
                }
            }         
            16 => {
                match t.1 {
                    0 => MrtRecordType::Bgp4Mp(Bgp4MpSubtype::StateChange),
                    1 => MrtRecordType::Bgp4Mp(Bgp4MpSubtype::Message),
                    4 => MrtRecordType::Bgp4Mp(Bgp4MpSubtype::MessageAs4),
                    5 => MrtRecordType::Bgp4Mp(Bgp4MpSubtype::StateChangeAs4),
                    6 => MrtRecordType::Bgp4Mp(Bgp4MpSubtype::MessageLocal),
                    7 => MrtRecordType::Bgp4Mp(Bgp4MpSubtype::MessageAs4Local),
                    _ => MrtRecordType::Unknown,
                }
            }
            17 => {
                match t.1 {
                    0 => MrtRecordType::Bgp4Mp_ET(Bgp4MpSubtype::StateChange),
                    1 => MrtRecordType::Bgp4Mp_ET(Bgp4MpSubtype::Message),
                    4 => MrtRecordType::Bgp4Mp_ET(Bgp4MpSubtype::MessageAs4),
                    5 => MrtRecordType::Bgp4Mp_ET(Bgp4MpSubtype::StateChangeAs4),
                    6 => MrtRecordType::Bgp4Mp_ET(Bgp4MpSubtype::MessageLocal),
                    7 => MrtRecordType::Bgp4Mp_ET(Bgp4MpSubtype::MessageAs4Local),
                    _ => MrtRecordType::Unknown,
                }
            }
            32 => MrtRecordType::Isis,
            33 => MrtRecordType::Isis_ET,
            48 => MrtRecordType::OspfV3,
            49 => MrtRecordType::OspfV3_ET,
            _ => MrtRecordType::Reserved,
        }
    }
}


#[derive(Debug)]
pub enum MrtRecordMessage {

}

#[derive(Debug)]
pub struct MrtRecord {
    timestamp: DateTime<Utc>,
    record_type: MrtRecordType,
    // 2 bytes
    // record_subtype: MrtRecordSubtype,
    // record_subtype: u16,
    // 4 bytes
    record_size: u32,
    // microsecond_timestamp: Option<u32>,
    message: TableDumpV4,
}

/*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                           Timestamp                           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |             Type              |            Subtype            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                             Length                            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Message... (variable)
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

named!(parse_record<&[u8], MrtRecord>, do_parse!(
    timestamp: be_u32 >>
    record_type: be_u16 >>
    record_subtype: be_u16 >>
    record_full_type: value!(MrtRecordType::from((record_type, record_subtype))) >>
    record_size: be_u32 >>
    microsecond_timestamp: cond!(record_full_type.is_et(), be_u32) >>
    // message: take!(record_size) >>
    table: call!(parse_tabledump_ipv4) >>
    (MrtRecord {
        timestamp: Utc.timestamp(timestamp as i64, microsecond_timestamp.unwrap_or(0) * 1000),
        record_type: record_full_type,
        record_size: record_size,
        message: table,
    }))
);

#[derive(Debug)]
struct TableDumpV4 {
    view_num: u16,
    seq_num: u16,
    prefix: Ipv4Addr,
    prefix_len: u8,
    originated_time: DateTime<Utc>,
    peer_ip_address: Ipv4Addr,
    peer_as: u16,
    attr_len: u16,
}

named!(parse_tabledump_ipv4<&[u8], TableDumpV4>, do_parse!(
    view_num: be_u16 >>
    seq_num: be_u16 >>
    prefix: be_u32 >>  
    prefix_len: be_u8 >>
    // STATUS field must be 1 in table_dump
    verify!(be_u8, |v| v == 1) >>
    originated_time: be_u32 >>
    peer_ip_address: be_u32 >>
    peer_as: be_u16 >>
    attr_len: be_u16 >>
    attributes: take!(attr_len) >>
    (TableDumpV4{
        view_num: view_num,
        seq_num: seq_num,
        prefix: Ipv4Addr::from(prefix),
        prefix_len: prefix_len,
        originated_time: Utc.timestamp(originated_time as i64, 0),
        peer_ip_address: Ipv4Addr::from(peer_ip_address),
        peer_as: peer_as,
        attr_len: attr_len,
    })
));