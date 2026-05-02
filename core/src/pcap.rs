use std::convert::TryInto;

#[derive(Clone, Copy)]
pub enum Endianness { Little, Big }
impl Endianness {
    pub fn read_u32(self, bytes: &[u8]) -> u32 { let a:[u8;4]=bytes[..4].try_into().unwrap(); match self { Self::Little=>u32::from_le_bytes(a), Self::Big=>u32::from_be_bytes(a) } }
    pub fn read_i32(self, bytes: &[u8]) -> i32 { let a:[u8;4]=bytes[..4].try_into().unwrap(); match self { Self::Little=>i32::from_le_bytes(a), Self::Big=>i32::from_be_bytes(a) } }
}

pub struct PcapHeaderInfo { pub endianness: Endianness, pub resolution: u64, pub timezone_offset: i32, pub linktype: u32, pub _snaplen: u32 }

pub fn parse_pcap_header(data: &[u8]) -> Result<(PcapHeaderInfo, usize), String> {
 if data.len()<24 { return Err("PCAP data is too short".to_string()); }
 let magic=u32::from_le_bytes(data[0..4].try_into().unwrap());
 let (endianness,resolution)=match magic {0xA1B2_C3D4=>(Endianness::Little,1_000_000),0xA1B2_3C4D=>(Endianness::Little,1_000_000_000),0xD4C3_B2A1=>(Endianness::Big,1_000_000),0x4D3C_B2A1=>(Endianness::Big,1_000_000_000), _=>return Err("Unrecognized PCAP header".to_string())};
 let thiszone=endianness.read_i32(&data[8..12]); let snaplen=endianness.read_u32(&data[16..20]); let linktype=endianness.read_u32(&data[20..24]);
 Ok((PcapHeaderInfo{endianness,resolution,timezone_offset:thiszone,linktype,_snaplen:snaplen},24))
}
