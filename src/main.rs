use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use glob::glob;
use regex::Regex;
use std::collections::HashMap;
use std::io::BufReader;
use std::io::prelude::*;
use std::fs::File;

pub struct Entry {
    protocol: String,
    local:    String,
    remote:   String,
    state:    String,
    inode:    String,
}

impl Entry {
    pub fn new_from(entry_line: Vec<&str>) -> Entry {
        Entry {
            protocol: protocol_translation(&entry_line),
            local:    address_translation(&entry_line, 1),
            remote:   address_translation(&entry_line, 2),
            state:    connection_translation(&entry_line),
            inode:    entry_line[9].to_string(),
        }
    }
}

fn protocol_translation(entry_line: &Vec<&str>) -> String {
    format!("{}", entry_line[entry_line.len() - 1])
}

fn address_translation(entry_line: &Vec<&str>, addr_type: usize) -> String {
    let addr = entry_line[addr_type];
    let address = match addr.len() {
        13 => ipv4_translation(addr),
        37 => ipv6_translation(addr),
        _ => "unknown".to_string(),
    };

    address
}

fn ipv4_translation(address: &str) -> String {
    let addr_port: Vec<&str> = address.split(":").collect();
    let addr = 
        u32::from_str_radix(&addr_port[0], 16).unwrap();
    let swapped = addr.swap_bytes();
    let ipv4 = Ipv4Addr::from(swapped).to_string();
    let port = 
        u16::from_str_radix(&addr_port[1], 16).unwrap();
    format!("{}:{}", ipv4, port)
}

fn ipv6_translation(address: &str) -> String {
    // example entry: 000080FE00000000DCE3A8A94F3E8895:C9D6 =
    // fe80::a9a8:e3dc:9:51670
    let addr_port: Vec<&str> = address.split(":").collect();
    // we need 8 u16 values to form an ipv6 addr
    // we just have this string to work with: 000080FE00000000DCE3A8A94F3E8895
    // we need a u16 of index (6-7 & 4-5)
    let mut u16s: Vec<u16> = Vec::new();
    let mut counter = 0; 
    while counter < 32 {
        let mut tmp_str1 = 
            String::from(&addr_port[0][counter + 6..counter + 8]);
        tmp_str1.push_str(&addr_port[0][counter + 4..counter + 6]);
        u16s.push(u16::from_str_radix(&tmp_str1, 16).unwrap());

        let mut tmp_str2 = 
            String::from(&addr_port[0][counter + 2..counter + 4]);
        tmp_str2.push_str(&addr_port[0][counter..counter + 2]);
        u16s.push(u16::from_str_radix(&tmp_str2, 16).unwrap());

        counter += 8;
    }
    let ipv6_addr = Ipv6Addr::new(
        u16s[0],
        u16s[1],
        u16s[2],
        u16s[3],
        u16s[4],
        u16s[5],
        u16s[6],
        u16s[7],
    );
    let port = 
        u16::from_str_radix(&addr_port[1], 16).unwrap();

    format!("{}:{}", ipv6_addr.to_string(), port)
}

fn connection_translation(entry_line: &Vec<&str>) -> String {
    // if tcp
    if entry_line[entry_line.len() - 1] == "tcp"
     || entry_line[entry_line.len() - 1] == "tcp6" {
        format!("{}", match entry_line[3] {
        // values taken from include/net/tcp_states.h
        "01" => "ESTABLISHED",
        "02" => "SENT",
        "03" => "RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        "0C" => "NEW_SYN_RECV",
        _    => "UNKNOWN",
        })
    } else {
        // if udp we just return empty string
        format!("{}","")
    }
}
fn main() {
    macro_rules! column_headings {() =>
        ("\n\x1B[1m\x1B[3;33m{: <8}\x1B[0m   \x1B[1m\x1B[3;33m{: <32}\x1B[0m   \
        \x1B[1m\x1B[3;33m{: <32}\x1B[0m   \x1B[1m\x1B[3;33m{: <15}\x1B[0m   \
        \x1B[1m\x1B[3;33m{: <15}\x1B[0m")};
    println!(column_headings!(), "type", "local", "remote", "connection", "process");
    let sock_to_proc = create_hashmap();
    process_entries(&sock_to_proc);
    print!("\n");
}

fn create_hashmap() -> HashMap<String,String> {
    let mut paths_to_sockets = HashMap::new();
    let mut paths: Vec<String> = Vec::new();
    // look through every process for those with open fds
    for entry in glob("/proc/[0-9]*/fd/*").unwrap() {
        if let Ok(path) = entry {
            paths.push((path.display()).to_string());
        };
    }
    
    // look through the list of open fds and grab sockets
    let re = Regex::new(r"socket:\[[0-9]+\]").unwrap();
    for i in 0..paths.len() {
        // read the symbolic links of the socket inodes
        let link = fs::read_link(&paths[i]);
        match link {
            Ok(path) => {
                let formatted_link = path.display().to_string();
                if re.is_match(&formatted_link) {
                    // look up the pid associated w the socket fd
                    let proc_name = pid_lookup(&paths[i]);
                    // insert (inode, process_name)
                    paths_to_sockets.insert(formatted_link
                        .replace("socket:[", "")
                        .replace("]",""), 
                        proc_name);
                }
            }
            Err(_e) => (),
        }
    }
    // return hashmap
    paths_to_sockets
}

fn pid_lookup(path: &String) -> String {
    // read the first line of /proc/pid/status to get the process name
    let mut lookup_path: String = path.split("fd").take(1).collect();
    lookup_path.push_str("status");
    
    // just read up until the first newline so we save some time
    // the process name is in the first line
    let f = File::open(lookup_path).unwrap();
    let mut f = BufReader::new(f);
    let mut proc_name: Vec<u8> = vec![];
    f.read_until(b'\n', &mut proc_name).unwrap();
    let proc_name = std::str::from_utf8(&proc_name).unwrap();
    proc_name.replace("Name:\t", "").replace("\n", "")
}

fn process_entries(hashmap: &HashMap<String,String>) {
    // create a vector that contains /proc/net/* entries separated by spaces
    // send them to parser per file
    macro_rules! formatted_print_tcp {() => 
        ("\x1B[1;36m{: <8}\x1B[0m   {: <32}   {: <32}   {: <15}   {: <15}")}
    macro_rules! formatted_print_udp {() => 
        ("\x1B[1;35m{: <8}\x1B[0m   {: <32}   {: <32}   {: <15}   {: <15}")}
    let file_names = vec!["tcp", "udp", "tcp6", "udp6"];
    for i in 0..file_names.len() {
        // for each /proc/net/* file, grab lines that contain entries
        let file_path = format!("/proc/net/{}", file_names[i]);
        let file = fs::read_to_string(file_path).unwrap();
        let entries: Vec<&str> = file.lines()
            .filter(|x| !x.contains("sl"))
            .collect();
        for x in 0..entries.len() {
            let mut separated: Vec<&str> = entries[x].split_whitespace().collect();
            // lets just append the protocol type on the end for ease
            separated.push(file_names[i]);
            let entry = Entry::new_from(separated);
            let process: String;
            if let Some(proc_name) = hashmap.get(&entry.inode) {
                process = proc_name.to_string();
            } else {
                process = String::from("-");
            }
            if entry.protocol == "tcp"
                || entry.protocol == "tcp6" {
                    println!(formatted_print_tcp!(),
                        entry.protocol, entry.local, entry.remote.replace("0.0.0.0:0", "0.0.0.0:*")
                            .replace(":::0", ":::*"), entry.state, process);
                } else {
                    println!(formatted_print_udp!(),
                        entry.protocol, entry.local, entry.remote.replace("0.0.0.0:0", "0.0.0.0:*")
                            .replace(":::0", ":::*"), entry.state, process);
                }
        }
    }
}
