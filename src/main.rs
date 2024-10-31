//use sysinfo::{
//    System,
//};
use std::str::FromStr;
use std::net::IpAddr;
use regex::Regex;
use reqwest::blocking::Client;
use anyhow::Result;
use mysql::*;
use mysql::prelude::*;


#[derive(Debug)]
struct NginxStatus {
    active_connections: u16,
    accepted_connections: u64,
    handled_connections: u64,
    total_requests: u64,
    reading: u32,
    writing: u32,
    waiting: u32
}


#[derive(Debug)]
struct NginxAccessLog {
    remote_addr: IpAddr,
    remote_user: Option<String>,
    time_local: String,
    request_method: String,
    request_uri: String,
    status: u16,
    body_bytes_sent: u32,
    request_time: f64,
    http_referer: Option<String>,
    http_user_agent: Option<String>,
    http_x_forwarded_for: Option<String>,
}

#[derive(Debug)]
struct user {
    email: String
}


fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let url = "https://dev01.firewalls.com/nginx_status";
    let res = fetch_url(&url);
    let body = match res {
        Ok(b) => b,
        Err(e) => format!("error: {e}")
    };

    //println!("{:#?}", body);
    //let mut buffer: Vec<String> = vec![];

    let log = r#"IP: 127.0.0.1 - User: - - Time: [27/Oct/2024:10:52:44 -0400] - Method: GET - URI: /health_check.php - Status: 200 - Bytes Sent: 5 - Request Time: 0.012 - Referer: "-" - User Agent: "-" - Forwarded For: "-""#;

    let res = NginxAccessLog::process_log_entry(log);
    match res {
        Ok(Some(parsed_log)) => {
            println!("Looks good {:#?}", parsed_log);
        },
        Ok(None) => {
            eprintln!("Looks bad");
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    };

    let url = "mysql://root:password@localhost:3306/cre";
    let pool = Pool::new(url)?;

    let mut conn = pool.get_conn()?;

    let u: user = user{email: String::from("adfjh@crepipeline.com")};

    let user_email = conn
        .query_map(
            "SELECT email FROM users LIMIT 1",
            |email| {
                user{email}
            }
        )?;

    println!("User email: {:#?}", user_email);
    Ok(())
}


fn fetch_url(url: &str) -> Result<String> {
    let client = Client::new();
    let res = client.get(url).send()?;
    if !res.status().is_success() {
        return Err(anyhow::anyhow!("Failed with status: {}", res.status()));
    }

    let body = res.text()?;
    Ok(body)
}

impl TryFrom<&str> for NginxStatus {

    type Error = String;

    fn try_from(line: &str) -> Result<Self, Self::Error> {
        let stuff: Vec<u64> = line
            .split_whitespace()
            .filter_map(|token| token.parse::<u64>().ok())
            .collect();
        for element in &stuff {
            println!("{}", element);
        }

        Ok(NginxStatus {
            active_connections: stuff[0] as u16,
            accepted_connections: stuff[1] as u64,
            handled_connections: stuff[2] as u64,
            total_requests: stuff[3] as u64,
            reading: stuff[4] as u32,
            writing: stuff[5] as u32,
            waiting: stuff[6] as u32
        })

    }

}

impl NginxAccessLog {
    fn process_log_entry(log: &str) -> Result<Option<NginxAccessLog>, String> {

        match NginxAccessLog::try_from(log) {
            Ok(parsed_log) => Ok(Some(parsed_log)),
            Err(e) => {
                eprintln!("Parse Error: {}\nLog: {}", e, log);
                Ok(None)
            }
        }
    }
}

impl TryFrom<&str> for NginxAccessLog {
    type Error = String;

    fn try_from(line: &str) -> Result<Self, Self::Error> {

        let log_pattern = Regex::new(r#"IP: (?P<remote_addr>[^\s]+) - User: (?P<remote_user>[^\s]+) - Time: \[(?P<time_local>[^\]]+)\] - Method: (?P<request_method>\w+) - URI: (?P<request_uri>[^\s]+) - Status: (?P<status>\d{3}) - Bytes Sent: (?P<body_bytes_sent>\d+) - Request Time: (?P<request_time>[^\s]+) - Referer: "(?P<http_referer>[^"]+)" - User Agent: "(?P<http_user_agent>[^"]+)" - Forwarded For: "(?P<http_x_forwarded_for>[^"]+)""#).map_err(|e| e.to_string())?;

        let captures = log_pattern.captures(line).ok_or("Log Entry Doesn't match regex pattern")?;

        Ok(NginxAccessLog {
            remote_addr: captures["remote_addr"]
                .parse()
                .map_err(|e| format!("Invalid ip addr : {}", e))?,
            remote_user: if &captures["remote_user"] == "-" {
                None
            } else {
                Some(captures["remote_user"].to_string())
            },
            time_local: captures["time_local"].to_string(),
            request_method: captures["request_method"]
                .parse()
                .map_err(|e| format!("Invalid request method: {}", e))?,
            request_uri: captures["request_uri"].to_string(),
            status: captures["status"]
                .parse()
                .map_err(|e| format!("Invalid status code: {}", e))?,
            body_bytes_sent: captures["body_bytes_sent"]
                .parse()
                .map_err(|e| format!("Invalid body bytes send: {}", e))?,
            request_time: captures["request_time"]
                .parse()
                .map_err(|e| format!("Invalid request time: {}", e))?,
            http_referer: if &captures["http_referer"] == "-" {
                None
            } else {
                Some(captures["http_referer"].to_string())
            },

            http_user_agent: if &captures["http_user_agent"]  == "-"{
                None
            } else {
                Some(captures["http_user_agent"].to_string())
            },
            http_x_forwarded_for: if &captures["http_x_forwarded_for"] == "-" {
                None
            } else {
                Some(captures["http_x_forwarded_for"].to_string())
            },
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn _try_from() {
        let log = r#"IP: 127.0.0.1 - User: - - Time: [27/Oct/2024:10:52:44 -0400] - Method: GET - URI: /health_check.php - Status: 200 - Bytes Sent: 5 - Request Time: 0.012 - Referer: "-" - User Agent: "-" - Forwarded For: "-""#;

        let res = NginxAccessLog::try_from(log);

        assert!(res.is_ok());

        let p_log = res.unwrap();
        assert_eq!(p_log.remote_addr.to_string(), "127.0.0.1");
        assert_eq!(p_log.remote_user, None);
        assert_eq!(p_log.time_local, "27/Oct/2024:10:52:44 -0400");
        assert_eq!(p_log.request_method, "GET");
        assert_eq!(p_log.request_uri, "/health_check.php");
        assert_eq!(p_log.status, 200);
        assert_eq!(p_log.body_bytes_sent, 5);
        assert_eq!(p_log.request_time, 0.012);
        assert_eq!(p_log.http_referer, None);
        assert_eq!(p_log.http_user_agent, None);
        assert_eq!(p_log.http_x_forwarded_for, None);
    }
}
