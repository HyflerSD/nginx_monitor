use std::net::IpAddr;
use regex::Regex;
use reqwest::blocking::Client;
use anyhow::Result;
use mysql::*;
use mysql::prelude::*;
use linemux::MuxedLines;
use tokio;
use dotenv::dotenv;
use std::env::{self};

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


#[derive(Debug, Clone)]
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

const BUFFER_SIZE: usize = 150;

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    let db_url = OptsBuilder::new()
        .user(Some(env::var("DB_USER").expect("DB_URL must be set!")))
        .db_name(Some(env::var("DB_NAME").expect("DB_NAME must be set!")))
        .pass(Some(env::var("DB_PASS").expect("DB_PASS must be set!")));
    let pool = Pool::new(db_url)?;

    let mut conn = pool.get_conn()?;
    let created = create_access_log_table(&mut conn);
    match created {
        Ok(good) => println!("{:#?}", good),
        Err(bad) => println!("Bad Message: {:#?}", bad)
    }

    let url = "https://dev01.firewalls.com/nginx_status";
    let res = match fetch_url(&url) {
        Ok(data) => data,
        Err(e) => {
            println!("{:#?}", e);
            e.to_string()
        }
    };
    let mut lines = MuxedLines::new()?;

    lines.add_file("/home/michael/www/fw/access.log").await?;

    let mut buffer: Vec<NginxAccessLog> = vec![];

    while let Ok(Some(line)) = lines.next_line().await {
        let res = NginxAccessLog::process_log_entry(line.line());
        match res {
            Ok(Some(parsed_log)) => {
                if buffer.len() >= BUFFER_SIZE {
                    println!("\nAttempting to Insert {} records\n", buffer.len());
                    let buff_clone = buffer.clone();
                    let _ = insert_logs(buff_clone, &mut conn);
                    println!("Clearing {} items from Buffer", buffer.len());
                    buffer.clear();
                }

                print!("\rBuffer Size: {}", buffer.len());
                use std::io::Write;
                std::io::stdout().flush().unwrap();
                buffer.push(parsed_log);
            },
            Ok(None) => {
                eprintln!("Looks bad");
            }
            Err(e) => {
                eprintln!("Error: {}", e);
            }
        };
    }
    //println!("{:#?}", res);
    Ok(())
}


//fn p<T>(_: &T) {
//    println!("{:?}", std::any::type_name::<T>())
//}

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

fn insert_logs(logs: Vec<NginxAccessLog>, conn: &mut PooledConn) ->Result<(), Error> {

    conn.exec_batch(
        r"INSERT INTO access_logs (
             remote_addr,
             remote_user,
             time_local,
             request_method,
             request_uri,
             status,
             body_bytes_sent,
             request_time,
             http_referer,
             http_user_agent,
             http_x_forwarded_for
        )
        VALUES (
             :remote_addr,
             :remote_user,
             :time_local,
             :request_method,
             :request_uri,
             :status,
             :body_bytes_sent,
             :request_time,
             :http_referer,
             :http_user_agent,
             :http_x_forwarded_for
        )",
        logs.iter().map(|log| params! {
             "remote_addr" => log.remote_addr.to_string(),
             "remote_user" => log.remote_user.clone(),
             "time_local" => log.time_local.clone(),
             "request_method" => log.request_method.clone(),
             "request_uri" => log.request_uri.clone(),
             "status" => log.status,
             "body_bytes_sent" => log.body_bytes_sent,
             "request_time" => log.request_time,
             "http_referer" => log.http_referer.clone(),
             "http_user_agent" => log.http_user_agent.clone(),
             "http_x_forwarded_for" => log.http_x_forwarded_for.clone()
        })
    )?;

    Ok(())
}

fn create_access_log_table(conn: &mut PooledConn) -> Result<String, Error> {
    conn.query_drop(
        "CREATE TABLE IF NOT EXISTS access_logs (
             id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
             remote_addr TEXT NOT NULL, 
             remote_user TEXT,
             time_local TEXT NOT NULL,
             request_method TEXT NOT NULL,
             request_uri TEXT NOT NULL,
             status SMALLINT NOT NULL,
             body_bytes_sent INT NOT NULL,
             request_time DOUBLE NOT NULL,
             http_referer TEXT,
             http_user_agent TEXT,
             http_x_forwarded_for TEXT
        )"
    )?;

    Ok(String::from("Got The table dude!\n"))
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
