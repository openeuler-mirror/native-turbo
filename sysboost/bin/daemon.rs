// Copyright (c) 2023 Huawei Technologies Co., Ltd.
// sysboost is licensed under the Mulan PSL v2.
// You can use this software according to the terms and conditions of the Mulan PSL v2.
// You may obtain a copy of Mulan PSL v2 at:
//     http://license.coscl.org.cn/MulanPSL2
// THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
// PURPOSE.
// See the Mulan PSL v2 for more details.
// Create: 2023-4-20

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::process::{Command, Stdio};
use serde::Deserialize;
use std::thread;
use std::time::Duration;
use inotify::{EventMask, Inotify, WatchMask};
use log::{self};
use std::io::{BufReader, BufRead};

const SYSBOOST_PATH: &str = "/usr/bin/sysboost";

// sleep some time wait for next event
const MIN_SLEEP_TIME: u64 = 10;

// only 10 program can use boost
const MAX_BOOST_PROGRAM: u32 = 10;

#[derive(Debug, Deserialize)]
pub struct RtoConfig {
	pub elf_path: String,
	pub mode: String,
	pub libs: Option<String>,

	#[serde(skip)]
	watch_paths: Vec<String>,
}

impl FromStr for RtoConfig {
	type Err = toml::de::Error;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		toml::from_str(s)
	}
}

fn run_child(cmd: &str, args: &Vec<String>) -> i32 {
    let mut child = match Command::new(cmd).args(args).stdout(Stdio::piped()).spawn() {
        Ok(child) => child,
        Err(e) => {
            log::error!("Failed to execute command: {}", e);
            return -1;
        }
    };
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            log::error!("Failed to capture stdout");
            return -1;
        }
    };
    let reader = BufReader::new(stdout);

    // Record the command output to the system log
    for line in reader.lines() {
        let line = line.unwrap_or_else(|_| "<read error>".to_owned());
        log::info!("{}: {}", cmd, line);
    }

    let status = match child.wait() {
        Ok(status) => status,
        Err(e) => {
            log::error!("Failed to wait on child: {}", e);
            return -1;
        }
    };

    let exit_code = match status.code() {
        Some(code) => code,
        None => {
            log::error!("Terminated by signal");
            return -1;
        }
    };

    // If the subprocess fails to exit, record the error information in the system log
    if exit_code != 0 {
        log::error!("Command exited with code: {}", exit_code);
    }

    exit_code
}

fn gen_app_rto(conf: &RtoConfig) -> i32 {
	let mut args: Vec<String> = Vec::new();
	let arg_mode = format!("-{}", conf.mode);
	args.push(arg_mode);
	args.push(conf.elf_path.to_owned());
	args.push(conf.libs.as_ref().unwrap_or(&String::from("")).split_whitespace().collect());
	return run_child(SYSBOOST_PATH, &args);
}

fn set_app_aot_flag(old_path: &String) -> i32 {
	let mut args: Vec<String> = Vec::new();
	args.push("-set".to_string());
	args.push(old_path.to_string());
	return run_child(SYSBOOST_PATH, &args);
}

// elf_path = "/usr/bin/bash"
// mode = "static"
// libs = "/usr/lib64/libtinfo.so.6"
fn parse_config(contents: String) -> Option<RtoConfig> {
	println!("config contents:\n{}", contents);
	let conf_e = contents.parse::<RtoConfig>();
	match conf_e {
		Ok(ref c) => println!("parse config: {:?}", c),
		Err(_) => { println!("parse config fail"); return None; }
	};

	let conf = conf_e.unwrap();
	if conf.mode != "static" && conf.mode != "share" {
		return None;
	}
	if conf.elf_path == SYSBOOST_PATH {
		// the tool can not renew self code
		return None;
	}

	return Some(conf);
}

fn read_config(path: PathBuf) -> Option<RtoConfig> {
	let ext = path.extension();
	if ext == None || ext.unwrap() != "toml" {
		//println!("not end with .toml: {}", path.display());
		return None;
	}

	let contents = fs::read_to_string(path).expect("Something went wrong reading the file");
	return parse_config(contents);
}

fn process_config(path: PathBuf) -> Option<RtoConfig> {
	let conf_e = read_config(path);
	let mut conf = match conf_e {
		Some(conf) => conf,
		None => return None,
	};

	let ret = gen_app_rto(&conf);
	if ret != 0 {
		return None;
	}

	let ret = set_app_aot_flag(&conf.elf_path);
	if ret != 0 {
		return None;
	}

	// add elf file to watch list
	conf.watch_paths.push(conf.elf_path.clone());
	conf.watch_paths.push(conf.libs.as_ref().unwrap_or(&String::from("")).split_whitespace().collect());
	// TODO: feature, auto get deps
	// TODO: feature, PATH may change libs

	return Some(conf);
}

fn refresh_all_config(rto_configs: &mut Vec<RtoConfig>) {
	// read configs /etc/sysboost.d, like bash.toml
	let dir_e = fs::read_dir(&Path::new("/etc/sysboost.d"));
	let dir = match dir_e {
		Ok(dir) => dir,
		Err(_) => return
	};

	let mut i = 0;
	for entry in dir {
		let entry = entry.ok().unwrap();
		let path = entry.path();
		if path.is_dir() {
			continue;
		}
		if path.file_name() == None {
			continue;
		}

		if i == MAX_BOOST_PROGRAM {
			println!("too many boost program");
			break;
		}
		let ret = process_config(path);
		match ret {
			Some(conf) => rto_configs.push(conf),
			None => {},
		}
		i += 1;
	}
}

fn watch_old_elf_files_perapp(conf: &RtoConfig, inotify: &mut Inotify) {
	for entry in &conf.watch_paths {
		let file_path = Path::new(entry);
		inotify.add_watch(file_path, WatchMask::MODIFY).expect("Failed to add watch.");
	}
}

fn watch_old_elf_files(rto_configs: &Vec<RtoConfig>) -> Inotify {
	let mut inotify = Inotify::init().expect("Failed to init inotify.");
	for entry in rto_configs {
		watch_old_elf_files_perapp(&entry, &mut inotify);
	}
	return inotify;
}

fn check_elf_files_modify(inotify: &mut Inotify) -> bool {
	let mut buffer = [0u8; 4096];
	let events = match inotify.read_events(&mut buffer) {
		Ok(events) => events,
		Err(_) => return false,
	};

        for event in events {
		if event.mask.contains(EventMask::MODIFY) {
			println!("File modified: {:?}", event);
			// The name field is present only when watch dir
			// https://man7.org/linux/man-pages/man7/inotify.7.html
			return true;
		}
        }
	return false;
}

fn start_service() {
	let mut rto_configs: Vec<RtoConfig> = Vec::new();
	refresh_all_config(&mut rto_configs);
	let mut elf_inotify = watch_old_elf_files(&rto_configs);

	loop {
		// wait some time
		thread::sleep(Duration::from_secs(MIN_SLEEP_TIME));

		// do not support config dynamic modify, need restart service
		// TODO: feature, check config file modify

		// check ELF modify, renew rto
		let is_elf_modify = check_elf_files_modify(&mut elf_inotify);
		if is_elf_modify == true {
			return;
		}
	}
}

pub fn daemon_loop() {
	println!("daemon_loop");
	loop {
		start_service();
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_check_elf_files_modify_1() {
		let mut elf_inotify = Inotify::init().expect("Failed to init inotify.");

		// create file, link to it
		Command::new("/usr/bin/touch").arg("xxx.log").spawn().expect("Fail to run cmd");

		// watch it
		let file_path = Path::new("xxx.log");
		elf_inotify.add_watch(file_path, WatchMask::MODIFY).expect("Failed to add watch.");

		// modity it, touch can not trigger evnet
		Command::new("bash").arg("-c").arg("echo 1 >> xxx.log").spawn().expect("Fail to run cmd");

		// wait modify happen
		thread::sleep(Duration::from_secs(1));

		let is_elf_modify = check_elf_files_modify(&mut elf_inotify);
		assert_eq!(is_elf_modify, true);
	}

	#[test]
	fn test_check_elf_files_modify_2() {
		let mut elf_inotify = Inotify::init().expect("Failed to init inotify.");

		// create file, link to it
		Command::new("/usr/bin/touch").arg("xxx.log").spawn().expect("Fail to run cmd");
		std::mem::forget(UnixFs::symlink("xxx.log", "xxx.link"));

		// watch link file
		let file_path = Path::new("xxx.link");
		//let canonical_path = fs::canonicalize(file_path).expect("fail");
		//println!("{} -- {}", file_path.display(), canonical_path.to_str().unwrap());
		elf_inotify.add_watch(file_path, WatchMask::MODIFY).expect("Failed to add watch.");

		// modity it, touch can not trigger evnet
		Command::new("bash").arg("-c").arg("echo 1 >> xxx.log").spawn().expect("Fail to run cmd");

		// wait modify happen
		thread::sleep(Duration::from_secs(1));

		let is_elf_modify = check_elf_files_modify(&mut elf_inotify);
		assert_eq!(is_elf_modify, true);
	}
}
