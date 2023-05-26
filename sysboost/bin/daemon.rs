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

use inotify::{EventMask, Inotify, WatchMask};
use log::{self};
use serde::Deserialize;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs as UnixFs;
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

const SYSBOOST_PATH: &str = "/usr/bin/sysboost";
const SYSBOOST_DB_PATH: &str = "/var/lib/sysboost/";
const KO_PATH: &str = "/lib/modules/sysboost/binfmt_rto.ko";
const KO_RTO_PARAM_PATH: &str = "/sys/module/binfmt_rto/parameters/use_rto";

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

fn is_symlink(path: &PathBuf) -> bool {
	let file_type = match fs::symlink_metadata(path) {
		Ok(metadata) => metadata.file_type(),
		Err(_) => {
			log::error!("get file type fail: {:?}", path.file_name());
			return false;
		}
	};

	return file_type.is_symlink();
}

fn db_add_link(path: &String) -> i32 {
	// symlink app.link to app
	let file_name = Path::new(path).file_name().unwrap().to_str().unwrap();
	let link_path = format!("{}{}.link", SYSBOOST_DB_PATH, file_name);
	let ret_e = UnixFs::symlink(&path, &link_path);
	match ret_e {
		Ok(_) => {}
		Err(_) => {
			log::error!("symlink fail {}", link_path);
			return -1;
		}
	};

	return 0;
}

fn db_remove_link(path: &String) {
	let ret = fs::remove_file(&path);
	match ret {
		Ok(_) => return,
		Err(e) => {
			log::error!("remove link fail: {}", e);
		}
	};
}

fn run_child(cmd: &str, args: &Vec<String>) -> i32 {
	log::info!("run child: {}, {}", cmd, args.join(" ").to_string());
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

	for line in reader.lines() {
		let line = line.unwrap_or_else(|_| "<read error>".to_owned());
		log::info!("output: {}", line);
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

	if exit_code != 0 {
		log::error!("Command exited with code: {}", exit_code);
	}

	exit_code
}

// echo 1 > /sys/module/binfmt_rto/parameters/use_rto
fn set_ko_rto_flag(is_set: bool) -> i32 {
	let mut args: Vec<String> = Vec::new();
	if is_set {
		args.push("1".to_string());
	} else {
		args.push("0".to_string());
	}
	args.push(">".to_string());
	args.push(KO_RTO_PARAM_PATH.to_string());
	let ret = run_child("/usr/bin/echo", &args);
	return ret;
}

fn gen_app_rto(conf: &RtoConfig) -> i32 {
	let mut args: Vec<String> = Vec::new();
	let arg_mode = format!("-{}", conf.mode);
	args.push(arg_mode);
	args.push(conf.elf_path.to_owned());
	args.push(conf.libs.as_ref().unwrap_or(&String::from("")).split_whitespace().collect());
	return run_child(SYSBOOST_PATH, &args);
}

fn set_app_aot_flag(old_path: &String, is_set: bool) -> i32 {
	let mut args: Vec<String> = Vec::new();
	if is_set {
		args.push("-set".to_string());
	} else {
		args.push("-unset".to_string());
	}
	let old_path = Path::new(old_path);
	let old_path = match fs::canonicalize(old_path) {
		Ok(p) => p,
		Err(e) => {
			log::error!("get realpath failed: {}", e);
			return -1;
		}
	};
	let new_path = old_path.with_extension("bak");
	match fs::copy(&old_path, &new_path) {
		Ok(_) => {}
		Err(e) => {
			log::error!("Copy failed: {}", e);
			return -1;
		}
	}
	args.push(new_path.to_str().unwrap().to_string());
	let ret = run_child(SYSBOOST_PATH, &args);
	match fs::rename(&new_path, &old_path) {
		Ok(_) => {}
		Err(e) => {
			log::error!("Mv failed: {}", e);
			return -1;
		}
	}
	return ret;
}

// elf_path = "/usr/bin/bash"
// mode = "static"
// libs = "/usr/lib64/libtinfo.so.6"
fn parse_config(contents: String) -> Option<RtoConfig> {
	let conf_e = contents.parse::<RtoConfig>();
	match conf_e {
		Ok(ref c) => log::info!("parse config: {:?}", c),
		Err(_) => {
			log::error!("parse config fail");
			return None;
		}
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

fn read_config(path: &PathBuf) -> Option<RtoConfig> {
	let ext = path.extension();
	if ext == None || ext.unwrap() != "toml" {
		return None;
	}

	let contents = match fs::read_to_string(path) {
		Ok(c) => c,
		Err(e) => {
			log::error!("reading file fail {}", e);
			return None;
		}
	};
	return parse_config(contents);
}

fn process_config(path: PathBuf) -> Option<RtoConfig> {
	let conf_e = read_config(&path);
	let mut conf = match conf_e {
		Some(conf) => conf,
		None => return None,
	};

	let ret = gen_app_rto(&conf);
	if ret != 0 {
		return None;
	}

	let ret = db_add_link(&conf.elf_path);
	if ret != 0 {
		return None;
	}

	let ret = set_app_aot_flag(&conf.elf_path, true);
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
		Err(e) => {
			log::error!("{}", e);
			return;
		}
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
			log::error!("too many boost program");
			break;
		}
		let ret = process_config(path);
		match ret {
			Some(conf) => rto_configs.push(conf),
			None => {}
		}
		log::error!("refresh all config {}", i);
		i += 1;
	}

	if rto_configs.len() > 0 {
		set_ko_rto_flag(true);
	}
}

fn clean_last_rto() {
	// all link, need unset flag
	let dir_e = fs::read_dir(&Path::new(SYSBOOST_DB_PATH));
	let dir = match dir_e {
		Ok(dir) => dir,
		Err(e) => {
			log::error!("{}", e);
			return;
		}
	};

	for entry in dir {
		let entry = entry.ok().unwrap();
		let path = entry.path();
		if path.is_dir() {
			continue;
		}
		if path.file_name() == None {
			continue;
		}
		if is_symlink(&path) == false {
			continue;
		}
		let file_name = path.file_name().unwrap();
		let p = format!("{}{}", SYSBOOST_DB_PATH, file_name.to_string_lossy());
		set_app_aot_flag(&p, false);
		db_remove_link(&p);
	}
}

fn watch_old_elf_files_perapp(conf: &RtoConfig, inotify: &mut Inotify) {
	for entry in &conf.watch_paths {
		let file_path = Path::new(entry);
		match inotify.add_watch(file_path, WatchMask::MODIFY) {
			Ok(_) => {}
			Err(e) => {
				log::error!("add_watch fail {}", e);
			}
		};
	}
}

fn watch_old_elf_files(rto_configs: &Vec<RtoConfig>) -> Inotify {
	// init fail exit program
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
			log::info!("File modified: {:?}", event);
			// The name field is present only when watch dir
			// https://man7.org/linux/man-pages/man7/inotify.7.html
			return true;
		}
	}
	return false;
}

fn start_service() {
	set_ko_rto_flag(false);
	clean_last_rto();

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

fn insmod_ko(path: &String) {
	let mut args: Vec<String> = Vec::new();
	args.push(path.to_string());
	run_child("/usr/sbin/insmod", &args);
}

pub fn daemon_loop() {
	insmod_ko(&KO_PATH.to_string());

	loop {
		start_service();
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use basic::logger::{self};

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
		// let canonical_path = fs::canonicalize(file_path).expect("fail");
		// println!("{} -- {}", file_path.display(), canonical_path.to_str().unwrap());
		elf_inotify.add_watch(file_path, WatchMask::MODIFY).expect("Failed to add watch.");

		// modity it, touch can not trigger evnet
		Command::new("bash").arg("-c").arg("echo 1 >> xxx.log").spawn().expect("Fail to run cmd");

		// wait modify happen
		thread::sleep(Duration::from_secs(1));

		let is_elf_modify = check_elf_files_modify(&mut elf_inotify);
		assert_eq!(is_elf_modify, true);
	}

	#[test]
	fn test_run_child() {
		logger::init_log("APP_NAME", log::LevelFilter::Info, "syslog", None);

		let cmd = "ls";
		let args = vec!["-l".to_owned(), ".".to_owned()];
		let exit_code = run_child(cmd, &args);

		assert_eq!(exit_code, 0);
	}
}
