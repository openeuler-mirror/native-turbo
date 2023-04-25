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
use serde::Deserialize;
use std::str::FromStr;
use std::process::Command;
use std::os::unix::fs as UnixFs;

// only 10 program can use boost
const MAX_BOOST_PROGRAM: u32 = 10;

#[derive(Debug, Deserialize)]
pub struct RtoConfig {
	pub elf_path: String,
	pub mode: String,
}

impl FromStr for RtoConfig {
	type Err = toml::de::Error;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		toml::from_str(s)
	}
}

fn run_child(conf: &RtoConfig) {
	let arg_mode = format!("-{}", conf.mode);
	let child = Command::new("/usr/bin/sysboost").arg(&arg_mode).arg(&conf.elf_path).spawn();
	match child {
		Ok(_) => {},
		Err(_) => { println!("exec fail"); return; }
	};
	let result = child.unwrap().wait();
	match result {
		Ok(_) => {},
		Err(_) => { println!("exec fail"); return; }
	};

	match result.unwrap().code() {
		Some(ret) => { if ret != 0 { return; } },
		None => println!("Process terminated by signal")
	}
}

fn symlink_app(old_path: &String) {
	// copy app.bak
	let metadata_e = fs::symlink_metadata(old_path);
	match metadata_e {
		Ok(_) => {},
		Err(_) => { println!("get file type fail"); return; }
	};
	let file_type = metadata_e.unwrap().file_type();
	if file_type.is_symlink() == false {
		let bak_path = format!("{}.bak", old_path);
		let ret_e = fs::copy(old_path, bak_path);
		match ret_e {
			Ok(_) => {},
			Err(_) => { println!("backup file fail"); return; }
		};
	}

	// symlink app.link to app.rto
	let new_path = format!("{}.rto", old_path);
	let link_path = format!("{}.link", old_path);
	let ret_e = UnixFs::symlink(&new_path, &link_path);
	match ret_e {
		Ok(_) => {},
		Err(_) => { println!("symlink fail"); return; }
	};

	// atomic move symlink app.link to app
	let ret_e = fs::rename(&link_path, old_path);
	match ret_e {
		Ok(_) => {},
		Err(_) => { println!("symlink move fail"); return; }
	};
}

// elf_path = "/usr/bin/bash"
// mode = "static"
fn parse_config(contents: String) {
	println!("config contents: {}", contents);
	let conf_e = contents.parse::<RtoConfig>();
	match conf_e {
		Ok(_) => {},
		Err(_) => { println!("parse config fail"); return; }
	};

	let conf = conf_e.unwrap();
	if conf.mode != "static" && conf.mode != "share" {
		return;
	}

	run_child(&conf);

	symlink_app(&conf.elf_path);
}

fn read_config(path: PathBuf) {
	let ext = path.extension();
	if ext == None || ext.unwrap() != "toml" {
		//println!("not end with .toml: {}", path.display());
		return;
	}

	let contents = fs::read_to_string(path).expect("Something went wrong reading the file");
	parse_config(contents);
}

pub fn daemon_loop() {
	println!("daemon_loop");

	// read config /etc/sysboost.d  bash.conf
	let dir = fs::read_dir(&Path::new("/etc/sysboost.d"));
	match dir {
		Ok(_) => {},
		Err(_) => return
	};

	let mut i = 0;
	for entry in dir.unwrap() {
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
		read_config(path);
		i += 1;
	}
}
