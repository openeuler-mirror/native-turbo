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

mod daemon;

use crate::daemon::daemon_loop;

use basic::logger::{self};
use daemonize::Daemonize;
use log::{self};
use std::env;

const APP_NAME: &str = "sysboostd";

fn main() {
	let args: Vec<String> = env::args().collect();
	let argc = args.len();
	let mut mode = "default";

	if argc != 1 {
		// arg0 is program name, parameter is from arg1
		let cur_arg = 1;

		if args[cur_arg] == "-debug" {
			mode = "debug";
		} else if args[cur_arg] == "-daemon" {
			mode = "daemon";
		}
	}

	if mode == "debug" {
		logger::init_log_to_console(APP_NAME, log::LevelFilter::Debug);
	} else {
		logger::init_log(APP_NAME, log::LevelFilter::Info, "syslog", None);
	}
	log::info!("{} running", APP_NAME);

	if mode == "daemon" {
		let daemonize = Daemonize::new();
		match daemonize.start() {
			Ok(_) => log::info!("Sysboost Start On Daemon"),
			Err(e) => {
				log::error!("Error, {}", e);
				return;
			}
		}
	}

	// daemon service gen rto ELF with config
	daemon_loop();
}
