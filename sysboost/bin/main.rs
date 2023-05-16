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

use daemonize::Daemonize;
use std::env;
use basic::logger::{self};
use log::{self};

const APP_NAME: &str = "sysboostd";

fn main() {
	let args: Vec<String> = env::args().collect();
	let argc = args.len();

	logger::init_log(APP_NAME, log::LevelFilter::Info, "syslog", None);
	log::info!("{} running", APP_NAME);

	if argc != 1 {
		// arg0 is program name, parameter is from arg1
		let cur_arg = 1;

		if args[cur_arg] == "-debug" {
			logger::init_log_to_console(APP_NAME, log::LevelFilter::Debug);
		} else if args[cur_arg] == "-daemon" {
			let daemonize = Daemonize::new();
			match daemonize.start() {
				Ok(_) => log::info!("Sysboost Start On Daemon"),
				Err(e) => {
					log::error!("Error, {}", e);
					return;
				}
			}
		}
	}

	// daemon service gen rto ELF with config
	daemon_loop();
}
