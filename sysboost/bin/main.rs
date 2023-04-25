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
use std::env;

fn set_print_log(_printlog: bool) {
	// syslog.New(syslog.LOG_NOTICE, "sysboost")
	// log.SetOutput(des)
	println!("set_print_log");
}

fn set_log_level(_loglevel: u8) {
	// log.SetLevel(loglevel)
}

fn main() {
	let args: Vec<String> = env::args().collect();
	let argc = args.len();

	if argc == 1 {
		println!("nothing to do");
		return;
	}

	// arg0 is program name, parameter is from arg1
	let mut cur_arg = 1;

	if args[cur_arg] == "-debug" {
		set_log_level(8);
		set_print_log(true);
		cur_arg += 1;
	} else {
		set_log_level(7);
	}

	// daemon service gen rto ELF with config
	if args[cur_arg] == "-daemon" {
		daemon_loop();
		return;
	}

	// -static parameter is used to determine whether static file generated
	if args[cur_arg] == "-static" {
		// TODO:
		// "/usr/bin/sysboost_static_template"
		// "/usr/lib64/libtinfo.so"
		println!("static mode");
		cur_arg += 1;
	}

	while cur_arg < argc {
		// TODO:
		println!("arg {}", args[cur_arg]);
		cur_arg += 1;
	}

	println!("OK");
}
