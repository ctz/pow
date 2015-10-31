
// cli frontend
extern crate rustc_serialize;
extern crate docopt;
use docopt::Docopt;

mod cli;
mod db;
mod crypto;
mod util;

static USAGE: &'static str = "
Usage:
  pow init
  pow passwd
  pow ls
  pow add <name> [<type>]
  pow gen <name> [<type>]
  pow echo <name> [<type>]
  pow rm <name> [<type>]
  pow paste <name> [<type>]
  pow pull
  pow push

Commands:
  pow init			create a new empty database
  pow passwd			change the password for an existing database
  pow ls			list all sites
  pow add <name> [<type>]	add secret for named site
  pow gen <name> [<type>]	generate a new secret for named site then echo it
  pow echo <name> [<type>]	echo secret for named site
  pow rm <name> [<type>]	delete secret for named site
  pow paste <name> [<type>]	put secret for named site on clipboard
  pow pull			download changes to database
  pow push			upload changes to database
";

#[derive(RustcDecodable,Debug)]
struct Args {
  cmd_init: bool,
  cmd_passwd: bool,
  cmd_ls: bool,
  cmd_add: bool,
  cmd_gen: bool,
  cmd_echo: bool,
  cmd_rm: bool,
  cmd_paste: bool,
  cmd_pull: bool,
  cmd_push: bool,
  arg_name: String,
  arg_type: String
}

fn main() {
  let mut args: Args = Docopt::new(USAGE)
    .and_then(|d| d.decode())
    .unwrap_or_else(|e| e.exit());
    
  if args.arg_type.is_empty() {
    args.arg_type = "password".to_string();
  }

  if args.cmd_init {
    cli::init();
  } else if args.cmd_passwd {
    cli::passwd();
  } else if args.cmd_ls {
    cli::ls();
  } else if args.cmd_add {
    cli::add(&args.arg_name, &args.arg_type);
  } else if args.cmd_gen {
    cli::gen(&args.arg_name, &args.arg_type);
  } else if args.cmd_echo {
    cli::echo(&args.arg_name, &args.arg_type);
  } else if args.cmd_rm {
    cli::rm(&args.arg_name, &args.arg_type);
  } else {
    println!("unhandled op {:?} ", args);
  }
}
