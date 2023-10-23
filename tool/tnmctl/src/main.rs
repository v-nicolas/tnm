fn main() {
    const PROGNAME: &str = "tnmctl";
    const NM_TIMEOUT_MIN: i16 = 10;
    const NM_TIMEOUT_MAX: i16 = 20;
    const NM_FREQ_MIN: i16 = 20;
    const NM_FREQ_MAX: i16 = 20;
    print!(
        "{} usage: {} cmd [OPTIONS...]\n
	   Arguments:\n
	     -h, --help      : Show program usage and exit.\n
	     -v, --version   : Show program version and exit.\n
	     -s, --sock-path : Socket unix path to dial with the program.\n
	     -p, --path      : file path (example reload).\n
	   \n
	   Commands:\n
	     -a, --add    : Add new hosts.\n
	     -r, --remove : Remove one host by uuid.\n
	     -l, --list   : List all hosts.\n
	   \n
	   Commands arguments:\n
	     -H, --hostname   : Set hostname.\n
	     -I, --ip         : Set host IP.\n
	     -M, --monit      : Set monitoring type.\n
	     -P, --port       : If monitoring type is port set port value.\n
	     -V, --ip-version : Set IP version.\n
	     -T, --timeout    : Set timeout (min:{} max:{}.\n
	     -F, --frequency  : Set host monitoring frequency (min:{} max:{}).\n
	     -U, --uuid       : Set host UUID.\n
	         --ssl        : Use SSL to monitoring type port && HTTP.\n
	   \n
	   HTTP options:\n
	         --http-method        : Set http method (default: GET).\n
	         --http-version       : Set HTTP protocol version (Default HTTP 1.1).\n
	         --http-path          : Set HTTP path (example: /index.html).\n
	         --http-user-agent    : Set HTTP user agent.\n
	         --http-auth-type     : Set HTTP authentification type (example: Basic or Bearer)\n.
	         --http-auth-value    : Set HTTP authentification value (token or other).\n",
        PROGNAME, PROGNAME, NM_TIMEOUT_MIN, NM_TIMEOUT_MAX, NM_FREQ_MIN, NM_FREQ_MAX
    );
}

fn list() {}
