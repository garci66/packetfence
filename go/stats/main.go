package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/daemon"
	"github.com/hpcloud/tail"
	"github.com/inverse-inc/packetfence/go/pfconfigdriver"

	"github.com/inverse-inc/packetfence/go/log"
	statsd "gopkg.in/alexcesaro/statsd.v2"
	ldap "gopkg.in/ldap.v2"
	"layeh.com/radius"
	. "layeh.com/radius/rfc2865"
)

type TypeName struct {
	Typename map[*regexp.Regexp]Types
}

type Types struct {
	Type map[int]TypeDef
}

type TypeDef struct {
	Name       string
	DataSource StatsdType
	Minimum    string
	Maximum    string
}

type StatsdType interface {
	Send(name string, a interface{})
}

var GAUGE gauge

type gauge struct{}

func (s gauge) Send(name string, a interface{}) {
	c, err := statsd.New()
	if err != nil {
		log.LoggerWContext(ctx).Error(err.Error())
	}
	defer c.Close()
	c.Gauge(name, a)
}

var ABSOLUTE absolute

type absolute struct{}

func (s absolute) Send(name string, a interface{}) {
	// StatsdClient.Gauge(name, a)
}

var DERIVE derive

type derive struct{}

func (s derive) Send(name string, a interface{}) {
	// StatsdClient.Gauge(name, a)
}

var COUNTER counter

type counter struct{}

func (s counter) Send(name string, a interface{}) {
	StatsdClient.Count(name, a)
}

type TestSource struct {
	SourceType TypeSource
}

type TypeSource interface {
	Test(source interface{}, ctx context.Context)
}

var RADIUS radiustype

type radiustype struct{}

func (s radiustype) Test(source interface{}, ctx context.Context) {
	t := StatsdClient.NewTiming()
	packet := radius.New(radius.CodeAccessRequest, []byte(source.(pfconfigdriver.AuthenticationSourceRadius).Secret))
	UserName_SetString(packet, "tim")
	UserPassword_SetString(packet, "12345")
	client := radius.DefaultClient
	response, err := client.Exchange(ctx, packet, source.(pfconfigdriver.AuthenticationSourceRadius).Host+":"+source.(pfconfigdriver.AuthenticationSourceRadius).Port)
	if err != nil {
		StatsdClient.Gauge("source."+source.(pfconfigdriver.AuthenticationSourceRadius).Type+"."+source.(pfconfigdriver.AuthenticationSourceRadius).PfconfigHashNS, 0)
	} else {
		StatsdClient.Gauge("source."+source.(pfconfigdriver.AuthenticationSourceRadius).Type+"."+source.(pfconfigdriver.AuthenticationSourceRadius).PfconfigHashNS, 1)
		if response.Code == radius.CodeAccessAccept {
			fmt.Println("Accepted")
		} else {
			fmt.Println("Denied")
		}
	}
	t.Send("source." + source.(pfconfigdriver.AuthenticationSourceRadius).Type + "." + source.(pfconfigdriver.AuthenticationSourceRadius).PfconfigHashNS)
}

var LDAP ldaptype

type ldaptype struct{}

func (s ldaptype) Test(source interface{}, ctx context.Context) {
	t := StatsdClient.NewTiming()
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%s", source.(pfconfigdriver.AuthenticationSourceLdap).Host, source.(pfconfigdriver.AuthenticationSourceLdap).Port))

	if err != nil {
		StatsdClient.Gauge("source."+source.(pfconfigdriver.AuthenticationSourceLdap).Type+"."+source.(pfconfigdriver.AuthenticationSourceLdap).PfconfigHashNS, 0)
		log.LoggerWContext(ctx).Error(err.Error())
	} else {
		defer l.Close()
		// Reconnect with TLS
		if source.(pfconfigdriver.AuthenticationSourceLdap).Encryption != "none" {
			err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
			if err != nil {
				log.LoggerWContext(ctx).Crit(err.Error())
			}
		}

		// First bind with a read only user
		timeout, err := strconv.Atoi(source.(pfconfigdriver.AuthenticationSourceLdap).ReadTimeout)
		if err != nil {
			log.LoggerWContext(ctx).Crit(err.Error())
		}

		l.SetTimeout(time.Duration(timeout) * time.Second)
		err = l.Bind(source.(pfconfigdriver.AuthenticationSourceLdap).BindDN, source.(pfconfigdriver.AuthenticationSourceLdap).Password)
		if err != nil {
			StatsdClient.Gauge("source."+source.(pfconfigdriver.AuthenticationSourceLdap).Type+"."+source.(pfconfigdriver.AuthenticationSourceLdap).PfconfigHashNS, 0)
		} else {
			StatsdClient.Gauge("source."+source.(pfconfigdriver.AuthenticationSourceLdap).Type+"."+source.(pfconfigdriver.AuthenticationSourceLdap).PfconfigHashNS, 1)
		}
		t.Send("source." + source.(pfconfigdriver.AuthenticationSourceLdap).Type + "." + source.(pfconfigdriver.AuthenticationSourceLdap).PfconfigHashNS)
	}
}

var EDUROAM eduroamtype

type eduroamtype struct{}

func (s eduroamtype) Test(source interface{}, ctx context.Context) {

	t := StatsdClient.NewTiming()
	packet := radius.New(radius.CodeAccessRequest, []byte(source.(pfconfigdriver.AuthenticationSourceEduroam).RadiusSecret))
	UserName_SetString(packet, "tim")
	UserPassword_SetString(packet, "12345")
	client := radius.DefaultClient
	response, err := client.Exchange(ctx, packet, source.(pfconfigdriver.AuthenticationSourceEduroam).Server1Address+":1812")

	if err != nil {
		StatsdClient.Gauge("source."+source.(pfconfigdriver.AuthenticationSourceEduroam).Type+"."+source.(pfconfigdriver.AuthenticationSourceEduroam).PfconfigHashNS+"1", 0)
	} else {
		StatsdClient.Count("source."+source.(pfconfigdriver.AuthenticationSourceEduroam).Type+"."+source.(pfconfigdriver.AuthenticationSourceEduroam).PfconfigHashNS+"1", 1)
		if response.Code == radius.CodeAccessAccept {
			fmt.Println("Accepted")
		} else {
			fmt.Println("Denied")
		}
	}
	t.Send("source." + source.(pfconfigdriver.AuthenticationSourceEduroam).Type + "." + source.(pfconfigdriver.AuthenticationSourceEduroam).PfconfigHashNS + "1")

	t = StatsdClient.NewTiming()
	packet = radius.New(radius.CodeAccessRequest, []byte(source.(pfconfigdriver.AuthenticationSourceEduroam).RadiusSecret))
	UserName_SetString(packet, "tim")
	UserPassword_SetString(packet, "12345")
	response, err = client.Exchange(ctx, packet, source.(pfconfigdriver.AuthenticationSourceEduroam).Server2Address+":1812")
	if err != nil {
		StatsdClient.Gauge("source."+source.(pfconfigdriver.AuthenticationSourceEduroam).Type+"."+source.(pfconfigdriver.AuthenticationSourceEduroam).PfconfigHashNS+"2", 0)
	} else {
		StatsdClient.Gauge("source."+source.(pfconfigdriver.AuthenticationSourceEduroam).Type+"."+source.(pfconfigdriver.AuthenticationSourceEduroam).PfconfigHashNS+"2", 1)
		if response.Code == radius.CodeAccessAccept {
			fmt.Println("Accepted")
		} else {
			fmt.Println("Denied")
		}
	}
	t.Send("source." + source.(pfconfigdriver.AuthenticationSourceEduroam).Type + "." + source.(pfconfigdriver.AuthenticationSourceEduroam).PfconfigHashNS + "2")

}

func forward(c net.Conn) {
	for {
		buf := make([]byte, 512)
		nr, err := c.Read(buf)
		if err != nil {
			return
		}

		data := buf[0:nr]
		rgx, _ := regexp.Compile("PUTVAL \"(.*)\"\\s+interval=(.*)\\s+(\\d+.\\d+):(.*)")
		if rgx.MatchString(string(data)) {
			splitted := rgx.FindStringSubmatch(string(data))
			s := strings.Split(splitted[1], "/")
			for k := range Verb.Typename {
				if k.MatchString(s[2]) {
					values := strings.Split(splitted[4], ":")
					for key, val := range values {
						val = strings.TrimSuffix(val, "\r")
						if val == "U" {
							continue
						}
						f, _ := strconv.ParseFloat(val, 64)
						Verb.Typename[k].Type[key].DataSource.Send(splitted[1]+"."+Verb.Typename[k].Type[key].Name, f)
					}
				}
			}
			_, err = c.Write([]byte("0 Success: 1 value has been dispatched.\n"))
		}
		if err != nil {
			log.LoggerWContext(ctx).Crit("Writing client error: " + err.Error())
		}
	}
}

var StatsdClient *statsd.Client

var ctx context.Context

func main() {
	d := time.Now().Add(500 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), d)
	ctx = log.LoggerNewContext(ctx)
	defer cancel()

	var err error

	StatsdClient, err = statsd.New()
	if err != nil {
		log.LoggerWContext(ctx).Error(err.Error())
	}

	log.LoggerWContext(ctx).Info("Starting stats server")
	// Systemd
	daemon.SdNotify(false, "READY=1")

	ln, err := net.Listen("unix", "/usr/local/pf/var/run/collectd-unixsock")
	if err != nil {
		log.LoggerWContext(ctx).Crit("Listen error: " + err.Error())
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func(ln net.Listener, c chan os.Signal) {
		sig := <-c
		log.LoggerWContext(ctx).Info("Caught signal " + sig.String() + ": shutting down.")
		ln.Close()
		os.Exit(0)
	}(ln, sigc)

	// LDAP Sources
	go func() {
		for {
			var sections pfconfigdriver.PfconfigKeys
			sections.PfconfigNS = "resource::authentication_sources_ldap"

			pfconfigdriver.FetchDecodeSocket(ctx, &sections)
			for _, src := range sections.Keys {
				var source pfconfigdriver.AuthenticationSourceLdap
				source.PfconfigNS = "resource::authentication_sources_ldap"
				source.PfconfigHashNS = src
				pfconfigdriver.FetchDecodeSocket(ctx, &source)
				if source.Monitor == "1" {
					var Source = TestSource{LDAP}
					go Source.SourceType.Test(source, ctx)
				}
			}
			time.Sleep(time.Second * 10)
		}
	}()
	// Radius Sources
	go func() {
		for {
			var sections pfconfigdriver.PfconfigKeys
			sections.PfconfigNS = "resource::authentication_sources_radius"

			pfconfigdriver.FetchDecodeSocket(ctx, &sections)
			for _, src := range sections.Keys {
				var source pfconfigdriver.AuthenticationSourceRadius
				source.PfconfigNS = "resource::authentication_sources_radius"
				source.PfconfigHashNS = src
				pfconfigdriver.FetchDecodeSocket(ctx, &source)
				if source.Monitor == "1" {
					var Source = TestSource{RADIUS}
					go Source.SourceType.Test(source, ctx)
				}
			}
			time.Sleep(time.Second * 10)
		}
	}()

	// Eduroam Sources
	go func() {
		for {
			var sections pfconfigdriver.PfconfigKeys
			sections.PfconfigNS = "resource::authentication_sources_eduroam"

			pfconfigdriver.FetchDecodeSocket(ctx, &sections)
			for _, src := range sections.Keys {
				var source pfconfigdriver.AuthenticationSourceEduroam
				source.PfconfigNS = "resource::authentication_sources_eduroam"
				source.PfconfigHashNS = src
				pfconfigdriver.FetchDecodeSocket(ctx, &source)
				if source.Monitor == "1" {
					var Source = TestSource{EDUROAM}
					go Source.SourceType.Test(source, ctx)
				}
			}
			time.Sleep(time.Second * 10)
		}
	}()

	var files []string

	config := tail.Config{Follow: true, ReOpen: true, Location: &tail.SeekInfo{-10, os.SEEK_END}}

	done := make(chan bool)

	var keyConfStats pfconfigdriver.PfconfigKeys
	keyConfStats.PfconfigNS = "config::Stats"
	pfconfigdriver.FetchDecodeSocket(ctx, &keyConfStats)

	for _, key := range keyConfStats.Keys {
		var ConfStat pfconfigdriver.PfStats
		ConfStat.PfconfigHashNS = key

		pfconfigdriver.FetchDecodeSocket(ctx, &ConfStat)
		files = append(files, ConfStat.File)

		go tailFile(ConfStat, config, done)
	}

	for _ = range files {
		<-done
	}

	for {
		fd, err := ln.Accept()
		if err != nil {
			log.LoggerWContext(ctx).Crit("Accept error: " + err.Error())
		}

		go forward(fd)
	}
}

func tailFile(stats pfconfigdriver.PfStats, config tail.Config, done chan bool) {
	defer func() { done <- true }()
	t, err := tail.TailFile(stats.File, config)
	if err != nil {
		log.LoggerWContext(ctx).Error(err.Error())
		return
	}

	rgx := regexp.MustCompile(stats.Match)

	for line := range t.Lines {
		if rgx.Match([]byte(line.Text)) {
			StatsdClient.Gauge(stats.PfconfigHashNS, 1)
		}
	}
	err = t.Wait()
	if err != nil {
		log.LoggerWContext(ctx).Error(err.Error())
	}
}

var Verb = TypeName{
	Typename: map[*regexp.Regexp]Types{
		regexp.MustCompile("^absolute(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", ABSOLUTE, "0", "U"},
			},
		},
		regexp.MustCompile("^apache_bytes(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^apache_connections(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "65535"},
			},
		},
		regexp.MustCompile("^apache_idle_workers(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "65535"},
			},
		},
		regexp.MustCompile("^apache_requests(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^apache_scoreboard(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "65535"},
			},
		},
		regexp.MustCompile("^ath_nodes(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "65535"},
			},
		},
		regexp.MustCompile("^ath_stat(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^backends(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "65535"},
			},
		},

		regexp.MustCompile("^bitrate(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "4294967295"},
			},
		},
		regexp.MustCompile("^blocked_clients(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^bytes(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^cache_eviction(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^cache_operation(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^cache_ratio(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "100"},
			},
		},
		regexp.MustCompile("^cache_result(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},

		regexp.MustCompile("^cache_size(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "1125899906842623"},
			},
		},
		regexp.MustCompile("^capacity(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^ceph_bytes(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "U", "U"},
			},
		},
		regexp.MustCompile("^ceph_latency(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "U", "U"},
			},
		},
		regexp.MustCompile("^ceph_rate(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^changes_since_last_save(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^charge(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^clock_last_meas(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^clock_last_update(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "U", "U"},
			},
		},
		regexp.MustCompile("^clock_mode(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^clock_reachability(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^clock_skew_ppm(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "-2", "2"},
			},
		},
		regexp.MustCompile("^clock_state(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^clock_stratum(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},

		regexp.MustCompile("^compression(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"uncompressed", DERIVE, "0", "U"},
				1: TypeDef{"compressed", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^compression_ratio(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "2"},
			},
		},

		regexp.MustCompile("^connections(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^conntrack(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "4294967295"},
			},
		},

		regexp.MustCompile("^contextswitch(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^count(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^counter(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", COUNTER, "U", "U"},
			},
		},
		regexp.MustCompile("^cpu(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^cpufreq(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^current(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "U", "U"},
			},
		},
		regexp.MustCompile("^current_connections(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^current_sessions(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^delay(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "-1000000", "1000000"},
			},
		},
		regexp.MustCompile("^derive(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^df(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"used", GAUGE, "0", "1125899906842623"},
				1: TypeDef{"free", GAUGE, "0", "1125899906842623"},
			},
		},
		regexp.MustCompile("^df_complex(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^df_inodes(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^dilution_of_precision(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},

		regexp.MustCompile("^disk_io_time(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"io_time", DERIVE, "0", "U"},
				1: TypeDef{"weighted_io_time", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^disk_latency(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"read", GAUGE, "0", "U"},
				1: TypeDef{"write", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^disk_merged(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"read", DERIVE, "0", "U"},
				1: TypeDef{"write", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^disk_octets(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"read", DERIVE, "0", "U"},
				1: TypeDef{"write", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^disk_ops(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"read", DERIVE, "0", "U"},
				1: TypeDef{"write", DERIVE, "0", "U"},
			},
		},

		regexp.MustCompile("^disk_ops_complex(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},

		regexp.MustCompile("^disk_time(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"read", DERIVE, "0", "U"},

				1: TypeDef{"write", DERIVE, "0", "U"},
			},
		},

		regexp.MustCompile("^dns_answer(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^dns_notify(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^dns_octets(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"queries", DERIVE, "0", "U"},
				1: TypeDef{"responses", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^dns_opcode(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^dns_qtype(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^dns_qtype_cached(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "4294967295"},
			},
		},
		regexp.MustCompile("^dns_query(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^dns_question(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^dns_rcode(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^dns_reject(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^dns_request(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^dns_resolver(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^dns_response(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^dns_transfer(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^dns_update(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^dns_zops(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^drbd_resource(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^duration(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"seconds", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^email_check(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^email_count(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^email_size(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^entropy(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "4294967295"},
			},
		},
		regexp.MustCompile("^evicted_keys(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^expired_keys(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^fanspeed(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^file_handles(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^file_size(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^files(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^flow(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^fork_rate(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^frequency(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^frequency_error(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "-2", "2"},
			},
		},
		regexp.MustCompile("^frequency_offset(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "-1000000", "1000000"},
			},
		},
		regexp.MustCompile("^fscache_stat(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^gauge(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "U", "U"},
			},
		},
		regexp.MustCompile("^hash_collisions(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^http_request_methods(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^http_requests(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^http_response_codes(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^humidity(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "100"},
			},
		},
		regexp.MustCompile("^if_collisions(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^if_dropped(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"rx", DERIVE, "0", "U"},

				1: TypeDef{"tx", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^if_errors(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"rx", DERIVE, "0", "U"},

				1: TypeDef{"tx", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^if_multicast(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^if_octets(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"rx", DERIVE, "0", "U"},

				1: TypeDef{"tx", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^if_packets(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"rx", DERIVE, "0", "U"},
				1: TypeDef{"tx", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^if_rx_errors(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^if_rx_octets(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^if_tx_errors(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^if_tx_octets(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^invocations(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^io_octets(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"rx", DERIVE, "0", "U"},
				1: TypeDef{"tx", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^io_packets(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"rx", DERIVE, "0", "U"},
				1: TypeDef{"tx", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^ipt_bytes(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^ipt_packets(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^irq(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^latency(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^links(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^load(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"shortterm", GAUGE, "0", "5000"},
				1: TypeDef{"midterm", GAUGE, "0", "5000"},
				2: TypeDef{"longterm", GAUGE, "0", "5000"},
			},
		},
		regexp.MustCompile("^md_disks(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^memcached_command(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^memcached_connections(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^memcached_items(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^memcached_octets(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"rx", DERIVE, "0", "U"},

				1: TypeDef{"tx", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^memcached_ops(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^memory(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "281474976710656"},
			},
		},
		regexp.MustCompile("^memory_lua(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "281474976710656"},
			},
		},
		regexp.MustCompile("^memory_throttle_count(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^multimeter(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "U", "U"},
			},
		},
		regexp.MustCompile("^mutex_operations(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_bpool_bytes(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_bpool_counters(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_bpool_pages(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_commands(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_handler(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_innodb_data(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_innodb_dblwr(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_innodb_log(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_innodb_pages(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_innodb_row_lock(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_innodb_rows(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_locks(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_log_position(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_octets(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"rx", DERIVE, "0", "U"},

				1: TypeDef{"tx", DERIVE, "0", "U"},
			},
		},

		regexp.MustCompile("^mysql_select(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_sort(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_sort_merge_passes(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_sort_rows(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_slow_queries(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^nfs_procedure(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^nginx_connections(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^nginx_requests(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^node_octets(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"rx", DERIVE, "0", "U"},
				1: TypeDef{"tx", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^node_rssi(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "255"},
			},
		},
		regexp.MustCompile("^node_stat(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^objects(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^node_tx_rate(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "127"},
			},
		},
		regexp.MustCompile("^operations(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^operations_per_second(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^packets(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^pending_operations(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^percent(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "100.1"},
			},
		},
		regexp.MustCompile("^percent_bytes(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "100.1"},
			},
		},
		regexp.MustCompile("^percent_inodes(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "100.1"},
			},
		},
		regexp.MustCompile("^pf_counters(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^pf_limits(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^pf_source(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^pf_state(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^pf_states(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^pg_blks(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^pg_db_size(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^pg_n_tup_c(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^pg_n_tup_g(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^pg_numbackends(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^pg_scan(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^pg_xact(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^ping(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "65535"},
			},
		},
		regexp.MustCompile("^ping_droprate(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "100"},
			},
		},
		regexp.MustCompile("^ping_stddev(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "65535"},
			},
		},
		regexp.MustCompile("^players(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "1000000"},
			},
		},
		regexp.MustCompile("^power(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "U", "U"},
			},
		},
		regexp.MustCompile("^pressure(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^protocol_counter(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^ps_code(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "9223372036854775807"},
			},
		},
		regexp.MustCompile("^ps_cputime(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"user", DERIVE, "0", "U"},

				1: TypeDef{"syst", DERIVE, "0", "U"},
			},
		},

		regexp.MustCompile("^ps_count(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"processes", GAUGE, "0", "1000000"},

				1: TypeDef{"threads", GAUGE, "0", "1000000"},
			},
		},
		regexp.MustCompile("^ps_data(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "9223372036854775807"},
			},
		},
		regexp.MustCompile("^ps_disk_octets(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"read", DERIVE, "0", "U"},

				1: TypeDef{"write", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^ps_disk_ops(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"read", DERIVE, "0", "U"},
				1: TypeDef{"write", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^ps_pagefaults(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"minflt", DERIVE, "0", "U"},
				1: TypeDef{"majflt", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^ps_rss(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "9223372036854775807"},
			},
		},
		regexp.MustCompile("^ps_stacksize(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "9223372036854775807"},
			},
		},
		regexp.MustCompile("^ps_state(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "65535"},
			},
		},
		regexp.MustCompile("^ps_vm(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "9223372036854775807"},
			},
		},
		regexp.MustCompile("^pubsub(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^queue_length(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^records(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^requests(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^response_code(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^response_time(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^root_delay(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "U", "U"},
			},
		},
		regexp.MustCompile("^root_dispersion(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "U", "U"},
			},
		},
		regexp.MustCompile("^route_etx(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^route_metric(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^routes(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^satellites(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^segments(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "65535"},
			},
		},
		regexp.MustCompile("^serial_octets(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"rx", DERIVE, "0", "U"},

				1: TypeDef{"tx", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^signal_noise(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "U", "0"},
			},
		},
		regexp.MustCompile("^signal_power(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "U", "0"},
			},
		},
		regexp.MustCompile("^signal_quality(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^smart_attribute(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"current", GAUGE, "0", "255"},
				1: TypeDef{"worst", GAUGE, "0", "255"},
				2: TypeDef{"threshold", GAUGE, "0", "255"},
				3: TypeDef{"pretty", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^smart_badsectors(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^smart_powercycles(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^smart_poweron(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^smart_temperature(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "-300", "300"},
			},
		},
		regexp.MustCompile("^snr(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^spam_check(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^spam_score(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "U", "U"},
			},
		},
		regexp.MustCompile("^spl(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "U", "U"},
			},
		},
		regexp.MustCompile("^swap(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "1099511627776"},
			},
		},
		regexp.MustCompile("^swap_io(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^tcp_connections(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "4294967295"},
			},
		},
		regexp.MustCompile("^temperature(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "U", "U"},
			},
		},
		regexp.MustCompile("^threads(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^time_dispersion(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "-1000000", "1000000"},
			},
		},
		regexp.MustCompile("^time_offset(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "-1000000", "1000000"},
			},
		},
		regexp.MustCompile("^time_offset_ntp(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "-1000000", "1000000"},
			},
		},
		regexp.MustCompile("^time_offset_rms(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "-1000000", "1000000"},
			},
		},
		regexp.MustCompile("^time_ref(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^timeleft(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^total_bytes(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^total_connections(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^total_objects(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^total_operations(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^total_requests(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^total_sessions(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^total_threads(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^total_time_in_ms(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^total_values(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^uptime(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "4294967295"},
			},
		},
		regexp.MustCompile("^users(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "65535"},
			},
		},
		regexp.MustCompile("^vcl(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "65535"},
			},
		},
		regexp.MustCompile("^vcpu(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^virt_cpu_total(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^virt_vcpu(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^vmpage_action(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^vmpage_faults(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"minflt", DERIVE, "0", "U"},
				1: TypeDef{"majflt", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^vmpage_io(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"in", DERIVE, "0", "U"},
				1: TypeDef{"out", DERIVE, "0", "U"},
			},
		},
		regexp.MustCompile("^vmpage_number(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "4294967295"},
			},
		},
		regexp.MustCompile("^volatile_changes(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^voltage(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "U", "U"},
			},
		},
		regexp.MustCompile("^voltage_threshold(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "U", "U"},
				1: TypeDef{"threshold", GAUGE, "U", "U"},
			},
		},
		regexp.MustCompile("^vs_memory(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "9223372036854775807"},
			},
		},
		regexp.MustCompile("^vs_processes(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "65535"},
			},
		},
		regexp.MustCompile("^vs_threads(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "65535"},
			},
		},
		regexp.MustCompile("^arc_counts(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"demand_data", COUNTER, "0", "U"},
				1: TypeDef{"demand_metadata", COUNTER, "0", "U"},
				2: TypeDef{"prefetch_data", COUNTER, "0", "U"},
				3: TypeDef{"prefetch_metadata", COUNTER, "0", "U"},
			},
		},
		regexp.MustCompile("^arc_l2_bytes(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"read", COUNTER, "0", "U"},
				1: TypeDef{"write", COUNTER, "0", "U"},
			},
		},
		regexp.MustCompile("^arc_l2_size(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^arc_ratio(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"value", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^arc_size(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"current", GAUGE, "0", "U"},
				1: TypeDef{"target", GAUGE, "0", "U"},

				2: TypeDef{"minlimit", GAUGE, "0", "U"},
				3: TypeDef{"maxlimit", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_qcache(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"hits", COUNTER, "0", "U"},
				1: TypeDef{"inserts", COUNTER, "0", "U"},
				2: TypeDef{"not_cached", COUNTER, "0", "U"},
				3: TypeDef{"lowmem_prunes", COUNTER, "0", "U"},
				4: TypeDef{"queries_in_cache", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^mysql_threads(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"running", GAUGE, "0", "U"},
				1: TypeDef{"connected", GAUGE, "0", "U"},
				2: TypeDef{"cached", GAUGE, "0", "U"},
				3: TypeDef{"created", COUNTER, "0", "U"},
			},
		},
		regexp.MustCompile("^radius_count(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"received", GAUGE, "0", "U"},
				1: TypeDef{"linked", GAUGE, "0", "U"},
				2: TypeDef{"unlinked", GAUGE, "0", "U"},
				3: TypeDef{"reused", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^radius_latency(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"smoothed", GAUGE, "0", "U"},
				1: TypeDef{"avg", GAUGE, "0", "U"},
				2: TypeDef{"high", GAUGE, "0", "U"},
				3: TypeDef{"low", GAUGE, "0", "U"},
			},
		},
		regexp.MustCompile("^radius_rtx(\\.|-).*"): {
			map[int]TypeDef{
				0: TypeDef{"none", GAUGE, "0", "U"},
				1: TypeDef{"1", GAUGE, "0", "U"},
				2: TypeDef{"2", GAUGE, "0", "U"},
				3: TypeDef{"3", GAUGE, "0", "U"},
				4: TypeDef{"4", GAUGE, "0", "U"},
				5: TypeDef{"more", GAUGE, "0", "U"},
				6: TypeDef{"lost", GAUGE, "0", "U"},
			},
		},
	},
}
