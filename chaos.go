package command

import (
	"fmt"
	"log"
	"math"
	"os"
	"runtime/debug"
	"strings"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/Netflix/chaosmonkey/v2"
	"github.com/Netflix/chaosmonkey/v2/clock"
	"github.com/Netflix/chaosmonkey/v2/config"
	"github.com/Netflix/chaosmonkey/v2/config/param"
	"github.com/Netflix/chaosmonkey/v2/deploy"
	"github.com/Netflix/chaosmonkey/v2/deps"
	"github.com/Netflix/chaosmonkey/v2/mysql"
	"github.com/Netflix/chaosmonkey/v2/schedstore"
	"github.com/Netflix/chaosmonkey/v2/schedule"
	"github.com/Netflix/chaosmonkey/v2/spinnaker"
)

// Version is the version number
const Version = "2.0.2"

func printVersion() {
	fmt.Printf("%s\n", Version)
}

var (
	// configPaths is where Chaos Monkey will look for a chaosmonkey.toml
	// configuration file
	configPaths = [...]string{".", "/apps/chaosmonkey", "/etc", "/etc/chaosmonkey"}
)

// Usage prints usage
func Usage() {
	usage := `
Chaos Monkey

Usage:
	chaosmonkey <command> ...

command: migrate | schedule | terminate | fetch-schedule | outage | config  | email | eligible | intest

Install
-------
Installs chaosmonkey with all the setup required, e.g setting up the cron, appling database migration etc.

migrate
-------
Applies database migration to the database defined in the configuration file.

schedule [--max-apps=<N>] [--apps=foo,bar,baz] [--no-record-schedule]
--------------------------------------------------------------------
Generates a schedule of terminations for the day and installs the
terminations as local cron jobs that call "chaosmonkey terminate ..."

--apps=foo,bar,baz     Optionally specify an explicit list of apps to schedule.
                       This is primarily used for debugging.

--max-apps=<N>         Optionally specify the maximum number of apps that Chaos Monkey
					   will schedule. This is primarily used for debugging.

--no-record-schedule   Do not record the schedule with the database.
                       This is primarily used for debugging.


terminate <app> <account> [--region=<region>] [--stack=<stack>] [--cluster=<cluster>] [--leashed]
-----------------------------------------------------------------------------------------------------------------
Terminates an instance from a given app and account.

Optionally specify a region, stack, cluster.

The --leashed flag forces chaosmonkey to run in leashed mode. When leashed,
Chaos Monkey will check if an instance should be terminated, but will not
actually terminate it.

fetch-schedule
--------------
Queries the database to see if there is an existing schedule of
terminations for today. If so, downloads the schedule and sets up cron jobs to
implement the schedule.

outage
------
Output "true" if there is an ongoing outage, otherwise "false". Used for debugging.


config [<app>]
------------
Query Spinnaker for the config for a specific app and dump it to
standard out. This is only used for debugging.

If no app is specified, dump the Monkey-level configuration options to standard out.

Examples:

	chaosmonkey config chaosguineapig

	chaosmonkey config

eligible <app> <account> [--region=<region>] [--stack=<stack>] [--cluster=<cluster>]
-------------------------------------------------------------------------------------

Dump a list of instance-ids that are eligible for termination for a given app, account,
and optionally region, stack, and cluster.

intest
------

Outputs "true" on standard out if running within a test environment, otherwise outputs "false"


account <name>
--------------

Look up an cloud account ID by name.

Example:

	chaosmonkey account test


provider <name>
---------------

Look up the cloud provider by account name.

Example:

	chaosmonkey provider test


clusters <app> <account>
------------------------

List the clusters for a given app and account

Example:

	chaosmonkey clusters chaosguineapig test


regions <cluster> <account>
---------------------------

List the regions for a given cluster and account

Example:

	chaosmonkey regions chaosguineapig test
`
	fmt.Printf(usage)
}

func init() {
	// Prepend the pid to log statements
	log.SetPrefix(fmt.Sprintf("[%5d] ", os.Getpid()))
}

// Execute is the main entry point for the chaosmonkey cli.
func Execute() {
	regionPtr := flag.String("region", "", "region of termination group")
	stackPtr := flag.String("stack", "", "stack of termination group")
	clusterPtr := flag.String("cluster", "", "cluster of termination group")
	appsPtr := flag.String("apps", "", "comma-separated list of apps to schedule for termination")
	noRecordSchedulePtr := flag.Bool("no-record-schedule", false, "do not record schedule")
	versionPtr := flag.BoolP("version", "v", false, "show version")
	flag.Usage = Usage

	// These flags, if specified, override config values
	maxAppsFlag := "max-apps"
	leashedFlag := "leashed"
	flag.Int(maxAppsFlag, math.MaxInt32, "max number of apps to examine for termination")
	flag.Bool(leashedFlag, false, "force leashed mode")

	flag.Parse()
	if len(flag.Args()) == 0 {
		if *versionPtr {
			printVersion()
			os.Exit(0)
		}

		flag.Usage()
		os.Exit(1)
	}

	cmd := flag.Arg(0)

	cfg, err := getConfig()

	if err != nil {
		log.Fatalf("FATAL: failed to load config: %v", err)
	}

	// Associate config values with flags
	err = cfg.BindPFlag(param.MaxApps, flag.Lookup(maxAppsFlag))
	if err != nil {
		log.Fatalf("FATAL: failed to bind flag: --%s: %v", maxAppsFlag, err)
	}
	err = cfg.BindPFlag(param.Leashed, flag.Lookup(leashedFlag))
	if err != nil {
		log.Fatalf("FATAL: failed to bind flag: --%s: %v", leashedFlag, err)
	}

	spin, err := spinnaker.NewFromConfig(cfg)

	if err != nil {
		log.Fatalf("FATAL: spinnaker.New failed: %+v", err)
	}

	outage, err := deps.GetOutage(cfg)
	if err != nil {
		log.Fatalf("FATAL: deps.GetOutage fail: %+v", err)
	}

	sql, err := mysql.NewFromConfig(cfg)
	if err != nil {
		log.Fatalf("FATAL: could not initialize mysql connection: %+v", err)
	}
