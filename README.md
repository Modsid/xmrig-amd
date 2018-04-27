# HYCminer AMD

HYCminer is a high performance Hycon (HYC) OpenCL miner, forked from [XMRig](https://github.com/xmrig/xmrig) release v2.6.1.

* This is the **AMD GPU** mining version, there is also a [CPU version](https://github.com/team-hycon/xmrig) and [NVIDIA GPU version](https://github.com/team-hycon/xmrig-nvidia).
* We plan on releasing our roadmap for next releases soon.

#### Table of contents
* [Features](#features)
* [Download](#download)
* [Usage](#usage)
* [Algorithm variations](#algorithm-variations)
* [Build](https://github.com/team-hycon/xmrig-amd/wiki/Build)
* [Common Issues](#common-issues)
* [Other information](#other-information)
* [Contacts](#contacts)

## Features
* Currently running Cryptonight v7
* High performance.
* Official Windows support.
* Support for backup (failover) mining server.
* CryptoNight-Lite support for AEON.
* Automatic GPU configuration.
* GPU health monitoring (clocks, power, temperature, fan speed) 
* Nicehash support.
* It's open source software.

## Download
* Binary releases: TBA
* Git tree: https://github.com/team-hycon/xmrig-amd.git
    * Clone with `git clone https://github.com/team-hycon/xmrig-amd.git` :hammer: [Build instructions](https://github.com/team-hycon/xmrig-amd/wiki/Build).

## Usage
See the example `config.json` to configure the miner.

### Command line options
```
  -a, --algo=ALGO           cryptonight (default) or cryptonight-lite
  -o, --url=URL             URL of mining server
  -O, --userpass=U:P        username:password pair for mining server
  -u, --user=USERNAME       username for mining server
  -p, --pass=PASSWORD       password for mining server
  -k, --keepalive           send keepalived for prevent timeout (need pool support)
  -r, --retries=N           number of times to retry before switch to backup server (default: 5)
  -R, --retry-pause=N       time to pause between retries (default: 5)
      --opencl-devices=N    list of OpenCL devices to use.
      --opencl-launch=IxW   list of launch config, intensity and worksize
      --opencl-affinity=N   affine GPU threads to a CPU
      --opencl-platform=N   OpenCL platform index
      --no-color            disable colored output
      --donate-level=N      donate level, default 5% (5 minutes in 100 minutes)
      --user-agent          set custom user-agent string for pool
  -B, --background          run the miner in the background
  -c, --config=FILE         load a JSON-format configuration file
  -l, --log-file=FILE       log all output to a file
      --nicehash            enable nicehash support
      --print-time=N        print hashrate report every N seconds
      --api-port=N          port for the miner API
      --api-access-token=T  access token for API
      --api-worker-id=ID    custom worker-id for API
  -h, --help                display this help and exit
  -V, --version             output version information and exit
```

Also you can use configuration via config file, default **config.json**. You can load multiple config files and combine it with command line options.

## Other information
* No HTTP support, only stratum protocol support.
* No TLS support.
* Default donation 5% (5 minutes in 100 minutes) can be reduced to 1% via command line option `--donate-level`.

## SHA256 for Windows Binary files
    ad7871564a0417d8b0d608bc34e61d7ab71dffcb61fabff1d3efb79173223826: certUtil -hashfile hycon-amd-win-0.0.1-without-mhttpd/xmrig-amd.exe sha256
    0dd192e71b6df71a912ab3d614b19de240ebfc7be2c03963d4b268e5599154f3: certUtil -hashfile hycon-amd-win-0.0.1/xmrig-amd.exe sha256

## Contacts
* hycon@glosfer.com
* [site](https://www.hycon.io)
* [reddit](https://www.reddit.com/r/HYCON)
* [facebook](https://www.facebook.com/teamHycon)
* [instagram](https://www.instagram.com/teamhycon)
* [medium](https://www.medium.com/@teamhycon)
* [twitter](https://www.twitter.com/teamhycon)
