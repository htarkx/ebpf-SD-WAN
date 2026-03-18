//go:build linux
// +build linux

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	programIngressName = "tc_mark_delegate_ingress"
	programEgressName  = "tc_mark_delegate_egress"
	legacyProgramName  = "tc_mark_delegate"
	cfgMap             = "cfg"
	statsMap           = "stats"

	defaultMark = uint32(0x66)
	defaultPin  = "/sys/fs/bpf/ebpf-sd-wan"
)

type cfgValue struct {
	Mark        uint32
	DNSRedirect uint32
	DNSIPBE     uint32
	DNSPortBE   uint16
	Pad         uint16
}

type statsValue struct {
	Packets uint64
	Bytes   uint64
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "apply":
		if err := runApply(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "detach":
		if err := runDetach(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "stats":
		if err := runStats(os.Args[2:]); err != nil {
			fatal(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func runApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	iface := fs.String("iface", "", "interface name (required)")
	obj := fs.String("obj", "./bpf/mark_delegate.o", "path to eBPF object")
	mark := fs.Uint("mark", uint(defaultMark), "skb mark (decimal or 0xhex)")
	dnsRedirect := fs.Bool("dns-redirect", false, "force redirect IPv4 TCP/UDP dport 53")
	dnsIP := fs.String("dns-ip", "10.66.67.1", "DNS redirect target IPv4")
	dnsPort := fs.Uint("dns-port", 53, "DNS redirect target port")
	pin := fs.String("pin", defaultPin, "bpffs pin directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iface == "" {
		return errors.New("apply requires --iface")
	}

	spec, err := ebpf.LoadCollectionSpec(*obj)
	if err != nil {
		return fmt.Errorf("load collection spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load collection: %w", err)
	}
	defer coll.Close()

	ingressProg, ok := coll.Programs[programIngressName]
	if !ok {
		return fmt.Errorf("program %q not found in object", programIngressName)
	}
	egressProg, ok := coll.Programs[programEgressName]
	if !ok {
		return fmt.Errorf("program %q not found in object", programEgressName)
	}
	if err := ensureClsact(*iface); err != nil {
		return err
	}
	if err := attachTC(*iface, ingressProg.FD(), programIngressName, netlink.HANDLE_MIN_INGRESS, 1); err != nil {
		return err
	}
	if err := attachTC(*iface, egressProg.FD(), programEgressName, netlink.HANDLE_MIN_EGRESS, 1); err != nil {
		return err
	}

	cfg, err := buildCfg(uint32(*mark), *dnsRedirect, *dnsIP, uint16(*dnsPort))
	if err != nil {
		return err
	}

	if err := programMaps(coll, cfg); err != nil {
		return err
	}
	if err := pinMaps(coll, *pin); err != nil {
		return err
	}

	fmt.Printf(
		"applied on iface=%s mark=0x%x dns_redirect=%t dns_target=%s:%d pin=%s\n",
		*iface,
		*mark,
		*dnsRedirect,
		*dnsIP,
		*dnsPort,
		*pin,
	)
	return nil
}

func runDetach(args []string) error {
	fs := flag.NewFlagSet("detach", flag.ContinueOnError)
	iface := fs.String("iface", "", "interface name (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iface == "" {
		return errors.New("detach requires --iface")
	}
	if err := detachTC(*iface); err != nil {
		return err
	}
	fmt.Printf("detached tc filters on iface=%s\n", *iface)
	return nil
}

func runStats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	pin := fs.String("pin", defaultPin, "bpffs pin directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	smapPath := filepath.Join(*pin, statsMap)
	smap, err := ebpf.LoadPinnedMap(smapPath, nil)
	if err != nil {
		return fmt.Errorf("load pinned map %s: %w", smapPath, err)
	}
	defer smap.Close()

	type row struct {
		Packets uint64 `json:"packets"`
		Bytes   uint64 `json:"bytes"`
	}
	rows := make([]row, 0, 1)

	var key uint32
	var val statsValue
	iter := smap.Iterate()
	for iter.Next(&key, &val) {
		rows = append(rows, row{
			Packets: val.Packets,
			Bytes:   val.Bytes,
		})
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate stats map: %w", err)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(rows)
}

func programMaps(coll *ebpf.Collection, cfgVal cfgValue) error {
	cmap, ok := coll.Maps[cfgMap]
	if !ok {
		return fmt.Errorf("map %q not found", cfgMap)
	}
	smap, ok := coll.Maps[statsMap]
	if !ok {
		return fmt.Errorf("map %q not found", statsMap)
	}

	cfgKey := uint32(0)
	if err := cmap.Update(cfgKey, cfgVal, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update cfg map: %w", err)
	}
	statsKey := uint32(0)
	statsVal := statsValue{Packets: 0, Bytes: 0}
	if err := smap.Update(statsKey, statsVal, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("initialize stats map: %w", err)
	}
	return nil
}

func buildCfg(mark uint32, dnsRedirect bool, dnsIP string, dnsPort uint16) (cfgValue, error) {
	cfg := cfgValue{
		Mark: mark,
	}
	if dnsPort == 0 {
		return cfg, fmt.Errorf("dns-port must be > 0")
	}
	if !dnsRedirect {
		return cfg, nil
	}
	ip := net.ParseIP(dnsIP).To4()
	if ip == nil {
		return cfg, fmt.Errorf("invalid IPv4 dns-ip: %q", dnsIP)
	}
	cfg.DNSRedirect = 1
	cfg.DNSIPBE = uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
	cfg.DNSPortBE = uint16(dnsPort<<8) | uint16(dnsPort>>8)
	return cfg, nil
}

func pinMaps(coll *ebpf.Collection, pinDir string) error {
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		return fmt.Errorf("create pin dir: %w", err)
	}
	for _, name := range []string{cfgMap, statsMap} {
		m, ok := coll.Maps[name]
		if !ok {
			return fmt.Errorf("map %q not found", name)
		}
		path := filepath.Join(pinDir, name)
		_ = os.Remove(path)
		if err := m.Pin(path); err != nil {
			return fmt.Errorf("pin map %q: %w", name, err)
		}
	}
	return nil
}

func ensureClsact(iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("lookup iface %q: %w", iface, err)
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("ensure clsact on %s: %w", iface, err)
	}
	return nil
}

func attachTC(iface string, progFD int, name string, parent uint32, handle uint32) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("lookup iface %q: %w", iface, err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    handle,
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           progFD,
		Name:         name,
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("attach tc filter parent=0x%x: %w", parent, err)
	}
	return nil
}

func detachTC(iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("lookup iface %q: %w", iface, err)
	}

	parents := []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS}
	matchNames := map[string]struct{}{
		programIngressName: {},
		programEgressName:  {},
		legacyProgramName:  {},
	}

	totalBPF := 0
	matched := 0
	removed := 0
	for _, parent := range parents {
		filters, err := netlink.FilterList(link, parent)
		if err != nil {
			return fmt.Errorf("list filters parent=0x%x: %w", parent, err)
		}
		fmt.Printf("detach tc iface=%s parent=0x%x total_filters=%d\n", iface, parent, len(filters))

		for _, f := range filters {
			bpfFilter, ok := f.(*netlink.BpfFilter)
			if !ok {
				continue
			}
			totalBPF++
			fmt.Printf(
				"found bpf program name=%q fd=%d handle=%d priority=%d protocol=%d parent=0x%x\n",
				bpfFilter.Name,
				bpfFilter.Fd,
				bpfFilter.Attrs().Handle,
				bpfFilter.Attrs().Priority,
				bpfFilter.Attrs().Protocol,
				parent,
			)
			if _, ok := matchNames[bpfFilter.Name]; !ok {
				continue
			}
			matched++
			if err := netlink.FilterDel(f); err != nil {
				return fmt.Errorf("delete tc filter parent=0x%x: %w", parent, err)
			}
			removed++
			fmt.Printf(
				"removed bpf program name=%q handle=%d priority=%d parent=0x%x\n",
				bpfFilter.Name,
				bpfFilter.Attrs().Handle,
				bpfFilter.Attrs().Priority,
				parent,
			)
		}
	}
	fmt.Printf(
		"detach summary iface=%s bpf_seen=%d matched=%d removed=%d\n",
		iface,
		totalBPF,
		matched,
		removed,
	)
	return nil
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

func usage() {
	fmt.Println(`sdwan-tc

Usage:
  sdwan-tc apply  --iface <ifname> [--obj ./bpf/mark_delegate.o] [--mark 0x66] [--dns-redirect --dns-ip 10.66.67.1 --dns-port 53] [--pin /sys/fs/bpf/ebpf-sd-wan]
  sdwan-tc detach --iface <ifname>
  sdwan-tc stats  [--pin /sys/fs/bpf/ebpf-sd-wan]
`)
}
