package overlay

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var Cmd *cobra.Command

func init() {
	Cmd = &cobra.Command{
		Use:   "overlay",
		Short: "Overlay network node daemon",
		Long:  "A transport layer overlay network. Node joined to the ToH server, and can be accessed by ToH clients",
		Args:  cobra.NoArgs,
		RunE:  runAction,
	}
	Cmd.Flags().StringP("server", "s", "", "the ToH server address")
	Cmd.Flags().StringP("key", "k", "", "the ToH api-key for authcate")
	Cmd.Flags().Duration("keepalive", 0, "http/ws conn keepalive (0s use system default)")
	Cmd.Flags().StringSliceP("route", "r", []string{}, "transport layer route (ip:port[/tcp|/tcp4|/tcp6|/udp|/udp4|/udp6])")

	Cmd.MarkFlagRequired("server")
	Cmd.MarkFlagRequired("key")
	Cmd.MarkFlagRequired("route")
}

type options struct {
	server    string
	key       string
	keepalive time.Duration
	routes    []string
}

func runAction(cmd *cobra.Command, args []string) error {
	options, err := processOptions(cmd)
	if err != nil {
		return err
	}

	network := OverlayNetwork{}

	control, err := network.Connect(options.server, options.key, options.keepalive)
	if err != nil {
		return err
	}
	defer control.Close()

	for _, route := range options.routes {
		// route format: ip:port[/tcp|/tcp4|/tcp6|/udp|/udp4|/udp6]
		routeParts := strings.Split(route, "/")
		if len(routeParts) == 1 {
			routeParts = append(routeParts, "tcp")
		}
		ip, port, err := net.SplitHostPort(routeParts[0])
		if err != nil {
			logrus.Errorf("invalid route %s: %s", route, err)
			continue
		}
		if ip == "" { // if no ip is specified, all ips of the routing node will be routed.
			err := walkNodeIps(func(ip net.IP) {
				if strings.HasSuffix(routeParts[1], "4") && ip.To4() == nil {
					return
				}
				if strings.HasSuffix(routeParts[1], "6") && ip.To4() != nil {
					return
				}
				control.Route(routeParts[1], net.JoinHostPort(ip.String(), port))
			})
			if err != nil {
				return fmt.Errorf("failed to walk node ips: %w", err)
			}
			continue
		}
		control.Route(routeParts[1], routeParts[0])
	}
	err = control.Run()
	if err != nil {
		logrus.Error(err)
	}
	return nil
}

// walkNodeIps walk all node ips
func walkNodeIps(callback func(ip net.IP)) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			logrus.Error(err)
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.IsLoopback() { // skip loopback ip
				continue
			}
			callback(ipNet.IP)
		}
	}
	return nil
}

func processOptions(cmd *cobra.Command) (options options, err error) {
	options.server, err = cmd.Flags().GetString("server")
	if err != nil {
		return
	}
	options.key, err = cmd.Flags().GetString("key")
	if err != nil {
		return
	}
	options.keepalive, err = cmd.Flags().GetDuration("keepalive")
	if err != nil {
		return
	}
	if options.keepalive == 0 {
		options.keepalive = 10 * time.Second
	}
	options.routes, err = cmd.Flags().GetStringSlice("route")
	return
}
