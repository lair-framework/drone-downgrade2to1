package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/lair-framework/go-lair"
	lv1 "gopkg.in/lair-framework/go-lair.v1"
)

const (
	usage = `
Usage:
  drone-downgrade2to1 <filename>
`
)

func main() {
	flag.Usage = func() {
		fmt.Println(usage)
	}
	flag.Parse()
	var filename string
	switch len(flag.Args()) {
	case 1:
		filename = flag.Arg(0)
	default:
		log.Fatal("Fatal: Missing required argument")
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Fatal: Could not open file. Error %s", err.Error())
	}
	l2 := lair.Project{}
	if err := json.Unmarshal(data, &l2); err != nil {
		log.Fatalf("Fatal: Could not parse JSON. Error %s", err.Error())
	}
	l1 := lv1.Project{
		Id:           l2.ID,
		ProjectName:  l2.Name,
		Description:  l2.Description,
		CreationDate: l2.CreatedAt,
		DroneLog:     l2.DroneLog,
		Industry:     l2.Industry,
	}
	for _, h := range l2.Hosts {
		l1Host := lv1.Host{
			Id:             h.ID,
			Alive:          true,
			Status:         h.Status,
			LongAddr:       h.LongIPv4Addr,
			StringAddr:     h.IPv4,
			MacAddr:        h.MAC,
			Flag:           h.IsFlagged,
			Hostnames:      h.Hostnames,
			LastModifiedBy: h.LastModifiedBy,
			OS: []lv1.OS{
				lv1.OS{
					Weight:      h.OS.Weight,
					Fingerprint: h.OS.Fingerprint,
					Tool:        h.OS.Tool,
				},
			},
		}
		for _, n := range h.Notes {
			l1Host.Notes = append(l1Host.Notes, lv1.Note{
				Title:          n.Title,
				Content:        n.Content,
				LastModifiedBy: n.LastModifiedBy,
			})
		}
		for _, s := range h.Services {
			l1Port := lv1.Port{
				Id:             s.ID,
				Alive:          true,
				Flag:           s.IsFlagged,
				Status:         s.Status,
				Port:           s.Port,
				Protocol:       s.Protocol,
				Service:        s.Service,
				Product:        s.Product,
				LastModifiedBy: s.LastModifiedBy,
			}
			for _, n := range h.Notes {
				l1Port.Notes = append(l1Port.Notes, lv1.Note{
					Title:   n.Title,
					Content: n.Content,
				})
			}
			l1Host.Ports = append(l1Host.Ports, l1Port)
		}
		l1.Hosts = append(l1.Hosts, l1Host)
		for _, n := range l2.Notes {
			l1.Notes = append(l1.Notes, lv1.Note{
				Title:   n.Title,
				Content: n.Content,
			})
		}
		for _, c := range l2.Commands {
			l1.Commands = append(l1.Commands, lv1.Command{
				Command: c.Command,
				Tool:    c.Tool,
			})
		}
		for _, i := range l2.Issues {
			l1Vuln := lv1.Vulnerability{
				Title:          i.Title,
				Status:         i.Status,
				Confirmed:      i.IsConfirmed,
				Cves:           i.CVEs,
				Cvss:           i.CVSS,
				Description:    i.Description,
				Evidence:       i.Evidence,
				Solution:       i.Solution,
				Flag:           i.IsFlagged,
				LastModifiedBy: i.LastModifiedBy,
			}
			for _, ident := range i.IdentifiedBy {
				l1Vuln.IdentifiedBy = append(l1Vuln.IdentifiedBy, lv1.IdentifiedBy{
					Tool: ident.Tool,
				})
			}
			for _, h := range i.Hosts {
				l1Vuln.Hosts = append(l1Vuln.Hosts, lv1.VulnerabilityHost{
					StringAddr: h.IPv4,
					Port:       h.Port,
					Protocol:   h.Protocol,
				})
			}
			for _, n := range i.Notes {
				l1Vuln.Notes = append(l1Vuln.Notes, lv1.Note{
					Title:   n.Title,
					Content: n.Content,
				})
			}
			for _, p := range i.PluginIDs {
				l1Vuln.PluginIds = append(l1Vuln.PluginIds, lv1.PluginId{
					Id:   p.ID,
					Tool: p.Tool,
				})
			}
			l1.Vulnerabilities = append(l1.Vulnerabilities, l1Vuln)
		}
	}

	buf, err := json.Marshal(l1)
	if err != nil {
		log.Fatalf("Fatal: Could not stringify JSON. Error %s", err.Error())
	}
	fmt.Println(string(buf))
}
