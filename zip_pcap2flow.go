package main

import (
	"archive/zip"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"gonum.org/v1/gonum/stat"

	"time"
)

type PacketFlow struct {
	Attack string
	// Sender IP address
	NwSrc string
	// Receiver IP address
	NwDst          string
	PortSrc        string
	PortDst        string
	DlSrc          string
	DlDst          string
	ByteCount      uint64
	Measures       uint64
	Packets        uint64
	LastSeqno      uint64
	FirstTimeSeen  time.Time
	LastTimeSeen   time.Time
	LastTimeUpdate time.Time
	IdleTime       time.Duration
	ActiveTime     time.Duration
	Fiat           []float64
	Biat           []float64
	Flowiat        []float64
	FbPsec         []float64
	FpPsec         []float64
	BytesPending   int
	PacketsPending uint64
}

func (pf PacketFlow) FlowDuration() time.Duration {
	return pf.LastTimeSeen.Sub(pf.FirstTimeSeen)
}

func AverageFloat64(values []float64) float64 {
	numerator := 0.0
	denominator := 0.0
	for _, v := range values {
		denominator++
		numerator += v
	}
	if denominator > 0 {
		return numerator / denominator
	} else {
		return 0
	}
}

func SumFloat64(values []float64) float64 {
	acc := 0.0
	for _, v := range values {
		acc += v
	}
	return acc
}

func MinFloat64(values []float64) float64 {
	min := math.MaxFloat64
	for _, value := range values {
		if min > value {
			min = value
		}
	}
	return min
}

func MaxFloat64(values []float64) float64 {
	max := 0.0
	for _, value := range values {
		if max < value {
			max = value
		}
	}
	return max
}

func (pf PacketFlow) ToStringArray() []string {
	return []string{
		// duration
		strconv.FormatFloat(pf.LastTimeUpdate.Sub(pf.FirstTimeSeen).Seconds(), 'f', -1, 64),

		// total_fiat, total_biat
		strconv.FormatFloat(SumFloat64(pf.Fiat), 'f', -1, 64),
		strconv.FormatFloat(SumFloat64(pf.Biat), 'f', -1, 64),

		// Min
		strconv.FormatFloat(MinFloat64(pf.Fiat), 'f', -1, 64),
		strconv.FormatFloat(MinFloat64(pf.Biat), 'f', -1, 64),

		// Max
		strconv.FormatFloat(MaxFloat64(pf.Fiat), 'f', -1, 64),
		strconv.FormatFloat(MaxFloat64(pf.Biat), 'f', -1, 64),

		// Average
		strconv.FormatFloat(AverageFloat64(pf.Fiat), 'f', -1, 64),
		strconv.FormatFloat(AverageFloat64(pf.Biat), 'f', -1, 64),

		// Packets and Bytes per second, average
		strconv.FormatFloat(AverageFloat64(pf.FpPsec), 'f', -1, 64),
		strconv.FormatFloat(AverageFloat64(pf.FbPsec), 'f', -1, 64),

		// min, max and mean, std of flowiat
		strconv.FormatFloat(MinFloat64(pf.Flowiat), 'f', -1, 64),
		strconv.FormatFloat(MaxFloat64(pf.Flowiat), 'f', -1, 64),
		strconv.FormatFloat(AverageFloat64(pf.Flowiat), 'f', -1, 64),
		strconv.FormatFloat(stat.StdDev(pf.Flowiat, nil), 'f', -1, 64),

		// min, mean, max std active
		// min, mean, max std idle

		// Attack
		pf.Attack,
	}
}

type FlowKey string

func (pf PacketFlow) Key() string {
	return fmt.Sprint(pf.NwSrc, pf.PortSrc, pf.NwDst, pf.PortDst)
}

func (pf PacketFlow) ReverseKey() string {
	return fmt.Sprint(pf.NwDst, pf.PortDst, pf.NwSrc, pf.PortSrc)
}

type FlowAccumulator struct {
	Flows       map[FlowKey]*PacketFlow
	LastTime    time.Time
	CurrentTime time.Time
	InitialTime time.Time
}

func (acc FlowAccumulator) PacketFlowKey(packet gopacket.Packet) FlowKey {
	PortSrc := ""
	PortDst := ""
	NwSrc := ""
	NwDst := ""
	if packet.NetworkLayer() != nil {
		NwSrc = packet.NetworkLayer().NetworkFlow().Src().String()
		NwDst = packet.NetworkLayer().NetworkFlow().Dst().String()
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		PortSrc = tcpLayer.(*layers.TCP).SrcPort.String()
		PortDst = tcpLayer.(*layers.TCP).DstPort.String()
	}

	str := fmt.Sprint(NwSrc, PortSrc, NwDst, PortDst, acc.AttackString(packet))
	return FlowKey(str)
}

func (acc FlowAccumulator) PacketReverseFlowKey(packet gopacket.Packet) FlowKey {
	PortSrc := ""
	PortDst := ""
	NwSrc := ""
	NwDst := ""
	if packet.NetworkLayer() != nil {
		NwSrc = packet.NetworkLayer().NetworkFlow().Src().String()
		NwDst = packet.NetworkLayer().NetworkFlow().Dst().String()
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		PortSrc = tcpLayer.(*layers.TCP).SrcPort.String()
		PortDst = tcpLayer.(*layers.TCP).DstPort.String()
	}

	str := fmt.Sprint(NwDst, PortDst, NwSrc, PortSrc, acc.AttackString(packet))
	return FlowKey(str)
}

// AttackString generates attack name given packet time of arrival
func (acc FlowAccumulator) AttackString(packet gopacket.Packet) string {
	if *isAttack {
		return "attack"
	}
	return "normal"
}

// FlowFromPacket creates a new Flow from a packet
func (acc FlowAccumulator) FlowFromPacket(packet gopacket.Packet) *PacketFlow {
	PortSrc := ""
	PortDst := ""
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		PortSrc = tcpLayer.(*layers.TCP).SrcPort.String()
		PortDst = tcpLayer.(*layers.TCP).DstPort.String()
	}

	NwSrc := ""
	NwDst := ""
	if packet.NetworkLayer() != nil {
		NwSrc = packet.NetworkLayer().NetworkFlow().Src().String()
		NwDst = packet.NetworkLayer().NetworkFlow().Dst().String()
	}

	flow := &PacketFlow{
		Attack: acc.AttackString(packet),
		// Sender IP address
		NwSrc: NwSrc,
		// Receiver IP address
		NwDst: NwDst,

		PortSrc: PortSrc,
		PortDst: PortDst,
		//DlSrc        string
		//DlDst        string
		ByteCount:      0,
		Measures:       0,
		Packets:        0,
		LastSeqno:      0,
		LastTimeSeen:   acc.CurrentTime,
		FirstTimeSeen:  acc.CurrentTime,
		Fiat:           make([]float64, 10),
		Biat:           make([]float64, 10),
		Flowiat:        make([]float64, 10),
		FbPsec:         make([]float64, 10),
		FpPsec:         make([]float64, 10),
		BytesPending:   0,
		PacketsPending: 0,
	}
	return flow
}

// RegisterPacket adds a packet in the Flow Accumulator
func (acc *FlowAccumulator) RegisterPacket(packet gopacket.Packet, flowChan chan *PacketFlow) {
	flowKey := acc.PacketReverseFlowKey(packet)
	flow, ok := acc.Flows[flowKey]
	isBackwards := ok
	packetSize := len(packet.Data())
	var sinceLastTime time.Duration

	if isBackwards {
		// This is a backward flow
		sinceLastTime = acc.CurrentTime.Sub(flow.LastTimeSeen)
	} else {
		flowKey = acc.PacketFlowKey(packet)
		flow, ok = acc.Flows[flowKey]
		if !ok {
			// This is a new forward flow
			flow = acc.FlowFromPacket(packet)
		}
		sinceLastTime = acc.CurrentTime.Sub(flow.LastTimeSeen)
	}

	if acc.CurrentTime.Sub(flow.FirstTimeSeen) > 15*time.Second {
		// Create a new flow
		flowChan <- flow
		delete(acc.Flows, flowKey)
		acc.RegisterPacket(packet, flowChan)
		return
	}

	if isBackwards {
		if sinceLastTime > 0 {
			flow.Biat = append(flow.Biat, sinceLastTime.Seconds())
		}
	} else {
		// Update all the flow information
		if sinceLastTime > 0 {
			flow.Fiat = append(flow.Fiat, sinceLastTime.Seconds())
		}
	}

	if sinceLastTime > 0 {
		flow.FbPsec = append(flow.FbPsec, float64(packetSize+flow.BytesPending)/sinceLastTime.Seconds())
		flow.FpPsec = append(flow.FpPsec, float64(1+flow.PacketsPending)/sinceLastTime.Seconds())
		flow.Flowiat = append(flow.Flowiat, sinceLastTime.Seconds())
		flow.BytesPending = 0
		flow.PacketsPending = 0
	} else {
		flow.BytesPending += packetSize
		flow.PacketsPending++
	}
	flow.ByteCount += uint64(packetSize)
	flow.Measures++
	flow.Packets++
	if sinceLastTime < 5*time.Second {
		flow.ActiveTime += sinceLastTime
	} else {
		flow.IdleTime += sinceLastTime
	}
	flow.LastTimeSeen = acc.CurrentTime
	flow.LastTimeUpdate = acc.CurrentTime

	acc.Flows[flowKey] = flow
}

var count = 0

func handlePacket(packet gopacket.Packet) {
	count++
	if count%1000000 == 0 {
		fmt.Println("Packets:", count)
	}
}

var source = flag.String("source", "", "PCAP With source traffic")
var destination = flag.String("output", "", "Output CSV")
var isAttack = flag.Bool("attack", false, "Determines if source PCAP is attack or not")

func main() {
	flag.Parse()
	if *source == "" || *destination == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}
	flows := FlowAccumulator{
		Flows: make(map[FlowKey]*PacketFlow),
	}
	generatedFlows := make(chan *PacketFlow, 100)
	firstPacket := true

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()

		r, err := zip.OpenReader(*source)
		if err != nil {
			log.Fatal(err)
		}
		defer r.Close()

		for _, f := range r.File {
			log.Println(f.Name)
			rc, err := f.Open()
			if err != nil {
				log.Fatal(err)
			}

			if strings.HasSuffix(f.Name, ".pcapng") {
				ngReader, err := pcapgo.NewNgReader(rc, pcapgo.DefaultNgReaderOptions)
				if err != nil {
					log.Println(err)
					rc.Close()
					continue
				}
				packetSource := gopacket.NewPacketSource(ngReader, ngReader.LinkType())

				for packet := range packetSource.Packets() {
					if firstPacket {
						flows.InitialTime = packet.Metadata().CaptureInfo.Timestamp
						firstPacket = false
					}
					flows.CurrentTime = packet.Metadata().CaptureInfo.Timestamp
					flows.RegisterPacket(packet, generatedFlows)
					handlePacket(packet)
					flows.LastTime = flows.CurrentTime
				}
			} else {
				pcapReader, err := pcapgo.NewReader(rc)
				if err != nil {
					log.Println(err)
					rc.Close()
					continue
				}
				packetSource := gopacket.NewPacketSource(pcapReader, pcapReader.LinkType())
				for packet := range packetSource.Packets() {
					if firstPacket {
						flows.InitialTime = packet.Metadata().CaptureInfo.Timestamp
						firstPacket = false
					}
					flows.CurrentTime = packet.Metadata().CaptureInfo.Timestamp
					flows.RegisterPacket(packet, generatedFlows)
					handlePacket(packet)
					flows.LastTime = flows.CurrentTime
				}
			}

			rc.Close()

			for k, flow := range flows.Flows {
				generatedFlows <- flow
				delete(flows.Flows, k)
			}
		}
		close(generatedFlows)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		file, err := os.Create(*destination)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		writer := csv.NewWriter(file)
		defer writer.Flush()

		count := 0
		for v := range generatedFlows {
			count++
			err := writer.Write(v.ToStringArray())
			if count%10000 == 0 {
				fmt.Println("Flows:", count)
			}
			if err != nil {
				panic(err)
			}
		}
	}()

	wg.Wait()
}
