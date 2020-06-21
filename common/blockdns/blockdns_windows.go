// +build windows

package blockdns

import (
	"fmt"
	"math"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/eycorsican/go-tun2socks/common/log"
	win "github.com/eycorsican/go-tun2socks/common/winsys"
)

func FixDnsLeakage(tunName string) error {
	// Open the engine with a session.
	var engine uintptr
	session := &win.FWPM_SESSION0{Flags: win.FWPM_SESSION_FLAG_DYNAMIC}
	err := win.FwpmEngineOpen0(nil, win.RPC_C_AUTHN_DEFAULT, nil, session, unsafe.Pointer(&engine))
	if err != nil {
		return fmt.Errorf("failed to open engine: %v", err)
	}

	// Add a sublayer.
	key, err := windows.GenerateGUID()
	if err != nil {
		return fmt.Errorf("failed to generate GUID: %v", err)
	}
	displayData, err := win.CreateDisplayData("Mellow", "Sublayer")
	if err != nil {
		return fmt.Errorf("failed to create display data: %v", err)
	}
	sublayer := win.FWPM_SUBLAYER0{}
	sublayer.SubLayerKey = key
	sublayer.DisplayData = *displayData
	sublayer.Weight = math.MaxUint16
	err = win.FwpmSubLayerAdd0(engine, &sublayer, 0)
	if err != nil {
		return fmt.Errorf("failed to add sublayer: %v", err)
	}

	var filterId uint64

	// Block all IPv6 traffic.
	blockV6FilterDisplayData, err := win.CreateDisplayData("Mellow", "Block all IPv6 traffic")
	if err != nil {
		return fmt.Errorf("failed to create block v6 filter filter display data: %v", err)
	}
	blockV6Filter := win.FWPM_FILTER0{}
	blockV6Filter.DisplayData = *blockV6FilterDisplayData
	blockV6Filter.SubLayerKey = key
	blockV6Filter.LayerKey = win.FWPM_LAYER_ALE_AUTH_CONNECT_V6
	blockV6Filter.Action.Type = win.FWP_ACTION_BLOCK
	blockV6Filter.Weight.Type = win.FWP_UINT8
	blockV6Filter.Weight.Value = uintptr(13)
	err = win.FwpmFilterAdd0(engine, &blockV6Filter, 0, &filterId)
	if err != nil {
		return fmt.Errorf("failed to add block v6 filter: %v", err)
	}
	log.Debugf("Added filter to block all IPv6 traffic")

	// Allow all IPv4 traffic from the current process i.e. Mellow.
	appID, err := win.GetCurrentProcessAppID()
	if err != nil {
		return err
	}
	defer win.FwpmFreeMemory0(unsafe.Pointer(&appID))
	permitMellowCondition := make([]win.FWPM_FILTER_CONDITION0, 1)
	permitMellowCondition[0].FieldKey = win.FWPM_CONDITION_ALE_APP_ID
	permitMellowCondition[0].MatchType = win.FWP_MATCH_EQUAL
	permitMellowCondition[0].ConditionValue.Type = win.FWP_BYTE_BLOB_TYPE
	permitMellowCondition[0].ConditionValue.Value = uintptr(unsafe.Pointer(appID))
	permitMellowFilterDisplayData, err := win.CreateDisplayData("Mellow", "Permit all Mellow traffic")
	if err != nil {
		return fmt.Errorf("failed to create permit Mellow filter display data: %v", err)
	}
	permitMellowFilter := win.FWPM_FILTER0{}
	permitMellowFilter.FilterCondition = (*win.FWPM_FILTER_CONDITION0)(unsafe.Pointer(&permitMellowCondition[0]))
	permitMellowFilter.NumFilterConditions = 1
	permitMellowFilter.DisplayData = *permitMellowFilterDisplayData
	permitMellowFilter.SubLayerKey = key
	permitMellowFilter.LayerKey = win.FWPM_LAYER_ALE_AUTH_CONNECT_V4
	permitMellowFilter.Action.Type = win.FWP_ACTION_PERMIT
	permitMellowFilter.Weight.Type = win.FWP_UINT8
	permitMellowFilter.Weight.Value = uintptr(12)
	permitMellowFilter.Flags = win.FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
	err = win.FwpmFilterAdd0(engine, &permitMellowFilter, 0, &filterId)
	if err != nil {
		return fmt.Errorf("failed to add permit Mellow filter: %v", err)
	}
	log.Debugf("Added filter to allow all traffic from Mellow")

	// Allow all IPv4 traffic to the TAP adapter.
	iface, err := net.InterfaceByName(tunName)
	if err != nil {
		return fmt.Errorf("fialed to get interface by name %v: %v", tunName, err)
	}
	tapWhitelistCondition := make([]win.FWPM_FILTER_CONDITION0, 1)
	tapWhitelistCondition[0].FieldKey = win.FWPM_CONDITION_LOCAL_INTERFACE_INDEX
	tapWhitelistCondition[0].MatchType = win.FWP_MATCH_EQUAL
	tapWhitelistCondition[0].ConditionValue.Type = win.FWP_UINT32
	tapWhitelistCondition[0].ConditionValue.Value = uintptr(uint32(iface.Index))
	tapWhitelistFilterDisplayData, err := win.CreateDisplayData("Mellow", "Allow all traffic to the TAP device")
	if err != nil {
		return fmt.Errorf("failed to create tap device whitelist filter display data: %v", err)
	}
	tapWhitelistFilter := win.FWPM_FILTER0{}
	tapWhitelistFilter.FilterCondition = (*win.FWPM_FILTER_CONDITION0)(unsafe.Pointer(&tapWhitelistCondition[0]))
	tapWhitelistFilter.NumFilterConditions = 1
	tapWhitelistFilter.DisplayData = *tapWhitelistFilterDisplayData
	tapWhitelistFilter.SubLayerKey = key
	tapWhitelistFilter.LayerKey = win.FWPM_LAYER_ALE_AUTH_CONNECT_V4
	tapWhitelistFilter.Action.Type = win.FWP_ACTION_PERMIT
	tapWhitelistFilter.Weight.Type = win.FWP_UINT8
	tapWhitelistFilter.Weight.Value = uintptr(11)
	err = win.FwpmFilterAdd0(engine, &tapWhitelistFilter, 0, &filterId)
	if err != nil {
		return fmt.Errorf("failed to add tap device whitelist filter: %v", err)
	}
	log.Debugf("Added filter to allow all traffic to %v", tunName)

	// Block all UDP traffic targeting port 53.
	blockAllUDP53Condition := make([]win.FWPM_FILTER_CONDITION0, 2)
	blockAllUDP53Condition[0].FieldKey = win.FWPM_CONDITION_IP_PROTOCOL
	blockAllUDP53Condition[0].MatchType = win.FWP_MATCH_EQUAL
	blockAllUDP53Condition[0].ConditionValue.Type = win.FWP_UINT8
	blockAllUDP53Condition[0].ConditionValue.Value = uintptr(uint8(win.IPPROTO_UDP))
	blockAllUDP53Condition[1].FieldKey = win.FWPM_CONDITION_IP_REMOTE_PORT
	blockAllUDP53Condition[1].MatchType = win.FWP_MATCH_EQUAL
	blockAllUDP53Condition[1].ConditionValue.Type = win.FWP_UINT16
	blockAllUDP53Condition[1].ConditionValue.Value = uintptr(uint16(53))
	blockAllUDP53FilterDisplayData, err := win.CreateDisplayData("Mellow", "Block all UDP traffic targeting port 53")
	if err != nil {
		return fmt.Errorf("failed to create filter display data: %v", err)
	}
	blockAllUDP53Filter := win.FWPM_FILTER0{}
	blockAllUDP53Filter.FilterCondition = (*win.FWPM_FILTER_CONDITION0)(unsafe.Pointer(&blockAllUDP53Condition[0]))
	blockAllUDP53Filter.NumFilterConditions = 2
	blockAllUDP53Filter.DisplayData = *blockAllUDP53FilterDisplayData
	blockAllUDP53Filter.SubLayerKey = key
	blockAllUDP53Filter.LayerKey = win.FWPM_LAYER_ALE_AUTH_CONNECT_V4
	blockAllUDP53Filter.Action.Type = win.FWP_ACTION_BLOCK
	blockAllUDP53Filter.Weight.Type = win.FWP_UINT8
	blockAllUDP53Filter.Weight.Value = uintptr(10)
	err = win.FwpmFilterAdd0(engine, &blockAllUDP53Filter, 0, &filterId)
	if err != nil {
		return fmt.Errorf("failed to add filter: %v", err)
	}
	log.Debugf("Added filter to block all udp traffic targeting 53 remote port")

	return nil
}
