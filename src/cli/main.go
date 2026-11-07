// Command-line interface for vTPM2. Connects to the running vTPM2 service
// (HTTP API on 127.0.0.1:8082 by default) and issues TPM 2.0 commands.
// Usage: vtpm2cli <command> [args...]
//
// Commands:
//   status                  Show engine status
//   capability              Show TPM capabilities (TPM_CAP_TPM_PROPERTIES)
//   pcr-read <alg> <pcr>    Read a PCR bank entry (e.g. sha256 0)
//   pcr-extend <alg> <pcr> <hexdigest>  Extend a PCR with a digest
//   nv-define <index> <size>  Define an NV index
//   nv-read <index> <offset> <size>   Read NV data
//   nv-write <index> <offset> <hexdata>  Write NV data
//   nv-undefine <index>   Undefine an NV index
//   create-primary          Create a primary key under Owner hierarchy
//   get-random <bytes>      Get random bytes
//   backup <file>           Backup persistent state to file
//   restore <file>          Restore persistent state from file
//   command <hexcmd>        Execute a raw TPM command blob (hex)

package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-sdk-vtpm2/tpm2"
)

const defaultURL = "http://127.0.0.1:8082"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	url := os.Getenv("VTPM2_URL")
	if url == "" {
		url = defaultURL
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "status":
		cmdStatus(url)
	case "capability":
		cmdCapability(url)
	case "pcr-read":
		if len(args) < 2 {
			fail("usage: vtpm2cli pcr-read <alg> <pcr>")
		}
		cmdPCRRead(url, args[0], args[1])
	case "pcr-extend":
		if len(args) < 3 {
			fail("usage: vtpm2cli pcr-extend <alg> <pcr> <hexdigest>")
		}
		cmdPCRExtend(url, args[0], args[1], args[2])
	case "nv-define":
		if len(args) < 2 {
			fail("usage: vtpm2cli nv-define <index> <size>")
		}
		cmdNVDefine(url, args[0], args[1])
	case "nv-read":
		if len(args) < 3 {
			fail("usage: vtpm2cli nv-read <index> <offset> <size>")
		}
		cmdNVRead(url, args[0], args[1], args[2])
	case "nv-write":
		if len(args) < 3 {
			fail("usage: vtpm2cli nv-write <index> <offset> <hexdata>")
		}
		cmdNVWrite(url, args[0], args[1], args[2])
	case "nv-undefine":
		if len(args) < 1 {
			fail("usage: vtpm2cli nv-undefine <index>")
		}
		cmdNVOndefine(url, args[0])
	case "create-primary":
		cmdCreatePrimary(url)
	case "get-random":
		if len(args) < 1 {
			fail("usage: vtpm2cli get-random <bytes>")
		}
		cmdGetRandom(url, args[0])
	case "backup":
		if len(args) < 1 {
			fail("usage: vtpm2cli backup <file>")
		}
		cmdBackup(url, args[0])
	case "restore":
		if len(args) < 1 {
			fail("usage: vtpm2cli restore <file>")
		}
		cmdRestore(url, args[0])
	case "command":
		if len(args) < 1 {
			fail("usage: vtpm2cli command <hexcmd>")
		}
		cmdCommand(url, args[0])
	case "help", "--help", "-h":
		printUsage()
	default:
		fail("unknown command: %s", cmd)
	}
}

func printUsage() {
	fmt.Println("vtpm2cli — vTPM2 command-line interface")
	fmt.Println()
	fmt.Println("Connects to the vTPM2 service (VTPM2_URL, default http://127.0.0.1:8082).")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  status                      Show engine status")
	fmt.Println("  capability                  Show TPM capabilities")
	fmt.Println("  pcr-read <alg> <pcr>        Read a PCR (e.g. sha256 0)")
	fmt.Println("  pcr-extend <alg> <pcr> <hexdigest>")
	fmt.Println("                                Extend a PCR with a digest")
	fmt.Println("  nv-define <index> <size>    Define an NV index")
	fmt.Println("  nv-read <index> <off> <sz>  Read NV data")
	fmt.Println("  nv-write <index> <off> <hex>")
	fmt.Println("                                Write NV data")
	fmt.Println("  nv-undefine <index>         Undefine an NV index")
	fmt.Println("  create-primary              Create a primary key")
	fmt.Println("  get-random <n>              Get random bytes")
	fmt.Println("  backup <file>               Backup state")
	fmt.Println("  restore <file>              Restore state")
	fmt.Println("  command <hex>               Raw TPM command")
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "vtpm2cli: "+format+"\n", args...)
	os.Exit(1)
}

func getJSON(url string, path string, out interface{}) error {
	resp, err := http.Get(url + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func postJSON(url string, path string, body interface{}, out interface{}) error {
	var b io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		b = strings.NewReader(string(data))
	}
	resp, err := http.Post(url+path, "application/json", b)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func postRaw(url string, path string, body []byte, out *[]byte) error {
	resp, err := http.Post(url+path, "application/octet-stream", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	*out = raw
	return nil
}

func cmdStatus(url string) {
	var st map[string]interface{}
	if err := getJSON(url, "/api/status", &st); err != nil {
		fail("status: %v", err)
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	fmt.Println(string(b))
}

func cmdCapability(url string) {
	var cap map[string]interface{}
	if err := getJSON(url, "/api/capability", &cap); err != nil {
		fail("capability: %v", err)
	}
	b, _ := json.MarshalIndent(cap, "", "  ")
	fmt.Println(string(b))
}

func algID(name string) uint16 {
	switch strings.ToLower(name) {
	case "sha1":
		return tpm2.AlgSHA1
	case "sha256":
		return tpm2.AlgSHA256
	case "sha384":
		return tpm2.AlgSHA384
	case "sha512":
		return tpm2.AlgSHA512
	default:
		fail("unsupported algorithm: %s", name)
		return 0
	}
}

func cmdPCRRead(url string, algName string, pcrStr string) {
	alg := algID(algName)
	pcr, err := strconv.Atoi(pcrStr)
	if err != nil {
		fail("invalid PCR index: %s", pcrStr)
	}
	var sel [4 + 2 + 1 + 3]byte
	binary.BigEndian.PutUint32(sel[0:], 1) // count
	binary.BigEndian.PutUint16(sel[4:], alg)
	sel[6] = 3
	sel[7] = byte(pcr)
	sel[8] = 0
	sel[9] = 0
	cmd := buildCmd(tpm2.TPMSTNoSessions, tpm2.CCPCRRead, sel[:])
	var resp map[string]interface{}
	if err := postJSON(url, "/api/command", map[string]interface{}{"command": hex.EncodeToString(cmd)}, &resp); err != nil {
		fail("pcr-read: %v", err)
	}
	fmt.Println(resp["response"])
}

func cmdPCRExtend(url string, algName string, pcrStr string, digestHex string) {
	alg := algID(algName)
	pcr, err := strconv.Atoi(pcrStr)
	if err != nil {
		fail("invalid PCR index: %s", pcrStr)
	}
	digest, err := hex.DecodeString(digestHex)
	if err != nil {
		fail("invalid digest hex: %v", err)
	}
	pcrHandle := make([]byte, 4)
	binary.BigEndian.PutUint32(pcrHandle, uint32(pcr))
	auth := authArea(tpm2.RHPW, 0)
	digestVals := make([]byte, 4+2+2+len(digest))
	binary.BigEndian.PutUint32(digestVals[0:], 1)
	binary.BigEndian.PutUint16(digestVals[4:], alg)
	binary.BigEndian.PutUint16(digestVals[6:], uint16(len(digest)))
	copy(digestVals[8:], digest)
	params := cmdParams([]uint32{uint32(pcr)}, auth, digestVals)
	cmd := buildCmd(tpm2.TPMSTSessions, tpm2.CCPCRExtend, params)
	var resp map[string]interface{}
	if err := postJSON(url, "/api/command", map[string]interface{}{"command": hex.EncodeToString(cmd)}, &resp); err != nil {
		fail("pcr-extend: %v", err)
	}
	fmt.Println(resp["response"])
}

func cmdNVDefine(url string, indexStr string, sizeStr string) {
	index, err := strconv.ParseUint(indexStr, 0, 32)
	if err != nil {
		fail("invalid NV index: %s", indexStr)
	}
	size, err := strconv.Atoi(sizeStr)
	if err != nil {
		fail("invalid NV size: %s", sizeStr)
	}
	auth := authArea(tpm2.RHOwner, 0)
	authTpm2b := []byte{0, 0}
	public := make([]byte, 4+2+4+2+2)
	binary.BigEndian.PutUint32(public[0:], uint32(index))
	binary.BigEndian.PutUint16(public[4:], tpm2.AlgSHA256)
	binary.BigEndian.PutUint32(public[6:], tpm2.NVPPWrite|tpm2.NVPPRead|tpm2.NVAuthWrite|tpm2.NVAuthRead|tpm2.NVOwnerWrite|tpm2.NVOwnerRead)
	binary.BigEndian.PutUint16(public[10:], 0)
	binary.BigEndian.PutUint16(public[12:], uint16(size))
	params := cmdParams([]uint32{tpm2.RHOwner}, auth, authTpm2b, u16(uint16(len(public))), public)
	cmd := buildCmd(tpm2.TPMSTSessions, tpm2.CCNVDefineSpace, params)
	var resp map[string]interface{}
	if err := postJSON(url, "/api/command", map[string]interface{}{"command": hex.EncodeToString(cmd)}, &resp); err != nil {
		fail("nv-define: %v", err)
	}
	fmt.Println(resp["response"])
}

func cmdNVRead(url string, indexStr string, offsetStr string, sizeStr string) {
	index, err := strconv.ParseUint(indexStr, 0, 32)
	if err != nil {
		fail("invalid NV index: %s", indexStr)
	}
	offset, err := strconv.Atoi(offsetStr)
	if err != nil {
		fail("invalid offset: %s", offsetStr)
	}
	size, err := strconv.Atoi(sizeStr)
	if err != nil {
		fail("invalid size: %s", sizeStr)
	}
	auth := authArea(tpm2.RHOwner, 0)
	readParams := make([]byte, 2+2)
	binary.BigEndian.PutUint16(readParams[0:], uint16(size))
	binary.BigEndian.PutUint16(readParams[2:], uint16(offset))
	params := cmdParams([]uint32{tpm2.RHOwner, uint32(index)}, auth, readParams)
	cmd := buildCmd(tpm2.TPMSTSessions, tpm2.CCNVRead, params)
	var resp map[string]interface{}
	if err := postJSON(url, "/api/command", map[string]interface{}{"command": hex.EncodeToString(cmd)}, &resp); err != nil {
		fail("nv-read: %v", err)
	}
	fmt.Println(resp["response"])
}

func cmdNVWrite(url string, indexStr string, offsetStr string, dataHex string) {
	index, err := strconv.ParseUint(indexStr, 0, 32)
	if err != nil {
		fail("invalid NV index: %s", indexStr)
	}
	offset, err := strconv.Atoi(offsetStr)
	if err != nil {
		fail("invalid offset: %s", offsetStr)
	}
	data, err := hex.DecodeString(dataHex)
	if err != nil {
		fail("invalid data hex: %v", err)
	}
	auth := authArea(tpm2.RHOwner, 0)
	writeData := append(u16(uint16(len(data))), data...)
	writeData = append(writeData, u16(uint16(offset))...)
	params := cmdParams([]uint32{tpm2.RHOwner, uint32(index)}, auth, writeData)
	cmd := buildCmd(tpm2.TPMSTSessions, tpm2.CCNVWrite, params)
	var resp map[string]interface{}
	if err := postJSON(url, "/api/command", map[string]interface{}{"command": hex.EncodeToString(cmd)}, &resp); err != nil {
		fail("nv-write: %v", err)
	}
	fmt.Println(resp["response"])
}

func cmdNVOndefine(url string, indexStr string) {
	index, err := strconv.ParseUint(indexStr, 0, 32)
	if err != nil {
		fail("invalid NV index: %s", indexStr)
	}
	auth := authArea(tpm2.RHOwner, 0)
	params := cmdParams([]uint32{tpm2.RHOwner, uint32(index)}, auth)
	cmd := buildCmd(tpm2.TPMSTSessions, tpm2.CCNVUndefineSpace, params)
	var resp map[string]interface{}
	if err := postJSON(url, "/api/command", map[string]interface{}{"command": hex.EncodeToString(cmd)}, &resp); err != nil {
		fail("nv-undefine: %v", err)
	}
	fmt.Println(resp["response"])
}

func cmdCreatePrimary(url string) {
	auth := authArea(tpm2.RHOwner, 0)
	inSensitive := u16(4)
	inSensitive = append(inSensitive, u16(0)...)
	inSensitive = append(inSensitive, u16(0)...)
	publicFields := make([]byte, 2+2+4+2+2+2+2+2+2+2+4)
	binary.BigEndian.PutUint16(publicFields[0:], tpm2.AlgRSA)
	binary.BigEndian.PutUint16(publicFields[2:], tpm2.AlgSHA256)
	binary.BigEndian.PutUint32(publicFields[4:], tpm2.ObjFixedTPM|tpm2.ObjFixedParent|tpm2.ObjSensitiveDataOrigin|tpm2.ObjUserWithAuth|tpm2.ObjAdminWithPolicy|tpm2.ObjNoDA|tpm2.ObjRestricted|tpm2.ObjDecrypt|tpm2.ObjSign)
	binary.BigEndian.PutUint16(publicFields[8:], 0)
	binary.BigEndian.PutUint16(publicFields[10:], tpm2.AlgAES)
	binary.BigEndian.PutUint16(publicFields[12:], 128)
	binary.BigEndian.PutUint16(publicFields[14:], 0x0043)
	binary.BigEndian.PutUint16(publicFields[16:], tpm2.AlgNull)
	binary.BigEndian.PutUint16(publicFields[18:], 2048)
	binary.BigEndian.PutUint32(publicFields[20:], 65537)
	inPublic := append(u16(uint16(len(publicFields))), publicFields...)
	outsideInfo := u16(0)
	pcrs := u32(0)
	params := cmdParams([]uint32{tpm2.RHOwner}, auth, inSensitive, inPublic, outsideInfo, pcrs)
	cmd := buildCmd(tpm2.TPMSTSessions, tpm2.CCCreatePrimary, params)
	var resp map[string]interface{}
	if err := postJSON(url, "/api/command", map[string]interface{}{"command": hex.EncodeToString(cmd)}, &resp); err != nil {
		fail("create-primary: %v", err)
	}
	fmt.Println(resp["response"])
}

func cmdGetRandom(url string, nStr string) {
	n, err := strconv.Atoi(nStr)
	if err != nil {
		fail("invalid byte count: %s", nStr)
	}
	if n > 64 {
		fail("maximum 64 bytes per GetRandom call")
	}
	cmd := buildCmd(tpm2.TPMSTNoSessions, tpm2.CCGetRandom, u16(uint16(n)))
	var resp map[string]interface{}
	if err := postJSON(url, "/api/command", map[string]interface{}{"command": hex.EncodeToString(cmd)}, &resp); err != nil {
		fail("get-random: %v", err)
	}
	fmt.Println(resp["response"])
}

func cmdBackup(url string, file string) {
	resp, err := http.Get(url + "/api/state/backup")
	if err != nil {
		fail("backup: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fail("backup: HTTP %d: %s", resp.StatusCode, string(body))
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fail("backup: read body: %v", err)
	}
	if err := os.WriteFile(file, data, 0o600); err != nil {
		fail("backup: write file: %v", err)
	}
	fmt.Printf("state backed up to %s (%d bytes)\n", file, len(data))
}

func cmdRestore(url string, file string) {
	data, err := os.ReadFile(file)
	if err != nil {
		fail("restore: read file: %v", err)
	}
	var resp []byte
	if err := postRaw(url, "/api/state/restore", data, &resp); err != nil {
		fail("restore: %v", err)
	}
	fmt.Printf("state restored: %s\n", string(resp))
}

func cmdCommand(url string, hexCmd string) {
	cmd, err := hex.DecodeString(strings.ReplaceAll(hexCmd, " ", ""))
	if err != nil {
		fail("invalid hex command: %v", err)
	}
	var resp map[string]interface{}
	if err := postJSON(url, "/api/command", map[string]interface{}{"command": hex.EncodeToString(cmd)}, &resp); err != nil {
		fail("command: %v", err)
	}
	fmt.Println(resp["response"])
}

// ---- wire-format helpers ----

func buildCmd(tag uint16, code uint32, params []byte) []byte {
	out := make([]byte, 10+len(params))
	binary.BigEndian.PutUint16(out[0:], tag)
	binary.BigEndian.PutUint32(out[2:], uint32(len(out)))
	binary.BigEndian.PutUint32(out[6:], code)
	copy(out[10:], params)
	return out
}

func u16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func authArea(sessionHandle uint32, nonceLen int) []byte {
	sessionData := 2 + nonceLen + 1 + 2
	authSize := 4 + sessionData
	a := make([]byte, 4+authSize)
	binary.BigEndian.PutUint32(a[0:], uint32(authSize))
	binary.BigEndian.PutUint32(a[4:], sessionHandle)
	off := 8
	binary.BigEndian.PutUint16(a[off:], uint16(nonceLen))
	off += 2 + nonceLen
	a[off] = 0
	off++
	binary.BigEndian.PutUint16(a[off:], 0)
	return a
}

func cmdParams(handles []uint32, auth []byte, rest ...[]byte) []byte {
	p := make([]byte, 0)
	for _, h := range handles {
		p = append(p, u32(h)...)
	}
	p = append(p, auth...)
	for _, r := range rest {
		p = append(p, r...)
	}
	return p
}
