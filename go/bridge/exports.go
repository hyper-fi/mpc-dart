package main

/*
#include <stdlib.h>
*/
import "C"

import "unsafe"

//export MpcFreeCString
func MpcFreeCString(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

//export MpcVersion
func MpcVersion() *C.char {
	return C.CString(respond(func() (any, error) { return coreVersion(), nil }))
}

//export MpcEcdsaKeygen
func MpcEcdsaKeygen() *C.char {
	return C.CString(respond(coreEcdsaKeygen))
}

//export MpcEcdsaRefresh
func MpcEcdsaRefresh(share1st *C.char, share2nd *C.char) *C.char {
	return C.CString(respond(func() (any, error) {
		return coreEcdsaRefresh(C.GoString(share1st), C.GoString(share2nd))
	}))
}

//export MpcEcdsaDerivedPubKey
func MpcEcdsaDerivedPubKey(share1st *C.char, share2nd *C.char, childIdx C.uint) *C.char {
	return C.CString(respond(func() (any, error) {
		return coreEcdsaDerivedPubKey(C.GoString(share1st), C.GoString(share2nd), uint32(childIdx))
	}))
}

//export MpcEcdsaSign
func MpcEcdsaSign(share1st *C.char, share2nd *C.char, childIdx C.uint, hashHex *C.char) *C.char {
	return C.CString(respond(func() (any, error) {
		return coreEcdsaSign(C.GoString(share1st), C.GoString(share2nd), uint32(childIdx), C.GoString(hashHex))
	}))
}

//export MpcEd25519DkgNew
func MpcEd25519DkgNew(deviceNumber C.int, total C.int) *C.char {
	return C.CString(respond(func() (any, error) {
		return coreEd25519DkgNew(int(deviceNumber), int(total))
	}))
}

//export MpcEd25519DkgStep1
func MpcEd25519DkgStep1(h C.longlong) *C.char {
	return C.CString(respond(func() (any, error) { return coreEd25519DkgStep1(int64(h)) }))
}

//export MpcEd25519DkgStep2
func MpcEd25519DkgStep2(h C.longlong, msgs *C.char) *C.char {
	return C.CString(respond(func() (any, error) {
		return coreEd25519DkgStep2(int64(h), C.GoString(msgs))
	}))
}

//export MpcEd25519DkgStep3
func MpcEd25519DkgStep3(h C.longlong, msgs *C.char) *C.char {
	return C.CString(respond(func() (any, error) {
		return coreEd25519DkgStep3(int64(h), C.GoString(msgs))
	}))
}

//export MpcEd25519DkgFree
func MpcEd25519DkgFree(h C.longlong) *C.char {
	return C.CString(respond(func() (any, error) { return coreEd25519DkgFree(int64(h)) }))
}

//export MpcEd25519SignNew
func MpcEd25519SignNew(deviceNumber C.int, threshold C.int, partListJson *C.char, shareI *C.char, pubKeyJson *C.char, msgHex *C.char) *C.char {
	return C.CString(respond(func() (any, error) {
		return coreEd25519SignNew(int(deviceNumber), int(threshold),
			C.GoString(partListJson), C.GoString(shareI), C.GoString(pubKeyJson), C.GoString(msgHex))
	}))
}

//export MpcEd25519SignStep1
func MpcEd25519SignStep1(h C.longlong) *C.char {
	return C.CString(respond(func() (any, error) { return coreEd25519SignStep1(int64(h)) }))
}

//export MpcEd25519SignStep2
func MpcEd25519SignStep2(h C.longlong, msgs *C.char) *C.char {
	return C.CString(respond(func() (any, error) {
		return coreEd25519SignStep2(int64(h), C.GoString(msgs))
	}))
}

//export MpcEd25519SignStep3
func MpcEd25519SignStep3(h C.longlong, msgs *C.char) *C.char {
	return C.CString(respond(func() (any, error) {
		return coreEd25519SignStep3(int64(h), C.GoString(msgs))
	}))
}

//export MpcEd25519SignFree
func MpcEd25519SignFree(h C.longlong) *C.char {
	return C.CString(respond(func() (any, error) { return coreEd25519SignFree(int64(h)) }))
}

//export MpcEd25519Verify
func MpcEd25519Verify(si1 *C.char, si2 *C.char, r *C.char, msgHex *C.char, pubKeyJson *C.char) *C.char {
	return C.CString(respond(func() (any, error) {
		return coreEd25519Verify(C.GoString(si1), C.GoString(si2), C.GoString(r),
			C.GoString(msgHex), C.GoString(pubKeyJson))
	}))
}

//export MpcSha256Hex
func MpcSha256Hex(dataHex *C.char) *C.char {
	return C.CString(respond(func() (any, error) { return coreSha256Hex(C.GoString(dataHex)) }))
}

func main() {}
