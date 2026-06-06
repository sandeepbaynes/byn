// Package ipc defines the wire protocol between the byn CLI and
// the daemon.
//
// Wire format: length-prefixed JSON. Each frame is a 4-byte
// big-endian uint32 length followed by that many bytes of JSON.
// Maximum frame size is MaxFrameSize (1 MiB) — secrets larger than
// that fail at the vault layer too, so the IPC limit is not the
// tighter constraint.
//
// Every message carries a "v" field (currently always 1). Future
// breaking changes bump the version; the daemon refuses unknown
// versions with a clear "upgrade required" error envelope.
//
// Three top-level message shapes share the wire:
//
//	Request:  {"v": 1, "id": "...", "op": "...", "req": {...}}
//	Response: {"v": 1, "id": "...", "resp": {...}}
//	Error:    {"v": 1, "id": "...", "err": {"code": "...", "message": "...", "recover": "..."}}
//
// The "id" field is a client-chosen correlation token (UUID or random
// string). The server echoes it back so multiplexing futures can match
// responses to in-flight requests.
//
// Op-specific request/response bodies live in this package as plain
// structs (no `interface{}`); the daemon dispatcher selects the right
// type via the Op constant.
package ipc
