module golang.zx2c4.com/wireguard/android

go 1.17

require (
	golang.org/x/sys v0.0.0-20211110154304-99a53858aa08
	golang.zx2c4.com/wireguard v0.0.0-20211028114750-eb6302c7eb71
)

require (
	golang.org/x/crypto v0.0.0-20211108221036-ceb1ce70b4fa // indirect
	golang.org/x/net v0.0.0-20211111083644-e5c967477495 // indirect
	golang.zx2c4.com/go118/netip v0.0.0-20211111135330-a4a02eeacf9d // indirect
	golang.zx2c4.com/wintun v0.0.0-20211104114900-415007cec224 // indirect
)

replace golang.zx2c4.com/wireguard v0.0.0-20211028114750-eb6302c7eb71 => ../../../../HWWireGuard-androidGoBackend
