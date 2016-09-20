package client

import "fmt"

var (
	ErrResolvedIPInvalid       = newError(1001)
	ErrDigestInvalid           = newError(1002)
	ErrTimeOutOfSync           = newError(1003)
	ErrMaxLicensedUsersReached = newError(1004)
	ErrPasswordExpired         = newError(1005)
)

func newError(number int) Error {
	return Error{
		Number: number,
	}
}

// Error contains the Keytalk client error
type Error struct {
	Number int
}

func (e Error) Error() string {
	switch e.Number {
	case 1001:
		return "Sent by the server when none of IPs  resolved by the client and by the server match."
	case 1002:
		return "Sent by server when the client’s calculated executable digest does not match the digest stored on the server."
	case 1003:
		return "Sent by the server when the client time is out of sync with the server’s time."
	case 1004:
		return "Sent by the server when no certificate can be supplied because the max number of licensed users has been reached"
	case 1005:
		return "Sent by the server when the password of the user trying to authenticate is expired but the client is not supposed to start password change procedure."
	}

	return fmt.Sprintf("Unknown error: %d", e.Number)
}
