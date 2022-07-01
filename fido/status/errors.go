package status

import (
	"errors"
)

var (
	ErrUserNotFound           = errors.New("user not found")
	ErrAuthenticatorNotFound  = errors.New("no registered authenticators")
	ErrDuplicateAuthenticator = errors.New("duplicate authenticator")

	ErrTokenFailed                = errors.New("failed to generate token")
	ErrDb                         = errors.New("failed to communicate with database")
	ErrTokenExpired               = errors.New("token is expired")
	ErrInvalidToken               = errors.New("invalid token")
	ErrInvalidIdentity            = errors.New("invalid Identity")
	ErrUpdateAccountID            = errors.New("Update Account Id to QRCode Failed")
	ErrUnsupportedAssertionScheme = errors.New("unsupported validator scheme")
	ErrInvalidAssertion           = errors.New("unsupported validator scheme")
	ErrInvalidQrCode              = errors.New("invalid qr code")
	ErrQrCodeExpired              = errors.New("qr code expired")
	ErrQrTokenUsed                = errors.New("qr code token used")
	ErrInvalidOperation           = errors.New("unknown op code")
	ErrUnknownAuthenticator       = errors.New("unknown authenticator")
)

type Status int

const (
	Ok                             = Status(1200)
	Accept                         = Status(1202)
	BadRequest                     = Status(1400)
	Unauthorized                   = Status(1401)
	Forbidden                      = Status(1403)
	NotFound                       = Status(1404)
	Timeout                        = Status(1408)
	UnknownAAID                    = Status(1480)
	UnknownKeyID                   = Status(1481)
	ChannelBindingRefused          = Status(1490)
	RequestInvalid                 = Status(1491)
	UnacceptableAuthenticator      = Status(1492)
	RevokedAuthenticator           = Status(1493)
	UnacceptableKey                = Status(1494)
	UnacceptableAlgorithm          = Status(1495)
	UnacceptableAttestation        = Status(1496)
	UnacceptableClientCapabilities = Status(1497)
	UnacceptableContent            = Status(1498)
	InternalServerError            = Status(1500)
)
