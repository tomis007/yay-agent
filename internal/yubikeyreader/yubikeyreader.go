package yubikeyreader

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/rs/zerolog/log"
)

// A type to wrap piv.Yubikey to manage the yubikey handle
type YubikeyReader struct {
	key *piv.YubiKey
}

func (y *YubikeyReader) GetKeyInfo(timeout time.Duration) (piv.KeyInfo, error) {
	if err := y.connectToYubikey(timeout); err != nil {
		return piv.KeyInfo{}, err
	}
	return y.key.KeyInfo(piv.SlotAuthentication)
}

// Returns
// firmware version
// pin tries remaining
// serial number
func (y *YubikeyReader) PIVInfo(timeout time.Duration) (string, int, uint32, error) {
	if err := y.connectToYubikey(timeout); err != nil {
		return "", 0, 0, err
	}
	firmware := y.key.Version()
	pintries, err := y.key.Retries()
	if err != nil {
		return "", 0, 0, err
	}
	serial, err := y.key.Serial()
	if err != nil {
		return "", 0, 0, err
	}
	return fmt.Sprintf("%d.%d.%d", firmware.Major, firmware.Minor, firmware.Patch), pintries, serial, nil
}

func (y *YubikeyReader) SetManagementKey(timeout time.Duration, oldKey []byte, newKey []byte) error {
	if err := y.connectToYubikey(timeout); err != nil {
		return err
	}
	return y.key.SetManagementKey(oldKey, newKey)
}

func (y *YubikeyReader) SetPIN(timeout time.Duration, currentPin string, newPin string) error {
	if err := y.connectToYubikey(timeout); err != nil {
		return err
	}
	return y.key.SetPIN(currentPin, newPin)
}

func (y *YubikeyReader) SetPUK(timeout time.Duration, currentPUK string, newPUK string) error {
	if err := y.connectToYubikey(timeout); err != nil {
		return err
	}
	return y.key.SetPUK(currentPUK, newPUK)
}

func (y *YubikeyReader) SetMetadata(timeout time.Duration, key []byte, data *piv.Metadata) error {
	if err := y.connectToYubikey(timeout); err != nil {
		return err
	}
	return y.key.SetMetadata(key, data)
}

func (y *YubikeyReader) VerifyPIN(timeout time.Duration, pin string) error {
	if err := y.connectToYubikey(timeout); err != nil {
		return err
	}
	return y.key.VerifyPIN(pin)
}

func (y *YubikeyReader) Metadata(timeout time.Duration, pin string) (*piv.Metadata, error) {
	if err := y.connectToYubikey(timeout); err != nil {
		return nil, err
	}
	return y.key.Metadata(pin)
}

func (y *YubikeyReader) GetSerial(timeout time.Duration) (uint32, error) {
	if err := y.connectToYubikey(timeout); err != nil {
		return 0, err
	}
	return y.key.Serial()
}

func (y *YubikeyReader) GetPIVKeyCert(timeout time.Duration) (*x509.Certificate, error) {
	if err := y.connectToYubikey(timeout); err != nil {
		return nil, err
	}
	return y.key.Attest(piv.SlotSignature)
}

func (y *YubikeyReader) GenerateKey(timeout time.Duration, key []byte, slot piv.Slot, opts piv.Key) (crypto.PublicKey, error) {
	if err := y.connectToYubikey(timeout); err != nil {
		return nil, err
	}
	return y.key.GenerateKey(key, slot, opts)
}

func (y *YubikeyReader) PrivateKey(timeout time.Duration, slot piv.Slot, public crypto.PublicKey, auth piv.KeyAuth) (crypto.PrivateKey, error) {
	if err := y.connectToYubikey(timeout); err != nil {
		return nil, err
	}
	return y.key.PrivateKey(slot, public, auth)
}

func yubikeyWithTimeout(waitTime time.Duration) (string, error) {
	c := make(chan []string, 1)
	timeout := time.After(waitTime)
	if newCards, err := piv.Cards(); err == nil && len(newCards) > 0 {
		c <- newCards
		goto end
	}

	if int(waitTime.Seconds()) > 1 {
		log.Info().Msg(fmt.Sprintf("Waiting %d seconds for yubikey connection", int(waitTime.Seconds())))
	}

	for {
		select {
		case <-time.After(500 * time.Millisecond):
			if newCards, err := piv.Cards(); err == nil && len(newCards) > 0 {
				c <- newCards
				goto end
			}
		case <-timeout:
			// time out
			goto end
		}
	}

end:
	select {
	case cards := <-c:
		if len(cards) != 1 {
			return "", fmt.Errorf("error %d yubikeys connected", len(cards))
		}
		if !strings.Contains(strings.ToLower(cards[0]), "yubikey") {
			return "", fmt.Errorf("invalid piv key connected: %s", cards[0])
		}
		return cards[0], nil
	default:
		return "", fmt.Errorf("timeout waiting for yubikey")
	}
}

func (y *YubikeyReader) connectToYubikey(timeout time.Duration) error {
	if y.key != nil {
		return nil
	}
	card, err := yubikeyWithTimeout(timeout)
	if err != nil {
		return err
	}

	if yk, err := piv.Open(card); err != nil || yk == nil {
		return fmt.Errorf("error opening yubikey: %v", err)
	} else {
		y.key = yk
		return nil
	}
}

func (y *YubikeyReader) Close() error {
	if y.key != nil {
		return y.key.Close()
	}
	return nil
}
