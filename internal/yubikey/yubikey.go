package yubikey

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/tomis007/yay-agent/internal/yubikeyreader"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func Create(overwrite bool, timeout time.Duration) error {
	y := yubikeyreader.YubikeyReader{}
	defer y.Close()

	// check if something is already in the slot
	if keyInfo, err := y.GetKeyInfo(timeout); err == nil {
		sshKey, err := ssh.NewPublicKey(keyInfo.PublicKey)
		if err != nil {
			return err
		}
		log.Info().Msg("Key already exists in Authentication Slot!")
		log.Info().Msg(fmt.Sprintf("Public Key: %s", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshKey)))))
		if overwrite {
			log.Warn().Msg("Overwriting key!")
			if confirmed, err := confirm("Continue ? (y/n): "); err != nil {
				return err
			} else if confirmed {
				log.Warn().Msg("Replacing existing key")
			} else {
				log.Info().Msg("Not creating key...")
				return nil
			}
		}
	} else if !errors.Is(err, piv.ErrNotFound) {
		return err
	}

	key := piv.Key{
		Algorithm:   piv.AlgorithmEd25519,
		PINPolicy:   piv.PINPolicyAlways,
		TouchPolicy: piv.TouchPolicyAlways,
	}
	pin, err := readPassword("Enter Yubikey PIN: ", false)
	if err != nil {
		return err
	}

	metaData, err := y.Metadata(0, string(pin))
	if err != nil {
		return err
	} else if metaData.ManagementKey == nil {
		log.Warn().Msg("No Management key stored in Metadata!")
		log.Warn().Msg("You probably want to run 'yay-util setup'! ")
		if confirm, err := confirm("Proceed with default Management Key? (y/n):"); err != nil {
			return err
		} else if !confirm {
			return nil
		}
		metaData.ManagementKey = &piv.DefaultManagementKey
	}

	var sshKey ssh.PublicKey
	if pubKey, err := y.GenerateKey(timeout, *metaData.ManagementKey, piv.SlotAuthentication, key); err != nil {
		return err
	} else if sshKey, err = ssh.NewPublicKey(pubKey); err != nil {
		return err
	}

	log.Info().Msg("created ssh public key:")
	log.Info().Msg(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshKey))))
	return nil
}

func Remove(name string) error {
	log.Error().Msg("Not Implemented")
	return nil
}

func GetPublicKey(timeout time.Duration) (ssh.PublicKey, error) {
	y := yubikeyreader.YubikeyReader{}
	defer y.Close()
	if keyInfo, err := getKeyInfo(&y, timeout); err != nil {
		return nil, err
	} else {
		return ssh.NewPublicKey(keyInfo.PublicKey)
	}
}

func Show(timeout time.Duration) error {
	return Write(os.Stdout, timeout)
}

func Save(outputFile string, timeout time.Duration) error {
	log.Info().Msg(fmt.Sprintf("saving public key to: %s", outputFile))
	outF, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if err := Write(outF, timeout); err != nil {
		return err
	}
	return outF.Close()
}

func Write(outFile *os.File, timeout time.Duration) error {
	y := yubikeyreader.YubikeyReader{}
	defer y.Close()
	keyInfo, err := getKeyInfo(&y, timeout)
	if err != nil {
		return err
	}

	serial, err := y.GetSerial(0)
	if err != nil {
		return err
	}

	sshKey, err := ssh.NewPublicKey(keyInfo.PublicKey)
	if err != nil {
		return err
	}

	pubKey := ssh.MarshalAuthorizedKey(sshKey)
	if _, err = outFile.Write(pubKey[:len(pubKey)-1]); err != nil {
		return err
	}
	_, err = fmt.Fprintf(outFile, " yayagent@%d\n", serial)
	return err
}

func confirm(message string) (bool, error) {
	fmt.Printf("%s", message)
	var confirmation string
	if _, err := fmt.Scanln(&confirmation); err != nil {
		return false, err
	}
	fmt.Printf("\n")
	return confirmation == "y", nil
}

func Status(timeout time.Duration) error {
	y := yubikeyreader.YubikeyReader{}
	if err := checkPinStatus(&y, timeout); err != nil {
		return err
	}
	if err := checkPUKStatus(&y); err != nil {
		return err
	}
	if err := checkManagementKeyStatus(&y, 0); err != nil {
		return err
	}

	return y.Close()
}

func checkPUKStatus(y *yubikeyreader.YubikeyReader) error {
	if err := y.SetPUK(0, piv.DefaultPUK, piv.DefaultPUK); err == nil {
		log.Warn().Msg("Using default PUK!")
		fmt.Print("Update PUK? (y/n): ")
		if confirmed, err := confirm("Update PUK? (y/n): "); err != nil {
			return err
		} else if !confirmed {
			log.Info().Msg("Not updating PUK!")
			return nil
		}
		if newPuk, err := readPassword("Enter new Yubikey PUK (8 digits): ", true); err != nil {
			return err
		} else if newPuk == piv.DefaultPUK {
			log.Error().Msg("That's the default PUK... Try Again!")
			return nil
		} else {
			log.Info().Msg("Updating PUK!")
			return y.SetPUK(0, piv.DefaultPUK, newPuk)
		}
	} else {
		log.Info().Msg("PUK is non default!")
	}
	return nil
}

func checkManagementKeyStatus(y *yubikeyreader.YubikeyReader, timeout time.Duration) error {
	if err := y.SetManagementKey(timeout, piv.DefaultManagementKey, piv.DefaultManagementKey); err != nil {
		log.Info().Msg("Managment key is non default!")
		return nil
	}

	log.Warn().Msg("Using default Management Key!")
	if confirmed, err := confirm("Update Management Key? (y/n): "); err != nil {
		return err
	} else if confirmed {
		var newKey [24]byte
		if _, err := io.ReadFull(rand.Reader, newKey[:]); err != nil {
			log.Error().Err(err).Msg("Unable to generate bytes")
			return err
		}
		if err := y.SetManagementKey(0, piv.DefaultManagementKey, newKey[:]); err != nil {
			log.Error().Err(err).Msg("Unable to set management key")
			return err
		}
		newK := newKey[:]
		if err := y.SetMetadata(0, newKey[:], &piv.Metadata{ManagementKey: &newK}); err != nil {
			log.Error().Err(err).Msg("Unable to save management key in metadata on key")
		}
		log.Info().Msg("Updated management key! Saved on Yubikey as Metadata")
	}
	return nil
}

func checkPinStatus(y *yubikeyreader.YubikeyReader, timeout time.Duration) error {
	log.Info().Msg("Verifying Yubikey PIN. Not sure? Try default '123456'")
	pin, err := readPassword("Enter Yubikey PIN: ", false)
	if err != nil {
		return err
	}
	err = y.VerifyPIN(timeout, string(pin))
	if err != nil {
		log.Error().Err(err).Msg("invalid pin!")
		return err
	}
	log.Info().Msg("Yubikey PIN verified!")
	if string(pin) != piv.DefaultPIN {
		return nil
	}
	log.Warn().Msg("Using default PIN!")
	if confirmed, err := confirm("Update PIN? (y/n): "); err != nil {
		return err
	} else if confirmed {
		if newPin, err := readPassword("Enter New Yubikey PIN (6 - 8 digits): ", true); err != nil {
			return err
		} else if newPin == piv.DefaultPIN {
			log.Error().Msg("That's the default pin... Try Again!")
			return nil
		} else {
			log.Info().Msg("Updating PIN!")
			return y.SetPIN(0, piv.DefaultPIN, string(newPin))
		}
	} else {
		log.Info().Msg("Not updating PIN!")
	}
	return nil
}

func readPassword(message string, confirm bool) (string, error) {
	fmt.Print(message)
	pass, err := getPassword()
	fmt.Printf("\n")
	if err != nil {
		return "", err
	}
	if !confirm {
		return pass, nil
	}
	fmt.Printf("Reenter: ")
	passCheck, err := getPassword()
	fmt.Printf("\n")
	if err != nil {
		return "", err
	}
	if passCheck != pass {
		return "", fmt.Errorf("passwords do not match")
	} else {
		return pass, nil
	}
}

func getPassword() (string, error) {
	if pass, err := term.ReadPassword(int(syscall.Stdin)); err != nil {
		return "", err
	} else {
		return string(pass), nil
	}
}

func PIVInfo(timeout time.Duration) error {
	y := yubikeyreader.YubikeyReader{}
	defer y.Close()

	vers, pintries, serial, err := y.PIVInfo(timeout)
	if err != nil {
		return err
	}

	log.Info().Msg("Yubikey PIV Info")
	log.Info().Msg(fmt.Sprintf("Serial number:\t\t%d", serial))
	log.Info().Msg(fmt.Sprintf("Firmware version:\t\t%s", vers))
	log.Info().Msg(fmt.Sprintf("PIN tries remaining:\t%d", pintries))

	return nil
}

func getKeyInfo(y *yubikeyreader.YubikeyReader, timeout time.Duration) (piv.KeyInfo, error) {
	keyInfo, err := y.GetKeyInfo(timeout)
	if errors.Is(err, piv.ErrNotFound) {
		log.Info().Msg("No Data in Yubikey PIV Authentication Slot (9C)")
		log.Info().Msg("Run: 'yay-agent keys create'")
		return piv.KeyInfo{}, piv.ErrNotFound
	} else if err != nil {
		return piv.KeyInfo{}, err
	}
	return keyInfo, nil
}

func Info(name string, timeout time.Duration) error {
	y := yubikeyreader.YubikeyReader{}
	defer y.Close()
	keyInfo, err := getKeyInfo(&y, timeout)
	if err != nil {
		return err
	}

	sshKey, err := ssh.NewPublicKey(keyInfo.PublicKey)
	if err != nil {
		return err
	}

	log.Info().Msg(fmt.Sprintf("PublicKey: %s", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshKey)))))
	log.Info().Msg(fmt.Sprintf("Algorithm: %s", PivAlgorithmString(keyInfo.Algorithm)))
	log.Info().Msg(fmt.Sprintf("TouchPolicy: %s", PivTouchPolicyString(keyInfo.TouchPolicy)))
	log.Info().Msg(fmt.Sprintf("PinPolicy: %s", PivPINPolicyString(keyInfo.PINPolicy)))
	return nil
}

func PivPINPolicyString(p piv.PINPolicy) string {
	switch p {
	case piv.PINPolicyAlways:
		return "Always"
	case piv.PINPolicyNever:
		return "Never"
	case piv.PINPolicyOnce:
		return "Once"
	default:
		return "invalid"
	}
}

func PivTouchPolicyString(p piv.TouchPolicy) string {
	switch p {
	case piv.TouchPolicyAlways:
		return "Always"
	case piv.TouchPolicyCached:
		return "Cached"
	case piv.TouchPolicyNever:
		return "Never"
	default:
		return "invalid"
	}
}

func PivAlgorithmString(a piv.Algorithm) string {
	switch a {
	case piv.AlgorithmEC256:
		return "EC256"
	case piv.AlgorithmEC384:
		return "EC384"
	case piv.AlgorithmEd25519:
		return "Ed25519"
	case piv.AlgorithmRSA1024:
		return "RSA1048"
	case piv.AlgorithmRSA2048:
		return "RSA2048"
	case piv.AlgorithmRSA3072:
		return "RSA3072"
	case piv.AlgorithmRSA4096:
		return "RSA4096"
	case piv.AlgorithmX25519:
		return "X25519"
	default:
		return "invalid"
	}
}
