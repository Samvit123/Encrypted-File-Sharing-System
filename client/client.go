package client

import (
	// "encoding/hex"
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

type User struct {
	username string
	rootKey  []byte
	DKey     userlib.PKEDecKey
	SKey     userlib.DSSignKey
}

type FileBridge struct {
	SymKeyEnc  []byte
	SymKeyMac  []byte
	FileId     uuid.UUID
	SharedWith map[string]uuid.UUID
	IsPointer  bool
}

type File struct {
	Length int
}

type ByteChunk struct {
	Content []byte
}

type Invitation struct {
	Id uuid.UUID
	EK []byte
	MK []byte
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	if username == "" {
		return nil, errors.New("Username cannot be empty")
	}

	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}

	_, ok := userlib.DatastoreGet(userUUID)
	if ok {
		return nil, errors.New("User already exists")
	}

	userdata.username = username

	userPKEEncKey, userPKEDecKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	userDSSignKey, userDSVerifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	userdata.DKey = userPKEDecKey
	userdata.SKey = userDSSignKey

	userPKEEncKeyStorage, err := uuid.FromBytes(userlib.Hash([]byte(username))[32:48])
	if err != nil {
		return nil, err
	}
	userDSVerifyKeyStorage, err := uuid.FromBytes(userlib.Hash([]byte(username))[48:])
	if err != nil {
		return nil, err
	}

	userlib.KeystoreSet(userPKEEncKeyStorage.String(), userPKEEncKey)
	userlib.KeystoreSet(userDSVerifyKeyStorage.String(), userDSVerifyKey)

	userSalt := userlib.RandomBytes(5)
	userSaltStorage, err := uuid.FromBytes(userlib.Hash([]byte(username + password))[16:32])
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(userSaltStorage, userSalt)

	userRootKey := userlib.Argon2Key([]byte(password), userSalt, 16)
	userMacKey, err := userlib.HashKDF(userRootKey, []byte("mac-key"))
	userMacKey = userMacKey[:16]
	if err != nil {
		return nil, err
	}

	userdata.rootKey = userRootKey

	marshalledUser, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}

	encryptedUser := userlib.SymEnc(userRootKey, userlib.RandomBytes(16), marshalledUser)
	userMac, err := userlib.HMACEval(userMacKey, encryptedUser)
	if err != nil {
		return nil, err
	}

	userlib.DatastoreSet(userUUID, append(encryptedUser, userMac...))

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}

	returnVal, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New("Invalid username or password")
	}
	if len(returnVal) < 64 {
		return nil, errors.New(strings.ToTitle("User Error"))
	}

	userMac := returnVal[len(returnVal)-64:]
	encryptedUser := returnVal[:len(returnVal)-64]

	userSaltStorage, err := uuid.FromBytes(userlib.Hash([]byte(username + password))[16:32])
	if err != nil {
		return nil, err
	}
	userSalt, ok := userlib.DatastoreGet(userSaltStorage)
	if !ok {
		return nil, errors.New("Invalid username or password")
	}

	userRootKey := userlib.Argon2Key([]byte(password), userSalt, 16)
	userMacKey, err := userlib.HashKDF(userRootKey, []byte("mac-key"))
	userMacKey = userMacKey[:16]
	if err != nil {
		return nil, err
	}

	userMacCheck, err := userlib.HMACEval(userMacKey, encryptedUser)
	if err != nil {
		return nil, err
	}

	if !userlib.HMACEqual(userMac, userMacCheck) {
		return nil, errors.New("User Error")
	}

	decryptedUser := userlib.SymDec(userRootKey, encryptedUser)
	json.Unmarshal(decryptedUser, &userdata)

	userdata.username = username
	userdata.rootKey = userRootKey

	userdataptr = &userdata
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.username))[:16])
	if err != nil {
		return err
	}
	FileStorage := uuid.New()
	userRootKey := userdata.rootKey
	userMacKey, err := userlib.HashKDF(userRootKey, []byte("mac-key"))
	userMacKey = userMacKey[:16]
	if err != nil {
		return err
	}

	fileEncKey := userlib.RandomBytes(16)
	fileMacKey := userlib.RandomBytes(16)

	FileBridgeStorage, err := uuid.FromBytes(userlib.Hash([]byte(userUUID.String() + filename))[:16])
	if err != nil {
		return err
	}
	returnVal, ok := userlib.DatastoreGet(FileBridgeStorage)
	if ok {
		if len(returnVal) < 64 {
			return errors.New(strings.ToTitle("File Error"))
		}
		fileBridgeMac := returnVal[len(returnVal)-64:]
		encryptedFileBridge := returnVal[:len(returnVal)-64]

		fileBridgeMacCheck, err := userlib.HMACEval(userMacKey, encryptedFileBridge)
		if err != nil {
			return err
		}

		if !userlib.HMACEqual(fileBridgeMac, fileBridgeMacCheck) {
			return errors.New("File Error")
		}

		decryptedFileBridge := userlib.SymDec(userRootKey, encryptedFileBridge)
		var fileBridge FileBridge
		json.Unmarshal(decryptedFileBridge, &fileBridge)

		FileStorage = fileBridge.FileId

		if fileBridge.IsPointer {
			returnVal, ok := userlib.DatastoreGet(FileStorage)
			if !ok {
				return errors.New(strings.ToTitle("File error #2"))
			}
			if len(returnVal) < 64 {
				return errors.New(strings.ToTitle("File Error"))
			}

			fileBridgeMac = returnVal[len(returnVal)-64:]
			encryptedFileBridge = returnVal[:len(returnVal)-64]

			fileBridgeMacCheck, err = userlib.HMACEval(fileBridge.SymKeyMac, encryptedFileBridge)
			if err != nil {
				return err
			}

			if !userlib.HMACEqual(fileBridgeMac, fileBridgeMacCheck) {
				return errors.New(strings.ToTitle("File error #3"))
			}

			decryptedFileBridge = userlib.SymDec(fileBridge.SymKeyEnc, encryptedFileBridge)
			json.Unmarshal(decryptedFileBridge, &fileBridge)
		}

		FileStorage = fileBridge.FileId
		fileEncKey := fileBridge.SymKeyEnc
		fileMacKey := fileBridge.SymKeyMac

		returnVal, ok = userlib.DatastoreGet(FileStorage)
		if !ok {
			return errors.New(strings.ToTitle("File error"))
		}
		if len(returnVal) < 64 {
			return errors.New(strings.ToTitle("File Error"))
		}

		fileMac := returnVal[len(returnVal)-64:]
		encryptedFile := returnVal[:len(returnVal)-64]

		fileMacCheck, err := userlib.HMACEval(fileMacKey, encryptedFile)
		if err != nil {
			return err
		}

		if !userlib.HMACEqual(fileMac, fileMacCheck) {
			return errors.New("File Error")
		}

		decryptedFile := userlib.SymDec(fileEncKey, encryptedFile)
		var file File
		json.Unmarshal(decryptedFile, &file)

		fileEncKey = fileBridge.SymKeyEnc
		fileMacKey = fileBridge.SymKeyMac

		for i := 0; i < file.Length+1; i++ {
			ByteChunkStorage, err := uuid.FromBytes(userlib.Hash([]byte(FileStorage.String() + fmt.Sprintf("%d", i)))[:16])
			if err != nil {
				return err
			}
			userlib.DatastoreDelete(ByteChunkStorage)
		}

		file.Length = 0
		ByteChunkStorage, err := uuid.FromBytes(userlib.Hash([]byte(FileStorage.String() + "0"))[:16])
		if err != nil {
			return err
		}
		ByteChunkStruct := ByteChunk{content}

		marshalledByteChunk, err := json.Marshal(ByteChunkStruct)
		if err != nil {
			return err
		}
		encryptedByteChunk := userlib.SymEnc(fileEncKey, userlib.RandomBytes(16), marshalledByteChunk)
		byteChunkMac, err := userlib.HMACEval(fileMacKey, encryptedByteChunk)
		if err != nil {
			return err
		}

		userlib.DatastoreSet(ByteChunkStorage, append(encryptedByteChunk, byteChunkMac...))

		marshalledFile, err := json.Marshal(file)
		if err != nil {
			return err
		}
		encryptedFile = userlib.SymEnc(fileEncKey, userlib.RandomBytes(16), marshalledFile)
		fileMac, err = userlib.HMACEval(fileMacKey, encryptedFile)
		if err != nil {
			return err
		}

		userlib.DatastoreSet(FileStorage, append(encryptedFile, fileMac...))

		return nil

	} else {
		ByteChunkStorage, err := uuid.FromBytes(userlib.Hash([]byte(FileStorage.String() + "0"))[:16])
		if err != nil {
			return err
		}

		FileBridgeStruct := FileBridge{fileEncKey, fileMacKey, FileStorage, make(map[string]uuid.UUID), false}
		FileStruct := File{0}
		ByteChunkStruct := ByteChunk{content}

		marshalledByteChunk, err := json.Marshal(ByteChunkStruct)
		if err != nil {
			return err
		}
		encryptedByteChunk := userlib.SymEnc(fileEncKey, userlib.RandomBytes(16), marshalledByteChunk)
		byteChunkMac, err := userlib.HMACEval(fileMacKey, encryptedByteChunk)
		if err != nil {
			return err
		}

		userlib.DatastoreSet(ByteChunkStorage, append(encryptedByteChunk, byteChunkMac...))

		marshalledFile, err := json.Marshal(FileStruct)
		if err != nil {
			return err
		}
		encryptedFile := userlib.SymEnc(fileEncKey, userlib.RandomBytes(16), marshalledFile)
		fileMac, err := userlib.HMACEval(fileMacKey, encryptedFile)
		if err != nil {
			return err
		}

		userlib.DatastoreSet(FileStorage, append(encryptedFile, fileMac...))

		marshalledFileBridge, err := json.Marshal(FileBridgeStruct)
		if err != nil {
			return err
		}
		encryptedFileBridge := userlib.SymEnc(userRootKey, userlib.RandomBytes(16), marshalledFileBridge)
		fileBridgeMac, err := userlib.HMACEval(userMacKey, encryptedFileBridge)
		if err != nil {
			return err
		}

		userlib.DatastoreSet(FileBridgeStorage, append(encryptedFileBridge, fileBridgeMac...))

		return nil

	}
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.username))[:16])
	if err != nil {
		return err
	}
	var fileBridge FileBridge
	var file File
	var byteChunk ByteChunk
	userRootKey := userdata.rootKey
	userMacKey, err := userlib.HashKDF(userRootKey, []byte("mac-key"))
	userMacKey = userMacKey[:16]
	if err != nil {
		return err
	}

	FileBridgeStorage, err := uuid.FromBytes(userlib.Hash([]byte(userUUID.String() + filename))[:16])
	if err != nil {
		return err
	}

	returnVal, ok := userlib.DatastoreGet(FileBridgeStorage)
	if !ok {
		return errors.New(strings.ToTitle("File not found"))
	}
	if len(returnVal) < 64 {
		return errors.New(strings.ToTitle("File Error"))
	}

	fileBridgeMac := returnVal[len(returnVal)-64:]
	encryptedFileBridge := returnVal[:len(returnVal)-64]

	fileBridgeMacCheck, err := userlib.HMACEval(userMacKey, encryptedFileBridge)
	if err != nil {
		return err
	}

	if !userlib.HMACEqual(fileBridgeMac, fileBridgeMacCheck) {
		return errors.New(strings.ToTitle("File error #1"))
	}

	decryptedFileBridge := userlib.SymDec(userRootKey, encryptedFileBridge)
	json.Unmarshal(decryptedFileBridge, &fileBridge)

	FileStorage := fileBridge.FileId
	fileEncKey := fileBridge.SymKeyEnc
	fileMacKey := fileBridge.SymKeyMac
	pointer := fileBridge.IsPointer

	if pointer {
		returnVal, ok := userlib.DatastoreGet(FileStorage)
		if !ok {
			return errors.New(strings.ToTitle("File error #2"))
		}
		if len(returnVal) < 64 {
			return errors.New(strings.ToTitle("File Error"))
		}

		fileBridgeMac = returnVal[len(returnVal)-64:]
		encryptedFileBridge = returnVal[:len(returnVal)-64]

		fileBridgeMacCheck, err = userlib.HMACEval(fileMacKey, encryptedFileBridge)
		if err != nil {
			return err
		}

		if !userlib.HMACEqual(fileBridgeMac, fileBridgeMacCheck) {
			return errors.New(strings.ToTitle("File error #3"))
		}

		decryptedFileBridge = userlib.SymDec(fileEncKey, encryptedFileBridge)
		json.Unmarshal(decryptedFileBridge, &fileBridge)

		FileStorage = fileBridge.FileId
		fileEncKey = fileBridge.SymKeyEnc
		fileMacKey = fileBridge.SymKeyMac
	}

	returnVal, ok = userlib.DatastoreGet(FileStorage)
	if !ok {
		return errors.New(strings.ToTitle("File not found"))
	}
	if len(returnVal) < 64 {
		return errors.New(strings.ToTitle("File Error"))
	}

	fileMac := returnVal[len(returnVal)-64:]
	encryptedFile := returnVal[:len(returnVal)-64]

	fileMacCheck, err := userlib.HMACEval(fileMacKey, encryptedFile)
	if err != nil {
		return err
	}

	if !userlib.HMACEqual(fileMac, fileMacCheck) {
		return errors.New(strings.ToTitle("File error #4"))
	}

	decryptedFile := userlib.SymDec(fileEncKey, encryptedFile)
	json.Unmarshal(decryptedFile, &file)

	file.Length += 1

	ByteChunkStorage, err := uuid.FromBytes(userlib.Hash([]byte(FileStorage.String() + fmt.Sprintf("%d", file.Length)))[:16])
	if err != nil {
		return err
	}

	byteChunk = ByteChunk{content}
	marshalledByteChunk, err := json.Marshal(byteChunk)
	if err != nil {
		return err
	}
	encryptedByteChunk := userlib.SymEnc(fileEncKey, userlib.RandomBytes(16), marshalledByteChunk)
	byteChunkMac, err := userlib.HMACEval(fileMacKey, encryptedByteChunk)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(ByteChunkStorage, append(encryptedByteChunk, byteChunkMac...))

	marshalledFile, err := json.Marshal(file)
	if err != nil {
		return err
	}
	encryptedFile = userlib.SymEnc(fileEncKey, userlib.RandomBytes(16), marshalledFile)
	fileMac, err = userlib.HMACEval(fileMacKey, encryptedFile)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(FileStorage, append(encryptedFile, fileMac...))

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.username))[:16])
	if err != nil {
		return nil, err
	}
	var fileBridge FileBridge
	var file File
	var byteChunk ByteChunk
	userRootKey := userdata.rootKey
	userMacKey, err := userlib.HashKDF(userRootKey, []byte("mac-key"))
	userMacKey = userMacKey[:16]
	if err != nil {
		return nil, err
	}

	FileBridgeStorage, err := uuid.FromBytes(userlib.Hash([]byte(userUUID.String() + filename))[:16])
	if err != nil {
		return nil, err
	}

	returnVal, ok := userlib.DatastoreGet(FileBridgeStorage)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found"))
	}
	if len(returnVal) < 64 {
		return nil, errors.New(strings.ToTitle("File Error"))
	}

	fileBridgeMac := returnVal[len(returnVal)-64:]
	encryptedFileBridge := returnVal[:len(returnVal)-64]

	fileBridgeMacCheck, err := userlib.HMACEval(userMacKey, encryptedFileBridge)
	if err != nil {
		return nil, err
	}

	if !userlib.HMACEqual(fileBridgeMac, fileBridgeMacCheck) {
		return nil, errors.New(strings.ToTitle("File error #1"))
	}

	decryptedFileBridge := userlib.SymDec(userRootKey, encryptedFileBridge)
	json.Unmarshal(decryptedFileBridge, &fileBridge)

	FileStorage := fileBridge.FileId
	fileEncKey := fileBridge.SymKeyEnc
	fileMacKey := fileBridge.SymKeyMac
	pointer := fileBridge.IsPointer

	if pointer {
		returnVal, ok := userlib.DatastoreGet(FileStorage)
		if !ok {
			return nil, errors.New(strings.ToTitle("File error #2"))
		}
		if len(returnVal) < 64 {
			return nil, errors.New(strings.ToTitle("File Error"))
		}

		fileBridgeMac = returnVal[len(returnVal)-64:]
		encryptedFileBridge = returnVal[:len(returnVal)-64]

		fileBridgeMacCheck, err = userlib.HMACEval(fileMacKey, encryptedFileBridge)
		if err != nil {
			return nil, err
		}

		if !userlib.HMACEqual(fileBridgeMac, fileBridgeMacCheck) {
			return nil, errors.New(strings.ToTitle("File error #3"))
		}

		decryptedFileBridge = userlib.SymDec(fileEncKey, encryptedFileBridge)
		json.Unmarshal(decryptedFileBridge, &fileBridge)

		FileStorage = fileBridge.FileId
		fileEncKey = fileBridge.SymKeyEnc
		fileMacKey = fileBridge.SymKeyMac

	}

	returnVal, ok = userlib.DatastoreGet(FileStorage)
	if !ok {
		return nil, errors.New(strings.ToTitle("File not found"))
	}
	if len(returnVal) < 64 {
		return nil, errors.New(strings.ToTitle("File Error"))
	}

	fileMac := returnVal[len(returnVal)-64:]
	encryptedFile := returnVal[:len(returnVal)-64]

	fileMacCheck, err := userlib.HMACEval(fileMacKey, encryptedFile)
	if err != nil {
		return nil, err
	}

	if !userlib.HMACEqual(fileMac, fileMacCheck) {
		return nil, errors.New(strings.ToTitle("File error #4"))
	}

	decryptedFile := userlib.SymDec(fileEncKey, encryptedFile)
	json.Unmarshal(decryptedFile, &file)

	content = make([]byte, 0)
	for i := 0; i < file.Length+1; i++ {
		ByteChunkStorage, err := uuid.FromBytes(userlib.Hash([]byte(FileStorage.String() + fmt.Sprintf("%d", i)))[:16])
		if err != nil {
			return nil, err
		}

		returnVal, ok = userlib.DatastoreGet(ByteChunkStorage)
		if !ok {
			return nil, errors.New(strings.ToTitle("File error #5"))
		}
		if len(returnVal) < 64 {
			return nil, errors.New(strings.ToTitle("File Error"))
		}

		byteChunkMac := returnVal[len(returnVal)-64:]
		encryptedByteChunk := returnVal[:len(returnVal)-64]

		byteChunkMacCheck, err := userlib.HMACEval(fileMacKey, encryptedByteChunk)
		if err != nil {
			return nil, err
		}

		if !userlib.HMACEqual(byteChunkMac, byteChunkMacCheck) {
			return nil, errors.New(strings.ToTitle("File error #6"))
		}

		decryptedByteChunk := userlib.SymDec(fileEncKey, encryptedByteChunk)
		json.Unmarshal(decryptedByteChunk, &byteChunk)

		content = append(content, byteChunk.Content...)
	}
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	recipientUUID, err := uuid.FromBytes(userlib.Hash([]byte(recipientUsername))[:16])
	if err != nil {
		return uuid.Nil, err
	}
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.username))[:16])
	if err != nil {
		return uuid.Nil, err
	}
	var fileBridge FileBridge
	var invitation Invitation
	invitationUUID, err := uuid.FromBytes(userlib.Hash([]byte(userUUID.String() + recipientUUID.String() + filename + "invitation"))[:16])
	if err != nil {
		return uuid.Nil, err
	}
	userRootKey := userdata.rootKey
	userMacKey, err := userlib.HashKDF(userRootKey, []byte("mac-key"))
	userMacKey = userMacKey[:16]
	if err != nil {
		return uuid.Nil, err
	}

	FileBridgeStorage, err := uuid.FromBytes(userlib.Hash([]byte(userUUID.String() + filename))[:16])
	if err != nil {
		return uuid.Nil, err
	}

	returnVal, ok := userlib.DatastoreGet(FileBridgeStorage)
	if !ok {
		return uuid.Nil, errors.New(strings.ToTitle("File not found"))
	}
	if len(returnVal) < 64 {
		return uuid.Nil, errors.New(strings.ToTitle("File Error"))
	}

	fileBridgeMac := returnVal[len(returnVal)-64:]
	encryptedFileBridge := returnVal[:len(returnVal)-64]

	fileBridgeMacCheck, err := userlib.HMACEval(userMacKey, encryptedFileBridge)
	if err != nil {
		return uuid.Nil, err
	}

	if !userlib.HMACEqual(fileBridgeMac, fileBridgeMacCheck) {
		return uuid.Nil, errors.New(strings.ToTitle("File error"))
	}

	decryptedFileBridge := userlib.SymDec(userRootKey, encryptedFileBridge)
	json.Unmarshal(decryptedFileBridge, &fileBridge)

	if !fileBridge.IsPointer {
		fileBridge.SharedWith[recipientUsername] = recipientUUID
		sharedFileBridge := FileBridge{fileBridge.SymKeyEnc, fileBridge.SymKeyMac, fileBridge.FileId, make(map[string]uuid.UUID), false}
		sharedFileBridgeUUID, err := uuid.FromBytes(userlib.Hash([]byte(userUUID.String() + recipientUUID.String() + filename))[:16])
		if err != nil {
			return uuid.Nil, err
		}
		sharedFileBridgeEnc := userlib.RandomBytes(16)
		sharedFileBridgeMac := userlib.RandomBytes(16)

		EncKeyUUID, err := uuid.FromBytes(userlib.Hash([]byte(userUUID.String() + recipientUUID.String() + filename + "enc-key"))[:16])
		if err != nil {
			return uuid.Nil, err
		}
		MacKeyUUID, err := uuid.FromBytes(userlib.Hash([]byte(userUUID.String() + recipientUUID.String() + filename + "mac-key"))[:16])
		if err != nil {
			return uuid.Nil, err
		}

		marshalledEncKey, err := json.Marshal(sharedFileBridgeEnc)
		if err != nil {
			return uuid.Nil, err
		}
		marshalledMacKey, err := json.Marshal(sharedFileBridgeMac)
		if err != nil {
			return uuid.Nil, err
		}

		encryptedEncKey := userlib.SymEnc(userRootKey, userlib.RandomBytes(16), marshalledEncKey)
		encryptedMacKey := userlib.SymEnc(userRootKey, userlib.RandomBytes(16), marshalledMacKey)

		EncKeyMac, err := userlib.HMACEval(userMacKey, encryptedEncKey)
		if err != nil {
			return uuid.Nil, err
		}
		MacKeyMac, err := userlib.HMACEval(userMacKey, encryptedMacKey)
		if err != nil {
			return uuid.Nil, err
		}

		userlib.DatastoreSet(EncKeyUUID, append(encryptedEncKey, EncKeyMac...))
		userlib.DatastoreSet(MacKeyUUID, append(encryptedMacKey, MacKeyMac...))

		marshalledSharedFileBridge, err := json.Marshal(sharedFileBridge)
		if err != nil {
			return uuid.Nil, err
		}

		encryptedSharedFileBridge := userlib.SymEnc(sharedFileBridgeEnc, userlib.RandomBytes(16), marshalledSharedFileBridge)
		sharedFileBridgeMacVal, err := userlib.HMACEval(sharedFileBridgeMac, encryptedSharedFileBridge)
		if err != nil {
			return uuid.Nil, err
		}

		userlib.DatastoreSet(sharedFileBridgeUUID, append(encryptedSharedFileBridge, sharedFileBridgeMacVal...))
		invitation = Invitation{sharedFileBridgeUUID, sharedFileBridgeEnc, sharedFileBridgeMac}
	} else {
		_, ok := userlib.DatastoreGet(fileBridge.FileId)
		if !ok {
			return uuid.Nil, errors.New(strings.ToTitle("File not found"))
		}
		invitation = Invitation{fileBridge.FileId, fileBridge.SymKeyEnc, fileBridge.SymKeyMac}
	}

	marshalledInvitation, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, err
	}

	recipientPKEStorage, err := uuid.FromBytes(userlib.Hash([]byte(recipientUsername))[32:48])
	if err != nil {
		return uuid.Nil, err
	}

	recipientPKE, ok := userlib.KeystoreGet(recipientPKEStorage.String())
	if !ok {
		return uuid.Nil, errors.New(strings.ToTitle("Recipient not found"))
	}

	encryptedInvitation, err := userlib.PKEEnc(recipientPKE, marshalledInvitation)
	if err != nil {
		return uuid.Nil, err
	}

	signedInvitation, err := userlib.DSSign(userdata.SKey, encryptedInvitation)

	userlib.DatastoreSet(invitationUUID, append(encryptedInvitation, signedInvitation...))

	marshalledFileBridge, err := json.Marshal(fileBridge)
	if err != nil {
		return uuid.Nil, err
	}
	encryptedFileBridge = userlib.SymEnc(userRootKey, userlib.RandomBytes(16), marshalledFileBridge)
	fileBridgeMac, err = userlib.HMACEval(userMacKey, encryptedFileBridge)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(FileBridgeStorage, append(encryptedFileBridge, fileBridgeMac...))

	return invitationUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.username))[:16])
	if err != nil {
		return err
	}
	existingFileUUID, err := uuid.FromBytes(userlib.Hash([]byte(userUUID.String() + filename))[:16])
	if err != nil {
		return err
	}
	_, ok := userlib.DatastoreGet(existingFileUUID)
	if ok {
		return errors.New(strings.ToTitle("Filename already exists"))
	}

	returnval, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New(strings.ToTitle("Invitation not found"))
	}
	if len(returnval) < 256 {
		return errors.New(strings.ToTitle("File Error"))
	}

	var invitation Invitation
	userRootKey := userdata.rootKey
	userMacKey, err := userlib.HashKDF(userRootKey, []byte("mac-key"))
	userMacKey = userMacKey[:16]
	if err != nil {
		return err
	}

	encryptedInvitation := returnval[:len(returnval)-256]
	signedInvitation := returnval[len(returnval)-256:]

	senderDSStorage, err := uuid.FromBytes(userlib.Hash([]byte(senderUsername))[48:])
	if err != nil {
		return err
	}

	senderDS, ok := userlib.KeystoreGet(senderDSStorage.String())
	if !ok {
		return errors.New(strings.ToTitle("Sender not found"))
	}

	err = userlib.DSVerify(senderDS, encryptedInvitation, signedInvitation)
	if err != nil {
		return err
	}

	decryptedInvitation, err := userlib.PKEDec(userdata.DKey, encryptedInvitation)
	if err != nil {
		return err
	}

	json.Unmarshal(decryptedInvitation, &invitation)

	DummyFileBridgeUUID, err := uuid.FromBytes(userlib.Hash([]byte(userUUID.String() + filename))[:16])
	if err != nil {
		return err
	}
	DummyFileBridge := FileBridge{invitation.EK, invitation.MK, invitation.Id, make(map[string]uuid.UUID), true}

	marshalledDummyFileBridge, err := json.Marshal(DummyFileBridge)
	if err != nil {
		return err
	}

	encryptedDummyFileBridge := userlib.SymEnc(userRootKey, userlib.RandomBytes(16), marshalledDummyFileBridge)
	DummyFileBridgeMac, err := userlib.HMACEval(userMacKey, encryptedDummyFileBridge)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(DummyFileBridgeUUID, append(encryptedDummyFileBridge, DummyFileBridgeMac...))
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(userdata.username))[:16])
	if err != nil {
		return err
	}
	var fileBridge FileBridge
	var file File
	var byteChunk ByteChunk
	var sharedFileBridge FileBridge
	var fileBridgeEncKey []byte
	var fileBridgeMacKey []byte
	userRootKey := userdata.rootKey
	userMacKey, err := userlib.HashKDF(userRootKey, []byte("mac-key"))
	userMacKey = userMacKey[:16]
	if err != nil {
		return err
	}
	recipientUUID, err := uuid.FromBytes(userlib.Hash([]byte(recipientUsername))[:16])
	if err != nil {
		return err
	}
	invitationUUID, err := uuid.FromBytes(userlib.Hash([]byte(userUUID.String() + recipientUUID.String() + filename + "invitation"))[:16])
	if err != nil {
		return err
	}
	_, ok := userlib.DatastoreGet(invitationUUID)
	if !ok {
		return errors.New(strings.ToTitle("Revoke Error #1"))
	}
	userlib.DatastoreDelete(invitationUUID)

	sharedFileBridgeUUID, err := uuid.FromBytes(userlib.Hash([]byte(userUUID.String() + recipientUUID.String() + filename))[:16])
	if err != nil {
		return err
	}
	_, ok = userlib.DatastoreGet(sharedFileBridgeUUID)
	if !ok {
		return errors.New(strings.ToTitle("Revoke Error #2"))
	}
	userlib.DatastoreDelete(sharedFileBridgeUUID)

	fileEncKey := userlib.RandomBytes(16)
	fileMacKey := userlib.RandomBytes(16)

	fileBridgeUUID, err := uuid.FromBytes(userlib.Hash([]byte(userUUID.String() + filename))[:16])
	if err != nil {
		return err
	}
	returnval, ok := userlib.DatastoreGet(fileBridgeUUID)
	if !ok {
		return errors.New(strings.ToTitle("File not found #1"))
	}
	if len(returnval) < 64 {
		return errors.New(strings.ToTitle("File Error #1"))
	}

	encryptedFileBridge := returnval[:len(returnval)-64]
	fileBridgeMac := returnval[len(returnval)-64:]

	fileBridgeMacCheck, err := userlib.HMACEval(userMacKey, encryptedFileBridge)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(fileBridgeMac, fileBridgeMacCheck) {
		return errors.New(strings.ToTitle("File Error #2"))
	}

	decryptedFileBridge := userlib.SymDec(userRootKey, encryptedFileBridge)
	json.Unmarshal(decryptedFileBridge, &fileBridge)

	fileUUID := fileBridge.FileId
	returnval, ok = userlib.DatastoreGet(fileUUID)
	if !ok {
		return errors.New(strings.ToTitle("File not found #2"))
	}
	if len(returnval) < 64 {
		return errors.New(strings.ToTitle("File Error #3"))
	}

	encryptedFile := returnval[:len(returnval)-64]
	fileMac := returnval[len(returnval)-64:]

	fileMacCheck, err := userlib.HMACEval(fileBridge.SymKeyMac, encryptedFile)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(fileMac, fileMacCheck) {
		return errors.New(strings.ToTitle("File Error #4"))
	}

	decryptedFile := userlib.SymDec(fileBridge.SymKeyEnc, encryptedFile)
	json.Unmarshal(decryptedFile, &file)

	newFileUUID := uuid.New()

	for i := 0; i < file.Length+1; i++ {
		byteChunkUUID, err := uuid.FromBytes(userlib.Hash([]byte(fileUUID.String() + fmt.Sprintf("%d", i)))[:16])
		if err != nil {
			return err
		}
		returnval, ok = userlib.DatastoreGet(byteChunkUUID)
		if !ok {
			return errors.New(strings.ToTitle("File not found #3"))
		}
		if len(returnval) < 64 {
			return errors.New(strings.ToTitle("File Error #5"))
		}

		encryptedByteChunk := returnval[:len(returnval)-64]
		byteChunkMac := returnval[len(returnval)-64:]

		byteChunkMacCheck, err := userlib.HMACEval(fileBridge.SymKeyMac, encryptedByteChunk)
		if err != nil {
			return err
		}
		if !userlib.HMACEqual(byteChunkMac, byteChunkMacCheck) {
			return errors.New(strings.ToTitle("File Error #6"))
		}

		decryptedByteChunk := userlib.SymDec(fileBridge.SymKeyEnc, encryptedByteChunk)
		json.Unmarshal(decryptedByteChunk, &byteChunk)

		marshalledByteChunk, err := json.Marshal(byteChunk)
		if err != nil {
			return err
		}

		encryptedByteChunk = userlib.SymEnc(fileEncKey, userlib.RandomBytes(16), marshalledByteChunk)
		byteChunkMac, err = userlib.HMACEval(fileMacKey, encryptedByteChunk)
		if err != nil {
			return err
		}

		newByteChunkUUID, err := uuid.FromBytes(userlib.Hash([]byte(newFileUUID.String() + fmt.Sprintf("%d", i)))[:16])

		userlib.DatastoreSet(newByteChunkUUID, append(encryptedByteChunk, byteChunkMac...))
		userlib.DatastoreDelete(byteChunkUUID)
	}

	marshalledFile, err := json.Marshal(file)
	if err != nil {
		return err
	}

	encryptedFile = userlib.SymEnc(fileEncKey, userlib.RandomBytes(16), marshalledFile)
	fileMac, err = userlib.HMACEval(fileMacKey, encryptedFile)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(newFileUUID, append(encryptedFile, fileMac...))
	userlib.DatastoreDelete(fileUUID)

	fileBridge.SymKeyEnc = fileEncKey
	fileBridge.SymKeyMac = fileMacKey
	fileBridge.FileId = newFileUUID
	delete(fileBridge.SharedWith, recipientUsername)

	for _, user := range fileBridge.SharedWith {
		if user != recipientUUID {
			sharedFileBridgeUUID, err = uuid.FromBytes(userlib.Hash([]byte(userUUID.String() + user.String() + filename))[:16])
			if err != nil {
				return err
			}
			fileBridgeEncKeyUUID, err := uuid.FromBytes(userlib.Hash([]byte(userUUID.String() + user.String() + filename + "enc-key"))[:16])
			if err != nil {
				return err
			}
			returnval, ok = userlib.DatastoreGet(fileBridgeEncKeyUUID)
			if !ok {
				return errors.New(strings.ToTitle("File not found #4"))
			}
			if len(returnval) < 64 {
				return errors.New(strings.ToTitle("File Error #7"))
			}

			encryptedFileBridgeEncKey := returnval[:len(returnval)-64]
			fileBridgeEncKeyMac := returnval[len(returnval)-64:]

			fileBridgeEncKeyMacCheck, err := userlib.HMACEval(userMacKey, encryptedFileBridgeEncKey)
			if err != nil {
				return err
			}
			if !userlib.HMACEqual(fileBridgeEncKeyMac, fileBridgeEncKeyMacCheck) {
				return errors.New(strings.ToTitle("File Error #8"))
			}

			decryptedFileBridgeEncKey := userlib.SymDec(userRootKey, encryptedFileBridgeEncKey)
			json.Unmarshal(decryptedFileBridgeEncKey, &fileBridgeEncKey)

			fileBridgeMacKeyUUID, err := uuid.FromBytes(userlib.Hash([]byte(userUUID.String() + user.String() + filename + "mac-key"))[:16])
			if err != nil {
				return err
			}
			returnval, ok = userlib.DatastoreGet(fileBridgeMacKeyUUID)
			if !ok {
				return errors.New(strings.ToTitle("File not found #5"))
			}
			if len(returnval) < 64 {
				return errors.New(strings.ToTitle("File Error #9"))
			}

			encryptedFileBridgeMacKey := returnval[:len(returnval)-64]
			fileBridgeMacKeyMac := returnval[len(returnval)-64:]

			fileBridgeMacKeyMacCheck, err := userlib.HMACEval(userMacKey, encryptedFileBridgeMacKey)
			if err != nil {
				return err
			}
			if !userlib.HMACEqual(fileBridgeMacKeyMac, fileBridgeMacKeyMacCheck) {
				return errors.New(strings.ToTitle("File Error #10"))
			}

			decryptedFileBridgeMacKey := userlib.SymDec(userRootKey, encryptedFileBridgeMacKey)
			json.Unmarshal(decryptedFileBridgeMacKey, &fileBridgeMacKey)

			returnval, ok = userlib.DatastoreGet(sharedFileBridgeUUID)
			if !ok {
				return errors.New(strings.ToTitle("File not found #6"))
			}
			if len(returnval) < 64 {
				return errors.New(strings.ToTitle("File Error #11"))
			}

			encryptedFileBridge := returnval[:len(returnval)-64]
			fileBridgeMac := returnval[len(returnval)-64:]

			fileBridgeMacCheck, err := userlib.HMACEval(fileBridgeMacKey, encryptedFileBridge)
			if err != nil {
				return err
			}
			if !userlib.HMACEqual(fileBridgeMac, fileBridgeMacCheck) {
				return errors.New(strings.ToTitle("File Error #12"))
			}

			decryptedFileBridge := userlib.SymDec(fileBridgeEncKey, encryptedFileBridge)
			json.Unmarshal(decryptedFileBridge, &sharedFileBridge)

			sharedFileBridge.SymKeyEnc = fileEncKey
			sharedFileBridge.SymKeyMac = fileMacKey
			sharedFileBridge.FileId = newFileUUID

			marshalledFileBridge, err := json.Marshal(sharedFileBridge)
			if err != nil {
				return err
			}

			encryptedFileBridge = userlib.SymEnc(fileBridgeEncKey, userlib.RandomBytes(16), marshalledFileBridge)
			fileBridgeMac, err = userlib.HMACEval(fileBridgeMacKey, encryptedFileBridge)
			if err != nil {
				return err
			}

			userlib.DatastoreSet(sharedFileBridgeUUID, append(encryptedFileBridge, fileBridgeMac...))
		}
	}

	marshalledFileBridge, err := json.Marshal(fileBridge)
	if err != nil {
		return err
	}

	encryptedFileBridge = userlib.SymEnc(userRootKey, userlib.RandomBytes(16), marshalledFileBridge)
	fileBridgeMac, err = userlib.HMACEval(userMacKey, encryptedFileBridge)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(fileBridgeUUID, append(encryptedFileBridge, fileBridgeMac...))

	return nil
}
