package client_test

import (
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/google/uuid"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

type UUID = uuid.UUID

const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

var _ = Describe("Client Tests", func() {

	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	aliceFile := "aliceFile.txt"
	aliceFile2 := "aliceFile2.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	measureBandwidth := func(probe func()) (bandwidth int) {
		before := userlib.DatastoreGetBandwidth()
		probe()
		after := userlib.DatastoreGetBandwidth()
		return after - before
	}

	compareMaps := func(data1, data2 map[UUID][]byte) []UUID {
		var diff []UUID
		for key := range data2 {
			_, ok := data1[key]
			if !ok {
				diff = append(diff, key)
			}
		}
		return diff
	}

	makeDataStoreMap := func(data map[UUID][]byte) map[UUID][]byte {
		dataStoreMap := make(map[UUID][]byte)
		for key, value := range data {
			dataStoreMap[key] = value
		}
		return dataStoreMap
	}

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Overwriting file data: %s", contentTwo)
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob can overwrite file.")
			err = bob.StoreFile(bobFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("More Revoke Tests", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, Charlie, Doris, and Eve.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice revoking invalid user's access %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "anon")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice revoking invalid file")
			err = alice.RevokeAccess("file.txt", "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice creating invite for Charles for file %s", aliceFile)
			invite, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepting invite under name %s.", charlesFile)
			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles appending to file")
			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Alice revoking Charles access for file %s", aliceFile)
			err = alice.RevokeAccess(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can't load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Revoked user sharing a file")
			invite, err = charles.CreateInvitation(charlesFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s", aliceFile)
			invite, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access for file %s", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Accepting a revoked file")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Checking that Bob can't load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Revoked user sharing a file")
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice creating invite for Doris for file %s", aliceFile)
			invite, err = alice.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Doris accepting invite under name %s.", dorisFile)
			err = doris.AcceptInvitation("alice", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Doris creating invite for Eve for file %s", dorisFile)
			invite, err = doris.CreateInvitation(dorisFile, "eve")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Doris's access for file %s", aliceFile)
			err = alice.RevokeAccess(aliceFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Eve accepting invite under name %s.", eveFile)
			err = eve.AcceptInvitation("doris", invite, eveFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Edge Case Tests", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting non-existent user.")
			_, err = client.GetUser("anon", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Empty Username")
			_, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Same Username")
			_, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Wrong Password")
			_, err = client.InitUser("alice", "wrong")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Storing file with content: %s", contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading non-existent file")
			_, err = aliceLaptop.LoadFile("file.txt")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Appending to non-existent file")
			err = aliceLaptop.AppendToFile("file.txt", []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating invite for non-existent user")
			invite, err := alice.CreateInvitation(aliceFile, "anon")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Creating invite for non-existent file")
			invite, err = bob.CreateInvitation("file.txt", "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob storing file", contentOne)
			bob.StoreFile(bobFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob")

			invite, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Accepting invite as wrong user")
			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Accepting invite with existing filename")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Accepting invite from wrong user")
			err = bob.AcceptInvitation("charles", invite, "bobFile2.txt")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Accepting invite properly")
			err = bob.AcceptInvitation("alice", invite, "bobFile2.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles")
			invite, err = bob.CreateInvitation("bobFile2.txt", "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepting invite from wrong user")
			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Charles accepting invite properly")
			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

		})

		Specify("Append Bandwith Test", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			initalBandwidth := measureBandwidth(func() {
				err = alice.AppendToFile(aliceFile, []byte(contentTwo))
				Expect(err).To(BeNil())
			})

			userlib.DebugMsg("Check that bandwidth doesn't increase too much after multiple appends")

			for i := 0; i < 100; i++ {
				err = alice.AppendToFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			}

			bandwidth2 := measureBandwidth(func() {
				err = alice.AppendToFile(aliceFile, []byte(contentThree))
				Expect(err).To(BeNil())
			})

			Expect(bandwidth2 - initalBandwidth).To(BeNumerically("<", 100))

			for i := 0; i < 1000; i++ {
				err = alice.AppendToFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			}

			bandwidth3 := measureBandwidth(func() {
				err = alice.AppendToFile(aliceFile, []byte(contentThree))
				Expect(err).To(BeNil())
			})

			Expect(bandwidth3 - bandwidth2).To(BeNumerically("<", 100))

			for i := 0; i < 10000; i++ {
				err = alice.AppendToFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			}

			finalBandwidth := measureBandwidth(func() {
				err = alice.AppendToFile(aliceFile, []byte(contentThree))
				Expect(err).To(BeNil())
			})

			Expect(finalBandwidth - bandwidth3).To(BeNumerically("<", 100))
		})

		Specify("Security Tests: User Corruption", func() {
			mapContent1 := makeDataStoreMap(userlib.DatastoreGetMap())

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			mapContent2 := makeDataStoreMap(userlib.DatastoreGetMap())

			mapCompare := compareMaps(mapContent1, mapContent2)

			userlib.DebugMsg("Corrupting user data")

			for _, v := range mapCompare {
				userlib.DatastoreSet(v, []byte("HACKED"))
			}

			userlib.DebugMsg("Getting user Alice")
			_, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

		})

		Specify("Security Tests: File Corruption", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			mapContent1 := makeDataStoreMap(userlib.DatastoreGetMap())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			mapContent2 := makeDataStoreMap(userlib.DatastoreGetMap())

			userlib.DebugMsg("Corrupt file contents")
			mapCompare := compareMaps(mapContent1, mapContent2)
			for _, v := range mapCompare {
				userlib.DatastoreSet(v, []byte("HACKED"))
			}

			userlib.DebugMsg("Loading file data:")
			_, err = alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentTwo)
			err = alice.StoreFile(aliceFile2, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file data:")
			_, err = alice.LoadFile(aliceFile2)
			Expect(err).To(BeNil())

			mapContent3 := makeDataStoreMap(userlib.DatastoreGetMap())

			userlib.DebugMsg("Corrupt file contents")
			mapCompare = compareMaps(mapContent2, mapContent3)
			for _, v := range mapCompare {
				userlib.DatastoreSet(v, []byte("HACKED"))
			}

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Create invite for corrupted file:")
			_, err := alice.CreateInvitation(aliceFile2, "bob")
			Expect(err).ToNot(BeNil())

			mapContent4 := makeDataStoreMap(userlib.DatastoreGetMap())

			userlib.DebugMsg("Bob storing file data: %s", contentOne)
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			mapContent5 := makeDataStoreMap(userlib.DatastoreGetMap())
			mapCompare = compareMaps(mapContent4, mapContent5)

			userlib.DebugMsg("Bob creating invite:")
			invite, err := bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepting invite:")
			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Corrupting file contents")
			for _, v := range mapCompare {
				userlib.DatastoreSet(v, []byte("HACKED"))
			}

			userlib.DebugMsg("Revoking corrupted file:")
			err = bob.RevokeAccess(bobFile, "charles")
			Expect(err).ToNot(BeNil())
		})

		Specify("Security Tests: Invite Corruption", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Corrupting invite")
			userlib.DatastoreSet(invite, []byte("HACKED"))

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob storing data")
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Alice for file %s, and Alice accepting invite under name %s.", bobFile, aliceFile2)
			invite, err = bob.CreateInvitation(bobFile, "alice")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Corrupting invite")

			recipientPKEStorage, err := uuid.FromBytes(userlib.Hash([]byte("alice"))[32:48])
			Expect(err).To(BeNil())

			recipientPKE, ok := userlib.KeystoreGet(recipientPKEStorage.String())
			Expect(ok).To(BeTrue())

			newEncryptedInvite, err := userlib.PKEEnc(recipientPKE, []byte("HACKED"))
			Expect(err).To(BeNil())

			attackerDSSignKey, _, err := userlib.DSKeyGen()
			Expect(err).To(BeNil())

			signedInvite, err := userlib.DSSign(attackerDSSignKey, newEncryptedInvite)
			Expect(err).To(BeNil())

			userlib.DatastoreSet(invite, append(newEncryptedInvite, signedInvite...))

			userlib.DebugMsg("Alice accepting invite")
			err = alice.AcceptInvitation("bob", invite, aliceFile2)
			Expect(err).ToNot(BeNil())
		})

		Specify("Security Tests: Revoked User Tampering", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Charles for file %s, and Charles accepting invite under name %s.", aliceFile, charlesFile)
			invite, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepting invite")
			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			mapContent1 := makeDataStoreMap(userlib.DatastoreGetMap())

			userlib.DebugMsg("Alice appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			mapContent2 := makeDataStoreMap(userlib.DatastoreGetMap())
			mapDifference := compareMaps(mapContent1, mapContent2)

			userlib.DebugMsg("Bob loading file %s", bobFile)
			data, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Alice revoking Bob's access to file %s", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			for _, v := range mapDifference {
				userlib.DatastoreSet(v, []byte("HACKED"))
			}

			userlib.DebugMsg("Alice loading file %s", aliceFile)
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Charles loading file %s", charlesFile)
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Bob trying to load file %s", bobFile)
			data, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
		})

	})
})
