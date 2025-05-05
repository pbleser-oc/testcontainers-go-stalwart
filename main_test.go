package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	petname "github.com/dustinkirkland/golang-petname"
	pw "github.com/sethvargo/go-password/password"
	"gopkg.in/loremipsum.v1"

	"github.com/go-crypt/crypt/algorithm/shacrypt"
)

const (
	// the container image for Stalwart
	stalwartImage  = "stalwartlabs/mail-server:latest"
	username       = "user"
	adminPassword  = "secret"
	masterPassword = "mastersecret"
	folder         = "INBOX"
	httpPort       = "8080"
	imapsPort      = "993"
	// Stalwart config.toml template, will be processed with placeholders
	// and then copied into the container
	configTemplate = `
authentication.fallback-admin.secret = "{{.adminPassword}}"
authentication.fallback-admin.user = "mailadmin"
authentication.master.secret = "{{.masterPassword}}"
authentication.master.user = "master"
directory.memory.principals.0000.class = "admin"
directory.memory.principals.0000.description = "Superuser"
directory.memory.principals.0000.email.0000 = "admin@example.org"
directory.memory.principals.0000.name = "admin"
directory.memory.principals.0000.secret = "secret"
directory.memory.principals.0001.class = "individual"
directory.memory.principals.0001.description = "Camina Drummer"
directory.memory.principals.0001.email.0000 = "camina.drummer@example.org"
directory.memory.principals.0001.name = "user"
directory.memory.principals.0001.secret = "{{.password}}"
directory.memory.principals.0001.storage.directory = "memory"
directory.memory.type = "memory"
metrics.prometheus.enable = false
server.listener.http.bind = "[::]:{{.httpPort}}"
server.listener.http.protocol = "http"
server.listener.imaptls.bind = "[::]:{{.imapsPort}}"
server.listener.imaptls.protocol = "imap"
server.listener.imaptls.tls.implicit = true
server.max-connections = 8192
server.socket.backlog = 1024
server.socket.nodelay = true
server.socket.reuse-addr = true
server.socket.reuse-port = true
storage.blob = "rocksdb"
storage.data = "rocksdb"
storage.directory = "memory"
storage.fts = "rocksdb"
storage.lookup = "rocksdb"
store.rocksdb.compression = "lz4"
store.rocksdb.path = "/opt/stalwart-mail/data"
store.rocksdb.type = "rocksdb"
tracer.log.ansi = false
tracer.log.buffered = false
tracer.log.enable = true
tracer.log.level = "trace"
tracer.log.lossy = false
tracer.log.multiline = false
tracer.log.type = "stdout"
`
)

type StalwartSuite struct {
	suite.Suite
	password  string // the password for username
	ctx       context.Context
	cancel    context.CancelFunc
	container testcontainers.Container
}

func TestSuite(t *testing.T) {
	suite.Run(t, new(StalwartSuite))
}

func (suite *StalwartSuite) SetupTest() {
	require := require.New(suite.T())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)

	// generate a new random password for the regular user account
	var err error
	suite.password, err = pw.Generate(4+rand.Intn(28), 2, 0, false, true)
	require.NoError(err)

	// hash the predefined passwords for the admin and the master authentication
	// using SHA-512, they will be templated into the configuration
	var (
		adminPasswordHash  string
		masterPasswordHash string
	)
	{
		h, err := shacrypt.New(shacrypt.WithSHA512(), shacrypt.WithIterations(shacrypt.IterationsDefaultOmitted))
		require.NoError(err)
		adminPasswordDigest, err := h.Hash(adminPassword)
		require.NoError(err)
		adminPasswordHash = adminPasswordDigest.Encode()
		masterPasswordDigest, err := h.Hash(masterPassword)
		require.NoError(err)
		masterPasswordHash = masterPasswordDigest.Encode()
	}

	// process the config template
	var configReader *strings.Reader
	{
		configBuf := bytes.NewBufferString("")
		template.Must(template.New("").Parse(configTemplate)).Execute(configBuf, map[string]interface{}{
			"password":       suite.password,
			"httpPort":       httpPort,
			"imapsPort":      imapsPort,
			"adminPassword":  adminPasswordHash,
			"masterPassword": masterPasswordHash,
		})
		configReader = strings.NewReader(configBuf.String())
	}

	// create and start the Stalwart container
	req := testcontainers.ContainerRequest{
		Image:        stalwartImage,
		ExposedPorts: []string{httpPort + "/tcp", imapsPort + "/tcp"},
		Files: []testcontainers.ContainerFile{{
			// copy the content of the configuration template into this file in the container:
			Reader:            configReader,
			ContainerFilePath: "/opt/stalwart-mail/etc/config.toml",
			FileMode:          0o700,
		}},
		// note that this requires setting the log level in the configuration to "info" at a minimum,
		// in the property "tracer.log.level":
		WaitingFor: wait.ForAll(
			// when the Stalwart logging mentions this line, it is ready to process inbound IMAPS connections
			wait.ForLog(`Network listener started (network.listen-start) listenerId = "imaptls"`),
			// when the Stalwart logging mentions this line, it is ready to process inbound HTTP connections
			wait.ForLog(`Network listener started (network.listen-start) listenerId = "http"`),
		),
	}
	suite.container, err = testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(err)
	suite.ctx = ctx
	suite.cancel = cancel

	host, err := suite.container.Host(ctx)
	require.NoError(err)
	mappedImapsPort, err := suite.container.MappedPort(ctx, imapsPort)
	require.NoError(err)
	log.Default().Printf("%v container running on %v:%v", stalwartImage, host, mappedImapsPort.Port())
}

func (suite *StalwartSuite) TearDownTest() {
	testcontainers.CleanupContainer(suite.T(), suite.container)
	suite.cancel()
}

type WellKnownJmap struct {
	PrimaryAccounts map[string]string `json:"primaryAccounts"`
}

func (suite *StalwartSuite) TestJMAP() {
	require := suite.Require()

	host, err := suite.container.Host(suite.ctx)
	require.NoError(err)
	mappedHttpPort, err := suite.container.MappedPort(suite.ctx, httpPort)
	require.NoError(err)

	url := fmt.Sprintf("http://%s:%d/.well-known/jmap", host, mappedHttpPort.Int())

	client := http.Client{Timeout: time.Second * 2}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(err)
	req.SetBasicAuth(username, suite.password)

	res, err := client.Do(req)
	require.NoError(err)
	require.Equal(200, res.StatusCode)

	if res.Body != nil {
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			require.NoError(err)
		}(res.Body)
	}

	body, err := io.ReadAll(res.Body)
	require.NoError(err)

	var data WellKnownJmap
	err = json.Unmarshal(body, &data)
	require.NoError(err)

	require.Contains(data.PrimaryAccounts, "urn:ietf:params:jmap:mail")
	accountId := data.PrimaryAccounts["urn:ietf:params:jmap:mail"]
	require.NotEmpty(accountId)
}

func (suite *StalwartSuite) TestIMAP() {
	require := suite.Require()

	ip, err := suite.container.Host(suite.ctx)
	require.NoError(err)

	{
		port, err := suite.container.MappedPort(suite.ctx, "993")
		require.NoError(err)

		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		c, err := imapclient.DialTLS(fmt.Sprintf("%s:%s", ip, port.Port()), &imapclient.Options{TLSConfig: tlsConfig})
		require.NoError(err)

		defer func(imap *imapclient.Client) {
			err := imap.Close()
			require.NoError(err)
		}(c)

		err = c.Login(username, suite.password).Wait()
		require.NoError(err)

		_, err = c.Select(folder, nil).Wait()
		require.NoError(err)

		// create between 5 and 40 emails in the INBOX folder, using IMAP APPEND
		count := 5 + rand.Intn(35)
		loremIpsumGenerator := loremipsum.New()
		for i := 0; i < count; i++ {
			first := petname.Adjective()
			last := petname.Adverb()
			fromName := first + " " + last
			fromAddress := strings.ToLower(first) + "." + strings.ToLower(last)
			text := loremIpsumGenerator.Paragraphs(5 + rand.Intn(20))
			summary := loremIpsumGenerator.Words(3 + rand.Intn(7))

			buf := fmt.Appendf(nil, "From: %s <%s>\r\nSubject: %s\r\n\r\n%s", fromName, fromAddress, summary, text)
			size := int64(len(buf))
			appendCmd := c.Append(folder, size, nil)
			_, err := appendCmd.Write(buf)
			require.NoError(err)
			err = appendCmd.Close()
			require.NoError(err)
			_, err = appendCmd.Wait()
			require.NoError(err)
		}

		// use IMAP LIST to collect statistics about each folder
		listCmd := c.List("", "%", &imap.ListOptions{
			ReturnStatus: &imap.StatusOptions{
				NumMessages: true,
				NumUnseen:   true,
			},
		})
		// store the number of messages in each folder into a map
		countMap := make(map[string]int)
		for {
			mbox := listCmd.Next()
			if mbox == nil {
				break
			}
			log.Printf("Mailbox %q contains %v messages (%v unseen)", mbox.Mailbox, *mbox.Status.NumMessages, *mbox.Status.NumUnseen)
			countMap[mbox.Mailbox] = int(*mbox.Status.NumMessages)
		}
		// and then assert that the INBOX folder does have the expected number of mails in it
		require.Contains(countMap, folder)
		require.Equal(count, countMap[folder])

		err = listCmd.Close()
		require.NoError(err)
	}
}
