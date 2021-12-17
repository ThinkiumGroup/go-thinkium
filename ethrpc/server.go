package ethrpc

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	mapset "github.com/deckarep/golang-set"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
)

const MetadataApi = "rpc"

// Server is an RPC server.
type Server struct {
	common.AbstractService
	services  serviceRegistry
	idgen     func() ID
	run       int32
	codecs    mapset.Set
	logger    logrus.FieldLogger
	local     common.Endpoint
	httpServe http.Server
}

// RPCService gives meta information about the server.
// e.g. gives information about the loaded modules.
type RPCService struct {
	server *Server
}

func (s *Server) Initializer() error {
	c := cors.New(cors.Options{
		AllowedMethods: []string{http.MethodPost, http.MethodGet},
		AllowedHeaders: []string{"*"},
		MaxAge:         600,
	})
	h := c.Handler(s)
	// Bundle and start the HTTP server
	s.httpServe = http.Server{
		Handler:      h,
		ReadTimeout:  DefaultHTTPTimeouts.ReadTimeout,
		WriteTimeout: DefaultHTTPTimeouts.WriteTimeout,
		IdleTimeout:  DefaultHTTPTimeouts.IdleTimeout,
	}
	s.logger.Info("[ETHRPC] initialized")
	return nil
}

func (s *Server) Starter() error {
	listener, err := net.Listen(s.local.NetType, s.local.Address)
	if err != nil {
		return err
	}
	go s.httpServe.Serve(listener)
	return err
}

func (s *Server) Closer() error {
	if err := s.httpServe.Close(); err != nil {
		s.logger.Errorf("[ETHRPC] %s, stopped error: %s", s.String(), err.Error())
		return err
	}
	s.logger.Info(s.String() + " stopped")
	return nil
}

func (s *Server) String() string {
	return "ETHRPC@" + s.local.String()
}

// NewServer creates a new server instance with no registered handlers.
func NewServer(local common.Endpoint) (*Server, error) {
	server := &Server{
		idgen:  randomIDGenerator(),
		codecs: mapset.NewSet(),
		local:  local,
		run:    1,
		logger: log.WithField("L", "ETHRPC"),
	}
	// Register the default service providing meta information about the RPC service such
	// as the services and methods it offers.
	rpcService := &RPCService{server}
	server.RegisterName(MetadataApi, rpcService)
	server.SetChanger(server)
	server.logger.Info("[ETHRPC] created")
	return server, nil
}

// RegisterName creates a service for the given receiver type under the given name. When no
// methods on the given receiver match the criteria to be either a RPC method or a
// subscription an error is returned. Otherwise a new service is created and added to the
// service collection this server provides to clients.
func (s *Server) RegisterName(name string, receiver interface{}) error {
	return s.services.registerName(name, receiver)
}

// ServeCodec reads incoming requests from codec, calls the appropriate callback and writes
// the response back using the given codec. It will block until the codec is closed or the
// server is stopped. In either case the codec is closed.
//
// Note that codec options are no longer supported.
func (s *Server) ServeCodec(codec ServerCodec) {
	defer codec.close()

	// Don't serve if server is stopped.
	if atomic.LoadInt32(&s.run) == 0 {
		return
	}

	// Add the codec to the set so it can be closed by Stop.
	s.codecs.Add(codec)
	defer s.codecs.Remove(codec)

	c := initClient(codec, s.idgen, &s.services)
	<-codec.closed()
	c.Close()
}

// serveSingleRequest reads and processes a single RPC request from the given codec. This
// is used to serve HTTP connections. Subscriptions and reverse calls are not allowed in
// this mode.
func (s *Server) serveSingleRequest(ctx context.Context, codec ServerCodec) {
	// Don't serve if server is stopped.
	if atomic.LoadInt32(&s.run) == 0 {
		return
	}

	h := newHandler(ctx, codec, s.idgen, &s.services)
	h.allowSubscribe = false
	defer h.close(io.EOF, nil)

	reqs, batch, err := codec.readBatch()
	if err != nil {
		if err != io.EOF {
			codec.writeJSON(ctx, errorMessage(&invalidMessageError{"parse error"}))
		}
		return
	}
	if batch {
		h.handleBatch(reqs)
	} else {
		h.handleMsg(reqs[0])
	}
}

// Stop stops reading new requests, waits for stopPendingRequestTimeout to allow pending
// requests to finish, then closes all codecs which will cancel pending requests and
// subscriptions.
func (s *Server) Stop() {
	if atomic.CompareAndSwapInt32(&s.run, 1, 0) {
		log.Debug("RPC server shutting down")
		s.codecs.Each(func(c interface{}) bool {
			c.(ServerCodec).close()
			return true
		})
	}
}
