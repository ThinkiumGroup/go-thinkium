package ethrpc

import (
	"container/list"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"reflect"
	"strings"
	"sync"
	"time"
)

var (
	ErrSubscriptionNotFound     = errors.New("subscription not found")
	ErrNotificationsUnsupported = errors.New("notifications not supported")
	errUnsubscribed             = errors.New("unsubscribed")
)

// Notifier is tied to a RPC connection that supports subscriptions.
// Server callbacks use the notifier to send notifications.
type Notifier struct {
	h         *handler
	namespace string

	mu           sync.Mutex
	sub          *Subscription
	buffer       []json.RawMessage
	callReturned bool
	activated    bool
}

// ID defines a pseudo random number that is used to identify RPC subscriptions.
type ID string

type notifierKey struct{}

// A Subscription is created by a notifier and tied to that notifier. The client can use
// this subscription to wait for an unsubscribe request for the client, see Err().
type Subscription struct {
	ID        ID
	namespace string
	err       chan error // closed on unsubscribe
}

func encodeID(b []byte) ID {
	id := hex.EncodeToString(b)
	id = strings.TrimLeft(id, "0")
	if id == "" {
		id = "0" // ID's are RPC quantities, no leading zero's and 0 is 0x0.
	}
	return ID("0x" + id)
}

// randomIDGenerator returns a function generates a random IDs.
func randomIDGenerator() func() ID {
	var buf = make([]byte, 8)
	var seed int64
	if _, err := crand.Read(buf); err == nil {
		seed = int64(binary.BigEndian.Uint64(buf))
	} else {
		seed = int64(time.Now().Nanosecond())
	}

	var (
		mu  sync.Mutex
		rng = rand.New(rand.NewSource(seed))
	)
	return func() ID {
		mu.Lock()
		defer mu.Unlock()
		id := make([]byte, 16)
		rng.Read(id)
		return encodeID(id)
	}
}

// ClientSubscription is a subscription established through the Client's Subscribe or
// EthSubscribe methods.
type ClientSubscription struct {
	client    *Client
	etype     reflect.Type
	channel   reflect.Value
	namespace string
	subid     string

	// The in channel receives notification values from client dispatcher.
	in chan json.RawMessage

	// The error channel receives the error from the forwarding loop.
	// It is closed by Unsubscribe.
	err     chan error
	errOnce sync.Once

	// Closing of the subscription is requested by sending on 'quit'. This is handled by
	// the forwarding loop, which closes 'forwardDone' when it has stopped sending to
	// sub.channel. Finally, 'unsubDone' is closed after unsubscribing on the server side.
	quit        chan error
	forwardDone chan struct{}
	unsubDone   chan struct{}
}

// takeSubscription returns the subscription (if one has been created). No subscription can
// be created after this call.
func (n *Notifier) takeSubscription() *Subscription {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.callReturned = true
	return n.sub
}

// close is called by the client's message dispatcher when the connection is closed.
func (sub *ClientSubscription) close(err error) {
	select {
	case sub.quit <- err:
	case <-sub.forwardDone:
	}
}

// deliver is called by the client's message dispatcher to send a notification value.
func (sub *ClientSubscription) deliver(result json.RawMessage) (ok bool) {
	select {
	case sub.in <- result:
		return true
	case <-sub.forwardDone:
		return false
	}
}

// run is the forwarding loop of the subscription. It runs in its own goroutine and
// is launched by the client's handler after the subscription has been created.
func (sub *ClientSubscription) run() {
	defer close(sub.unsubDone)

	unsubscribe, err := sub.forward()

	// The client's dispatch loop won't be able to execute the unsubscribe call if it is
	// blocked in sub.deliver() or sub.close(). Closing forwardDone unblocks them.
	close(sub.forwardDone)

	// Call the unsubscribe method on the server.
	if unsubscribe {
		sub.requestUnsubscribe()
	}

	// Send the error.
	if err != nil {
		if err == ErrClientQuit {
			// ErrClientQuit gets here when Client.Close is called. This is reported as a
			// nil error because it's not an error, but we can't close sub.err here.
			err = nil
		}
		sub.err <- err
	}
}

// forward is the forwarding loop. It takes in RPC notifications and sends them
// on the subscription channel.
func (sub *ClientSubscription) forward() (unsubscribeServer bool, err error) {
	cases := []reflect.SelectCase{
		{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(sub.quit)},
		{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(sub.in)},
		{Dir: reflect.SelectSend, Chan: sub.channel},
	}
	buffer := list.New()

	for {
		var chosen int
		var recv reflect.Value
		if buffer.Len() == 0 {
			// Idle, omit send case.
			chosen, recv, _ = reflect.Select(cases[:2])
		} else {
			// Non-empty buffer, send the first queued item.
			cases[2].Send = reflect.ValueOf(buffer.Front().Value)
			chosen, recv, _ = reflect.Select(cases)
		}

		switch chosen {
		case 0: // <-sub.quit
			if !recv.IsNil() {
				err = recv.Interface().(error)
			}
			if err == errUnsubscribed {
				// Exiting because Unsubscribe was called, unsubscribe on server.
				return true, nil
			}
			return false, err

		case 1: // <-sub.in
			val, err := sub.unmarshal(recv.Interface().(json.RawMessage))
			if err != nil {
				return true, err
			}
			if buffer.Len() == maxClientSubscriptionBuffer {
				return true, ErrSubscriptionQueueOverflow
			}
			buffer.PushBack(val)

		case 2: // sub.channel<-
			cases[2].Send = reflect.Value{} // Don't hold onto the value.
			buffer.Remove(buffer.Front())
		}
	}
}

func (sub *ClientSubscription) unmarshal(result json.RawMessage) (interface{}, error) {
	val := reflect.New(sub.etype)
	err := json.Unmarshal(result, val.Interface())
	return val.Elem().Interface(), err
}

func (sub *ClientSubscription) requestUnsubscribe() error {
	var result interface{}
	return sub.client.Call(&result, sub.namespace+unsubscribeMethodSuffix, sub.subid)
}
