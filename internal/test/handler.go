package test

import (
	"fmt"
	
	"github.com/sa8/multi-party-sig/pkg/party"
	"github.com/sa8/multi-party-sig/pkg/protocol"
)

// HandlerLoop blocks until the handler has finished. The result of the execution is given by Handler.Result().
func HandlerLoopKeyGen(id party.ID, h protocol.Handler, network *Network) {
	for {
		select {

		// outgoing messages
		case msg, ok := <-h.Listen():
			fmt.Println("Outgoing message:", msg)
			if !ok {
				<-network.Done(id)
				// the channel was closed, indicating that the protocol is done executing.
				return
			}
			go network.Send(msg)

		// incoming messages
		case msg := <-network.Next(id):
			h.Accept(msg)

		// timeout case
		default: //timeout done
			h.TimeOutExpired()
		}
	}
}

// HandlerLoop blocks until the handler has finished. The result of the execution is given by Handler.Result().
func HandlerLoop(id party.ID, h protocol.Handler, network *Network) {
	for {
		select {

		// outgoing messages
		case msg, ok := <-h.Listen():
			fmt.Println("Outgoing message:", msg)
			if !ok {
				<-network.Done(id)
				// the channel was closed, indicating that the protocol is done executing.
				return
			}
			go network.Send(msg)

		// incoming messages
		case msg := <-network.Next(id):
			fmt.Println("Incoming message:", msg, h.CanAccept(msg))

			h.Accept(msg)
		}
	}
}

