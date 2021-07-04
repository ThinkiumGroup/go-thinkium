// Copyright 2020 Thinkium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"errors"
	"fmt"
	"sync"

	"github.com/ThinkiumGroup/go-common"
	"github.com/ThinkiumGroup/go-common/log"
	"github.com/ThinkiumGroup/go-thinkium/config"
	"github.com/ThinkiumGroup/go-thinkium/models"
)

type RunContext interface {
	NetworkManager() models.NetworkManager // network service interface
	DataManager() models.DataManager       // data service interface
	Engine() models.Engine                 // consensus engine
	Eventer() models.Eventer               // event queue
	Config() *config.Config                // system configuration
}

type Cmd interface {
	Prefix() []byte               // prefix of command, used for pattern matching
	Match(string) error           // whether the parameter is matching current command
	Run(string, RunContext) error // execute command
	String() string
}

type SingleCmd string

func (s SingleCmd) Prefix() []byte {
	return []byte(s)
}

func (s SingleCmd) Match(line string) error {
	if string(s) == line {
		return nil
	}
	return fmt.Errorf("command should be [%s]", s)
}

func (s SingleCmd) String() string {
	return fmt.Sprintf("SingleCmd<%s>", string(s))
}

type DynamicCmd string

func (d DynamicCmd) Prefix() []byte {
	return []byte(d)
}

func (d DynamicCmd) String() string {
	return fmt.Sprintf("DynamicCmd<%s>", string(d))
}

type cmdnode struct {
	children map[byte]*cmdnode // child node of command tree
	cmd      Cmd               // command at the current node
}

func (n *cmdnode) put(prefix []byte, cmd Cmd) error {
	if cmd == nil {
		return common.ErrNil
	}
	if len(prefix) == 0 {
		// current node is the target
		if n.cmd != nil {
			return errors.New(fmt.Sprintf("duplicated cmd found: %s, new: %s", n.cmd.String(), cmd.String()))
		}
		n.cmd = cmd
		return nil
	}
	if n.children == nil {
		n.children = make(map[byte]*cmdnode)
	}
	child, exist := n.children[prefix[0]]
	if !exist {
		child = new(cmdnode)
		n.children[prefix[0]] = child
	}
	return child.put(prefix[1:], cmd)
}

func (n *cmdnode) checkCmd(line string) (Cmd, error) {
	if n.cmd != nil {
		if err := n.cmd.Match(line); err != nil {
			return nil, fmt.Errorf("match [%s] failed: %v", line, err)
		}
		return n.cmd, nil
	}
	return nil, fmt.Errorf("command [%s] not found", line)
}

// Find the first non-nil command object that can be matched according to line start from offset, otherwise
// nil is returned. If no node found, non-nil error returned.
func (n *cmdnode) search(line string, offset int) (Cmd, error) {
	if n == nil {
		return nil, common.ErrNil
	}
	if n.cmd != nil || // current node has a command
		len(line) <= offset || // input line ends
		n.children == nil { // current node is a leaf node of the command tree
		return n.checkCmd(line)
	}
	child, exist := n.children[[]byte(line)[offset]]
	if !exist {
		// specified path by line has no child
		// FIXME: should return error directly
		return n.checkCmd(line)
	}
	return child.search(line, offset+1)
}

type Cmds struct {
	root *cmdnode
	lock sync.RWMutex
}

func (c *Cmds) Put(cmds ...Cmd) error {
	if len(cmds) == 0 {
		return common.ErrNil
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.root == nil {
		c.root = new(cmdnode)
	}
	for _, cmd := range cmds {
		if err := c.root.put(cmd.Prefix(), cmd); err != nil {
			return err
		}
		log.Infof("COMMAND: %s added", cmd)
	}
	return nil
}

func (c *Cmds) Get(line string) (Cmd, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.root.search(line, 0)
}

func (c *Cmds) Run(line string, ctx RunContext) (exist bool, err error) {
	cmd, err := c.Get(line)
	if err != nil {
		return false, err
	}
	return true, cmd.Run(line, ctx)
}
