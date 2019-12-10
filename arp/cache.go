package arp

import (
	"sync"
	"time"
)

type cache struct {
	sync.RWMutex
	table ArpTable

	Updated      time.Time
	UpdatedCount int
}

func (c *cache) Refresh() {
	c.Lock()
	defer c.Unlock()

	c.table = Table()
	c.Updated = time.Now()
	c.UpdatedCount += 1
}

func (c *cache) Search(ip string) ArpEntry {
	c.RLock()
	defer c.RUnlock()

	mac, ok := c.table[ip]

	if !ok {
		c.RUnlock()
		c.Refresh()
		c.RLock()
		mac = c.table[ip]
	}

	return mac
}

func (c *cache) ReverseSearch(mac string) (entries []ArpEntry) {
	c.Refresh()
	c.RLock()
	defer c.RUnlock()
	for _, v := range c.table {
		if v.MacAddress == mac {
			entries = append(entries, v)
		}
	}
	return entries
}
