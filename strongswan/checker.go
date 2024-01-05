package strongswan

import (
	"context"
)

func (c *Collector) Check(context.Context) error {
	s, err := c.viciClientFn()
	if err != nil {
		return err
	}
	_ = s.Close()
	return nil
}
