package proxy

func (p *SocketPrompter) HasClient() bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.client != nil
}
