package runtime

// Flow identity is immutable. A reassigned login with older live flows cannot
// prove which account authenticated during the configuration handover.
func (r *Runtime) retainBinding(identity Identity, client string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bound[identity] == nil {
		r.bound[identity] = map[string]int{}
	}
	r.bound[identity][client]++
}

func (r *Runtime) releaseBinding(identity Identity, client string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	clients := r.bound[identity]
	clients[client]--
	if clients[client] == 0 {
		delete(clients, client)
	}
	if len(clients) == 0 {
		delete(r.bound, identity)
	}
}

// Called under r.mu, alongside the observation snapshot.
func (r *Runtime) conflictingBindings(incomplete []string) []string {
	users := r.users.Load().users
	for identity, clients := range r.bound {
		current := users[identity]
		if current == "" {
			continue
		}
		for client := range clients {
			if client != current {
				incomplete = append(incomplete, client, current)
			}
		}
	}
	return incomplete
}
