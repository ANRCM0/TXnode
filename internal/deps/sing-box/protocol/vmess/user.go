package vmess

import (
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

func (h *Inbound) UpdateUsers(users []option.VMessUser) error {
	h.usersMu.Lock()
	defer h.usersMu.Unlock()
	return h.updateUsersLocked(users)
}

func (h *Inbound) updateUsersLocked(users []option.VMessUser) error {
	users = append([]option.VMessUser(nil), users...)
	err := h.service.UpdateUsers(common.MapIndexed(users, func(index int, user option.VMessUser) authenticatedUser {
		return authenticatedUser{Index: index, Name: user.Name, UUID: user.UUID}
	}), common.Map(users, func(user option.VMessUser) string { return user.UUID }), common.Map(users, func(user option.VMessUser) int { return user.AlterId }))
	if err != nil {
		return err
	}
	h.users = users
	return nil
}

func (h *Inbound) DelUsers(uuids []string) error {
	h.usersMu.Lock()
	defer h.usersMu.Unlock()
	toDelete := make(map[string]struct{}, len(uuids))
	for _, uuid := range uuids {
		toDelete[uuid] = struct{}{}
	}
	remaining := make([]option.VMessUser, 0, len(h.users))
	for _, user := range h.users {
		if _, found := toDelete[user.UUID]; !found {
			remaining = append(remaining, user)
		}
	}
	return h.updateUsersLocked(remaining)
}
